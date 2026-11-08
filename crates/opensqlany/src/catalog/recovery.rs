//! Corroborate physical catalog records against layouts from the ordinary scan.
//! The directory supplies the row span. The catalog's self-described fixed
//! fields and complete field walk select a candidate while its stored length
//! bytes are hidden. Only then may the observed length corroborate that row.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

#[cfg(test)]
use crate::row::sector::inverse_odd;
use crate::row::sector::visit_sector_candidates;
use crate::row::tail::STASH_START;
use crate::{
    CalibratedPage, CalibratedStore, CatalogFragment, CatalogSchemaVersions, ForwardedRow, Page,
    PhysicalValue, RecordLayout, RowHeaderError, RowPageHeader, RowSectorReader, RowSectorRecovery,
    RowSlotRecovery, RowSlotSector, RowTail, RowTailError, SECTOR_SIZE, forwarded_row_address,
};

/// Independent context from the *first*, ordinary catalog scan. Keep this
/// context fixed while evaluating sparse candidates.
#[derive(Debug, Default)]
pub struct CatalogRecoveryContext {
    definitions: CatalogSchemaVersions,
    owners: BTreeSet<u32>,
    domains: BTreeSet<u16>,
    names: BTreeMap<u32, BTreeMap<String, BTreeSet<u32>>>,
}

/// Individually checked physical catalog definitions from a page whose sole
/// structural key has a second occurrence of the page number. The result is
/// specific to these occupied slots and does not establish currency.
#[derive(Debug)]
pub struct CorroboratedCatalogPage {
    /// ISYSTAB (1) or ISYSTABCOL (2).
    pub owner: u32,
    /// Catalog data-row kind in the candidate header.
    pub kind: u8,
    /// Zero-based slot and complete length-checked record, in slot order.
    pub rows: Vec<(u16, Vec<u8>)>,
    /// Length-checked nine-byte stubs as (source slot, (target page, target slot)).
    /// They count in `unverified_slots` until their targets are checked separately.
    pub forward_slots: Vec<(u16, (u32, u16))>,
    /// Occupied slots for which ordinary bytes or catalog checks were incomplete.
    pub unverified_slots: u16,
}

impl CatalogRecoveryContext {
    /// Observe an ordinary recovered inline catalog definition.
    pub fn observe(&mut self, fragment: &CatalogFragment<'_>) {
        self.definitions.observe_definition(fragment);
        match fragment {
            CatalogFragment::Table { table_id, .. } => {
                self.owners.insert(*table_id);
            }
            CatalogFragment::Column {
                table_id,
                column_id,
                domain_id,
                name,
                ..
            } => {
                self.owners.insert(*table_id);
                self.domains.insert(*domain_id);
                if matches!(table_id, 1 | 2) {
                    self.names
                        .entry(*table_id)
                        .or_default()
                        .entry((*name).to_owned())
                        .or_default()
                        .insert(*column_id);
                }
            }
        }
    }

    /// Check the sole structural header for the repeated-page-number case.
    /// Require a complete directory and at least two distinct catalog identities
    /// under this fixed first-pass context. Each returned row has a matching
    /// stored length, an exact field walk, and independently corroborated fields.
    /// No candidate page or row contributes to this context.
    pub fn recover_repeated_page(
        &self,
        page: Page<'_>,
        layouts: &[Option<RecordLayout>; 2],
    ) -> Result<Option<CorroboratedCatalogPage>, RowHeaderError> {
        Ok(self
            .repeated_page_with_header(page, layouts)?
            .map(|(_, confirmed)| confirmed))
    }

    pub(crate) fn repeated_page_with_header(
        &self,
        page: Page<'_>,
        layouts: &[Option<RecordLayout>; 2],
    ) -> Result<Option<(RowPageHeader, CorroboratedCatalogPage)>, RowHeaderError> {
        let Some(header) = RowPageHeader::sole_repeated_candidate(page)? else {
            return Ok(None);
        };
        if !inline_catalog_page(&header) {
            return Ok(None);
        }
        let owner = header.owner_id();
        let kind = header.page_kind();
        let Some(layout) = &layouts[owner as usize - 1] else {
            return Ok(None);
        };
        let Ok(fields) = self.identity(layout, owner) else {
            return Ok(None);
        };
        let reader = RowSectorReader::from_header(page, header);
        let Some(slots) = reader.header().complete_slot_starts() else {
            return Ok(None);
        };
        let mut identities = BTreeSet::new();
        let mut rows = Vec::new();
        let mut forward_slots = Vec::new();
        let mut unverified_slots = 0;
        for (slot, start) in slots.iter().enumerate() {
            if start.is_none() {
                continue;
            }
            let slot = slot as u16;
            if let Some(RowSlotRecovery::Candidate { bytes, .. }) = reader.read_slot(slot) {
                if let Some(address) = forwarded_row_address(&bytes) {
                    forward_slots.push((slot, address));
                } else if let Some(identity) =
                    fields.validated_identity(self, layout, reader.header(), &bytes)
                {
                    identities.insert(identity);
                    rows.push((slot, bytes));
                    continue;
                }
            }
            unverified_slots += 1;
        }
        Ok((identities.len() >= 2).then(|| {
            (
                reader.header().clone(),
                CorroboratedCatalogPage {
                    owner,
                    kind,
                    rows,
                    forward_slots,
                    unverified_slots,
                },
            )
        }))
    }

    /// Follow one length-checked catalog forward. The terminal record must
    /// match the original source catalog's fixed ordinary layout and field
    /// identities. A repeated-anchor source also needs two corroborated inline
    /// identities and an ordinary, length-checked stub at the requested slot.
    /// The target always goes through the ordinary header checks.
    pub fn corroborated_forwarded_slot<'a>(
        &self,
        store: &CalibratedStore<'a>,
        page: u32,
        slot: u16,
        layouts: &[Option<RecordLayout>; 2],
    ) -> Option<ForwardedRow<'a>> {
        let reader = self.forward_source(store, page, slot, layouts)?;
        let source = reader.header();
        if !inline_catalog_page(source) {
            return None;
        }
        let layout = layouts[source.owner_id() as usize - 1].as_ref()?;
        let fields = self.identity(layout, source.owner_id()).ok()?;
        let row = reader.resolve_forwarded_row(slot).ok()?;
        fields.validated_identity(self, layout, source, &row.target.bytes)?;
        Some(row)
    }

    fn forward_source<'r, 's>(
        &self,
        store: &'r CalibratedStore<'s>,
        page: u32,
        slot: u16,
        layouts: &[Option<RecordLayout>; 2],
    ) -> Option<CalibratedPage<'r, 's>> {
        Some(match store.page(page) {
            Ok(reader) => reader,
            Err(RowHeaderError::Ambiguous { .. }) => {
                let stored = store.store().page(u64::from(page)).ok()?;
                let confirmed = self.recover_repeated_page(stored, layouts).ok()??;
                if !confirmed.forward_slots.iter().any(|(s, _)| *s == slot) {
                    return None;
                }
                let header = RowPageHeader::sole_repeated_candidate(stored).ok()??;
                store.page_with_header(stored, header)
            }
            Err(_) => return None,
        })
    }

    /// Validate a forwarded catalog definition on a chunk page witnessed by an
    /// independently verified positive bitmap in another slot. The caller must
    /// separately corroborate at least two distinct identities on the target page.
    pub fn corroborated_witnessed_forwarded_slot<'s>(
        &self,
        store: &CalibratedStore<'s>,
        page: u32,
        slot: u16,
        layouts: &[Option<RecordLayout>; 2],
        witnesses: &crate::CatalogChunkWitnesses<'_, 's>,
    ) -> Option<((u32, u32), crate::Witnessed<ForwardedRow<'s>>)> {
        let reader = self.forward_source(store, page, slot, layouts)?;
        let header = reader.header();
        if !inline_catalog_page(header) {
            return None;
        }
        let layout = layouts[header.owner_id() as usize - 1].as_ref()?;
        let fields = self.identity(layout, header.owner_id()).ok()?;
        let resolved = witnesses.resolve_forwarded_row(&reader, slot).ok()?;
        let identity =
            fields.validated_identity(self, layout, header, &resolved.value.target.bytes)?;
        Some((identity, resolved))
    }

    /// Return a wholly length- and field-checked record from a calibrated page
    /// only when a region of this slot actually used calibrated evidence.
    /// Intended for an ordinary catalog gap with no discriminating held-out
    /// length, using a context built exclusively from the ordinary first pass.
    pub fn corroborated_calibrated_slot(
        &self,
        page: &CalibratedPage<'_, '_>,
        slot: u16,
        layout: &RecordLayout,
    ) -> Option<Vec<u8>> {
        let h = page.header();
        if !inline_catalog_page(h) {
            return None;
        }
        let fields = self.identity(layout, h.owner_id()).ok()?;
        let RowSlotRecovery::Candidate { bytes, sectors, .. } = page.read_slot(slot)? else {
            return None;
        };
        if !sectors
            .iter()
            .any(|s| matches!(s, RowSlotSector::Calibrated { .. }))
        {
            return None;
        }
        fields.validated_identity(self, layout, h, &bytes)?;
        Some(bytes)
    }

    /// Read an additional column definition only through a previously verified
    /// ISYSTABCOL map on this same reader. The fixed bootstrap still supplies
    /// the exact catalog layout. A repeated header has already been selected
    /// using independent known identities; this record cannot select its own
    /// key or lend evidence to another header. Its complete typed fields must
    /// match its inline definition, even for a previously unseen table/domain.
    pub fn corroborated_mapped_column_slot(
        &self,
        store: &CalibratedStore<'_>,
        members: &crate::ColumnCatalogMembers,
        page: u32,
        slot: u16,
        layout: &RecordLayout,
    ) -> Option<Vec<u8>> {
        let reader = members.page(store, page).ok()?;
        let header = reader.header();
        if header.owner_id() != 2 || !inline_catalog_page(header) {
            return None;
        }
        let fields = self.identity(layout, 2).ok()?;
        let RowSlotRecovery::Candidate { bytes, .. } = reader.read_slot(slot)? else {
            return None;
        };
        fields.checked_identity(self, layout, header, &bytes, false)?;
        Some(bytes)
    }

    /// Add only an owner identity from a fully checked column on this reader's
    /// verified ISYSTABCOL map. Layouts, domains and first-pass observations are
    /// unchanged. Use a separate context for this later pass: a newly recovered
    /// table definition must not supply its own identity or select its own page.
    /// Physical membership here does not establish SQL row visibility.
    pub fn observe_mapped_column_owner(
        &mut self,
        store: &CalibratedStore<'_>,
        members: &crate::ColumnCatalogMembers,
        page: u32,
        slot: u16,
        layout: &RecordLayout,
    ) -> Option<u32> {
        let bytes = self.corroborated_mapped_column_slot(store, members, page, slot, layout)?;
        // Membership alone can include a retained deleted or linked record.
        // Only an ordinary inline definition may seed another catalog identity.
        if bytes.get(2)? & !0x40 != 0 {
            return None;
        }
        let reader = members.page(store, page).ok()?;
        let CatalogFragment::Column { table_id, .. } =
            CatalogFragment::parse(2, reader.header().page_kind(), &bytes)?
        else {
            return None;
        };
        self.owners.insert(table_id);
        Some(table_id)
    }

    fn identity(&self, layout: &RecordLayout, owner: u32) -> Result<Fields, CatalogRecoveryError> {
        if self
            .definitions
            .full_layout(owner)
            .ok()
            .is_none_or(|bootstrap| bootstrap.columns() != layout.columns())
        {
            return Err(CatalogRecoveryError::UnknownLayout);
        }
        let ord = |name: &str| -> Result<usize, CatalogRecoveryError> {
            self.names
                .get(&owner)
                .and_then(|m| m.get(name))
                .filter(|v| v.len() == 1)
                .and_then(|v| v.first()?.checked_sub(1))
                .map(|v| v as usize)
                .ok_or(CatalogRecoveryError::UnknownLayout)
        };
        Ok(Fields {
            table_id: ord("table_id")?,
            name: ord(if owner == 1 {
                "table_name"
            } else {
                "column_name"
            })?,
            version: ord(if owner == 1 {
                "current_schema"
            } else {
                "start_schema"
            })?,
            column_ids: if owner == 2 {
                Some([
                    ord("column_id")?,
                    ord("domain_id")?,
                    ord("nulls")?,
                    ord("width")?,
                    ord("scale")?,
                    ord("object_id")?,
                ])
            } else {
                None
            },
        })
    }
}

fn inline_catalog_page(h: &RowPageHeader) -> bool {
    matches!(h.owner_id(), 1 | 2) && (1..=4).contains(&h.page_kind())
}

struct Fields {
    table_id: usize,
    name: usize,
    version: usize,
    column_ids: Option<[usize; 6]>,
}

impl Fields {
    fn validated_identity(
        &self,
        context: &CatalogRecoveryContext,
        layout: &RecordLayout,
        header: &RowPageHeader,
        row: &[u8],
    ) -> Option<(u32, u32)> {
        self.checked_identity(context, layout, header, row, true)
    }

    fn checked_identity(
        &self,
        context: &CatalogRecoveryContext,
        layout: &RecordLayout,
        header: &RowPageHeader,
        row: &[u8],
        require_prior_identity: bool,
    ) -> Option<(u32, u32)> {
        let fragment = CatalogFragment::parse(header.owner_id(), header.page_kind(), row)?;
        let record = layout.decode(row).ok()?;
        let (owner, name) = match &fragment {
            CatalogFragment::Column { table_id, name, .. }
            | CatalogFragment::Table { table_id, name } => (*table_id, *name),
        };
        if require_prior_identity && !context.owners.contains(&owner)
            || !matches!(record.fields.get(self.table_id),Some(PhysicalValue::UnsignedInteger(v)) if *v==owner)
            || !matches!(record.fields.get(self.name),Some(PhysicalValue::InlineBytes{bytes,..}) if *bytes==name.as_bytes())
            || !matches!(record.fields.get(self.version),Some(PhysicalValue::UnsignedInteger(v)) if *v<=u32::from(u8::MAX))
        {
            return None;
        }
        match fragment {
            CatalogFragment::Table { .. } => self.column_ids.is_none().then_some((owner, 0)),
            CatalogFragment::Column {
                column_id,
                domain_id,
                nullable,
                width,
                scale,
                object_id,
                ..
            } => {
                let [id, domain, nulls, w, sc, obj] = self.column_ids?;
                (column_id > 0
                    && (!require_prior_identity || context.domains.contains(&domain_id))
                    && matches!(record.fields.get(id), Some(PhysicalValue::UnsignedInteger(v)) if *v==column_id)
                    && matches!(record.fields.get(domain), Some(PhysicalValue::SmallInt(v)) if u16::try_from(*v)==Ok(domain_id))
                    && matches!(record.fields.get(nulls), Some(PhysicalValue::InlineBytes{bytes,..}) if *bytes == if nullable{b"Y"}else{b"N"})
                    && matches!(record.fields.get(w), Some(PhysicalValue::UnsignedInteger(v)) if *v==width)
                    && matches!(record.fields.get(sc), Some(PhysicalValue::SmallInt(v)) if u16::try_from(*v)==Ok(scale))
                    && matches!(record.fields.get(obj), Some(PhysicalValue::UnsignedBigInt(v)) if *v==object_id))
                    .then_some((owner, column_id))
            }
        }
    }
}

/// One physical catalog record accepted by its independent structural and
/// held-out length evidence. The rest of its sparse sector remains unresolved.
#[derive(Debug)]
pub struct CatalogRowCandidate {
    /// Physical page index.
    pub page: u32,
    /// Zero-based physical slot.
    pub slot: u16,
    /// Absolute logical row start.
    pub start: usize,
    /// Sector where the additional catalog evidence was needed.
    pub gap_sector: usize,
    /// Complete candidate catalog record, including its checked length.
    pub bytes: Vec<u8>,
}

/// Additional catalog-specific checks that can refuse a candidate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogRecoveryError {
    /// Physical header or integrity check failed.
    #[error(transparent)]
    Header(#[from] RowHeaderError),
    /// Only data-page kinds of the two system catalogs are eligible.
    #[error("not an inline ISYSTAB or ISYSTABCOL data page")]
    NotCatalog,
    /// The caller's self-describing source layout could not be established.
    #[error("unknown or inconsistent source catalog layout")]
    UnknownLayout,
    /// Source page has incomplete directory or slot cannot be delimited.
    #[error("no complete physical slot span")]
    UnknownSlot,
    /// The entire candidate row was already available under the ordinary model.
    #[error("ordinary sector recovery covers the row")]
    AlreadyCovered,
    /// Two or more unresolved sector bodies cross this row.
    #[error("the row touches multiple unresolved sectors")]
    MultipleGaps,
    /// The unknown bytes were not solely due to insufficient ordinary length anchors.
    #[error("an independently unresolved or contradictory sector prevents catalog recovery")]
    IneligibleGap,
    /// No independently discriminating stored length byte was left to validate.
    #[error("candidate rotations do not yield a discriminating held-out row length")]
    NoHoldout,
    /// No candidate met the full catalog/typed-field conditions.
    #[error("no model satisfies the catalog structure")]
    NoMatch,
    /// Structural matches disagree, including on their held-out word.
    #[error("catalog structural evidence admits different physical row bytes")]
    Ambiguous,
    /// The sole structural candidate does not pass the independent length check.
    #[error("catalog structural candidate disagrees with its held-out length word")]
    LengthMismatch,
}

/// Recover an inline catalog slot when exactly one missing region can be
/// checked by the catalog's field layout and a varying stored row-length
/// word. Ordinary non-catalog and multi-gap pages are outside this route.
pub fn recover_catalog_slot(
    page: Page<'_>,
    slot: u16,
    source_layout: &RecordLayout,
    context: &CatalogRecoveryContext,
) -> Result<CatalogRowCandidate, CatalogRecoveryError> {
    let reader = RowSectorReader::new(page)?;
    let h = reader.header();
    if !inline_catalog_page(h) {
        return Err(CatalogRecoveryError::NotCatalog);
    }
    let rows = h.physical_rows().ok_or(CatalogRecoveryError::UnknownSlot)?;
    let row = rows
        .iter()
        .find(|r| r.slot() == slot)
        .ok_or(CatalogRecoveryError::UnknownSlot)?;
    if row.length() < 3 {
        return Err(CatalogRecoveryError::UnknownSlot);
    }
    let range = row.start()..row.end();
    let fields = context.identity(source_layout, h.owner_id())?;
    let (fixed, gap) = sparse_row_template(page, &reader, range.clone())?;
    let sector_start = gap * SECTOR_SIZE;
    let sector_end = if gap == 7 {
        STASH_START
    } else {
        sector_start + SECTOR_SIZE
    };
    let missing = range.start.max(sector_start)..range.end.min(sector_end);
    if missing.start >= range.start + 2 {
        return Err(CatalogRecoveryError::NoHoldout);
    }
    let mut neighbors = Vec::new();
    for other in rows.iter().filter(|r| r.slot() != slot) {
        if other.length() < 2 {
            return Err(CatalogRecoveryError::IneligibleGap);
        }
        for (i, value) in (other.length() as u16)
            .to_le_bytes()
            .into_iter()
            .enumerate()
        {
            let at = other.start() + i;
            if (sector_start..sector_end).contains(&at) {
                neighbors.push((at - sector_start, value));
            }
        }
    }
    let mut candidates = MaskedCandidates::new(range.len() as u16);
    let consider = |decode: &dyn Fn(usize) -> u8| -> Result<(), CatalogRecoveryError> {
        if neighbors.iter().all(|&(i, want)| decode(i) == want) {
            let mut record = fixed.clone();
            for i in missing.clone() {
                record[i - range.start] = decode(i - sector_start);
            }
            candidates.test(record, |masked| {
                fields
                    .validated_identity(context, source_layout, h, masked)
                    .is_some()
            })?;
        }
        Ok(())
    };
    visit_sector_candidates(page, h, gap, consider)?;
    Ok(CatalogRowCandidate {
        page: h.page_number(),
        slot,
        start: range.start,
        gap_sector: gap,
        bytes: candidates.finish()?,
    })
}

/// Copy known bytes of an occupied row, requiring precisely one sector
/// unresolved solely for lack of length anchors. The range must come from
/// this reader's complete physical directory.
pub(crate) fn sparse_row_template(
    page: Page<'_>,
    reader: &RowSectorReader<'_>,
    row: Range<usize>,
) -> Result<(Vec<u8>, usize), CatalogRecoveryError> {
    let header = reader.header();
    let mut bytes = vec![0; row.len()];
    let mut gap = None;
    let mut missing = |sector| {
        if gap.replace(sector).is_some() {
            Err(CatalogRecoveryError::MultipleGaps)
        } else {
            Ok(())
        }
    };
    for s in row.start / SECTOR_SIZE..=(row.end - 1) / SECTOR_SIZE {
        let sector = s * SECTOR_SIZE;
        let l = row.start.max(sector);
        let r = row.end.min(sector + SECTOR_SIZE);
        let dest = l - row.start..r - row.start;
        let local = l - sector..r - sector;
        if s == 0 {
            bytes[dest].copy_from_slice(&header.sector0()[local]);
        } else if s <= 6 {
            match reader.recover(s) {
                Some(RowSectorRecovery::Unique(key)) => {
                    bytes[dest].copy_from_slice(&key.candidate_bytes()[local])
                }
                Some(RowSectorRecovery::Equivalent { bytes: raw, .. }) => {
                    bytes[dest].copy_from_slice(&raw[local])
                }
                Some(RowSectorRecovery::InsufficientLengths { .. }) => missing(s)?,
                _ => return Err(CatalogRecoveryError::IneligibleGap),
            }
        } else {
            if l < STASH_START {
                match RowTail::recover_from_header(page, header) {
                    Ok(t) => bytes[l - row.start..r.min(STASH_START) - row.start]
                        .copy_from_slice(&t.bytes()[l - sector..r.min(STASH_START) - sector]),
                    Err(RowTailError::InsufficientAnchors { .. }) => missing(7)?,
                    Err(_) => return Err(CatalogRecoveryError::IneligibleGap),
                }
            }
            if r > STASH_START {
                let from = l.max(STASH_START);
                bytes[from - row.start..r - row.start]
                    .copy_from_slice(&header.row_tail_stash()[from - STASH_START..r - STASH_START]);
            }
        }
    }
    Ok((bytes, gap.ok_or(CatalogRecoveryError::AlreadyCovered)?))
}

struct MaskedCandidates {
    expected: u16,
    first_length: Option<u16>,
    varied: bool,
    candidate: Option<Vec<u8>>,
}
impl MaskedCandidates {
    fn new(expected: u16) -> Self {
        Self {
            expected,
            first_length: None,
            varied: false,
            candidate: None,
        }
    }
    fn test(
        &mut self,
        mut bytes: Vec<u8>,
        valid: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), CatalogRecoveryError> {
        let actual = u16::from_le_bytes([bytes[0], bytes[1]]);
        if self.first_length.get_or_insert(actual) != &actual {
            self.varied = true;
        }
        bytes[..2].copy_from_slice(&self.expected.to_le_bytes());
        if valid(&bytes) {
            bytes[..2].copy_from_slice(&actual.to_le_bytes());
            match &self.candidate {
                Some(prior) if *prior != bytes => return Err(CatalogRecoveryError::Ambiguous),
                None => self.candidate = Some(bytes),
                _ => {}
            }
        }
        Ok(())
    }
    fn finish(self) -> Result<Vec<u8>, CatalogRecoveryError> {
        let bytes = self.candidate.ok_or(CatalogRecoveryError::NoMatch)?;
        if !self.varied {
            return Err(CatalogRecoveryError::NoHoldout);
        }
        if bytes[..2] != self.expected.to_le_bytes() {
            return Err(CatalogRecoveryError::LengthMismatch);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{PAGE_SIZE, RecordColumn};
    const PN: u32 = 0x1234_5678;
    pub(crate) fn sample_column() -> (CatalogRecoveryContext, RecordLayout, Vec<u8>) {
        let defs = [
            ("table_id", 21, 4, false),
            ("column_id", 21, 4, false),
            ("domain_id", 1, 2, false),
            ("nulls", 8, 1, false),
            ("width", 21, 4, false),
            ("scale", 1, 2, false),
            ("object_id", 23, 8, false),
            ("max_identity", 20, 8, true),
            ("column_name", 8, 128, false),
            ("start_schema", 21, 4, false),
        ];
        let mut ctx = CatalogRecoveryContext::default();
        let mut columns = Vec::new();
        for (i, (name, d, width, nullable)) in defs.into_iter().enumerate() {
            let ord = (i + 1) as u32;
            ctx.observe(&CatalogFragment::Column {
                table_id: 2,
                column_id: ord,
                name,
                domain_id: d,
                width,
                nullable,
                scale: 0,
                object_id: u64::from(ord),
            });
            columns.push(RecordColumn {
                column_id: ord,
                domain_id: d,
                width,
                nullable,
            });
        }
        ctx.observe(&CatalogFragment::Table {
            table_id: 42,
            name: "fixture",
        });
        let layout = RecordLayout::new(columns).unwrap();
        let mut row = vec![0, 0, 0, 0x80];
        row.extend(42u32.to_le_bytes());
        row.extend(13u32.to_le_bytes());
        row.extend(8i16.to_le_bytes());
        row.extend([1, b'Y']);
        row.extend(128u32.to_le_bytes());
        row.extend(0i16.to_le_bytes());
        row.extend(380u64.to_le_bytes());
        row.extend(6u64.to_le_bytes());
        row.push(6);
        row.extend(b"sample");
        row.extend(0u32.to_le_bytes());
        let len = row.len() as u16;
        row[..2].copy_from_slice(&len.to_le_bytes());
        (ctx, layout, row)
    }

    fn fixture() -> (
        CatalogRecoveryContext,
        RecordLayout,
        [u8; PAGE_SIZE],
        Vec<u8>,
        usize,
    ) {
        let (ctx, layout, row) = sample_column();
        let start = 1024 - row.len();
        let r0 = 109usize;
        let step0 = 37u8;
        let b0 = 91u8;
        let mut header = [0x51; 512];
        header[..4].copy_from_slice(&PN.to_le_bytes());
        header[16] = 4;
        header[17] = 3;
        header[20..22].copy_from_slice(&((start - 28) as u16).to_le_bytes());
        header[22..24].copy_from_slice(&2u16.to_le_bytes());
        header[24..28].copy_from_slice(&2u32.to_le_bytes());
        header[28..30].copy_from_slice(&((start - 28) as u16).to_le_bytes());
        header[30..32].copy_from_slice(&(1024u16 - 28).to_le_bytes());
        let mut raw = [0xd3; PAGE_SIZE];
        for (i, &b) in header.iter().enumerate() {
            let at = (i + r0) % 512;
            raw[at] = b
                .wrapping_add(b0)
                .wrapping_add((at as u8).wrapping_mul(step0));
        }
        let r1 = 73usize;
        let k = (1u8..=255)
            .step_by(2)
            .find(|k| k.wrapping_mul(r1 as u8) == 1)
            .unwrap();
        let step1 = (r0 as u8).wrapping_mul(step0).wrapping_mul(k);
        let sector: [u8; 512] = std::array::from_fn(|i| ((i * i + 13 * i + 5) / 7) as u8);
        for i in 0..512 {
            let b = if i >= start - 512 {
                row[i - (start - 512)]
            } else {
                sector[i]
            };
            let at = (i + r1) % 512;
            raw[512 + at] = b
                .wrapping_add(b0 + 1)
                .wrapping_add((at as u8).wrapping_mul(step1));
        }
        raw[4080..4082].copy_from_slice(&2u16.to_le_bytes());
        raw[4082] = b'E';
        raw[4083] = 0;
        raw[4088..4092].fill(0);
        seal(&mut raw);
        (ctx, layout, raw, row, start)
    }
    fn seal(raw: &mut [u8; PAGE_SIZE]) {
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
    }
    #[test]
    fn recovers_only_the_catalog_slot_and_checks_its_stored_length() {
        let (ctx, layout, mut raw, want, start) = fixture();
        let source = Page::from_bytes(u64::from(PN), &raw).unwrap();
        assert!(matches!(
            RowSectorReader::new(source).unwrap().read_slot(0),
            Some(crate::RowSlotRecovery::Unavailable { .. })
        ));
        let got = recover_catalog_slot(source, 0, &layout, &ctx).unwrap();
        assert_eq!(got.bytes, want);
        assert_eq!((got.start, got.gap_sector, got.slot), (start, 1, 0));
        // Only the held-out length changes; all of the independent catalog
        // fields and the CRC still fit.
        let at = 512 + (start - 512 + 73) % 512;
        raw[at] = raw[at].wrapping_add(1);
        seal(&mut raw);
        let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
        assert!(matches!(
            recover_catalog_slot(page, 0, &layout, &ctx),
            Err(CatalogRecoveryError::LengthMismatch)
        ));
    }
    // The last slot starts immediately after the supplied rows, delimiting
    // their spans independently. Its own bytes are intentionally unresolved.
    fn catalog_page(
        owner: u32,
        rows: &[Vec<u8>],
        repeated: bool,
        competing_key: bool,
    ) -> [u8; PAGE_SIZE] {
        stored_catalog_page(PN, owner, 3, rows, repeated, competing_key)
    }

    pub(crate) fn stored_catalog_page(
        number: u32,
        owner: u32,
        kind: u8,
        rows: &[Vec<u8>],
        repeated: bool,
        competing_key: bool,
    ) -> [u8; PAGE_SIZE] {
        let slots = rows.len() + 2;
        let mut plain = [0x53u8; SECTOR_SIZE];
        plain[..4].copy_from_slice(&number.to_le_bytes());
        plain[16] = 4;
        plain[17] = kind;
        plain[20..22].copy_from_slice(&72u16.to_le_bytes());
        plain[22..24].copy_from_slice(&(slots as u16).to_le_bytes());
        plain[24..28].copy_from_slice(&owner.to_le_bytes());
        let mut start = 100usize;
        for (slot, row) in rows.iter().enumerate() {
            plain[28 + 2 * slot..30 + 2 * slot]
                .copy_from_slice(&((start - 28) as u16).to_le_bytes());
            plain[start..start + row.len()].copy_from_slice(row);
            start += row.len();
        }
        let marker = 28 + rows.len() * 2;
        plain[marker..marker + 2].fill(0); // vacant slot
        plain[marker + 2..marker + 4].copy_from_slice(&((start - 28) as u16).to_le_bytes());
        if repeated {
            plain[440..444].copy_from_slice(&number.to_le_bytes());
        }
        if competing_key {
            // A second odd rotation 256 bytes from the first sees a separate
            // valid catalog header and directory under the same additive key.
            plain.copy_within(..28 + 2 * slots, 256);
        }
        let mut raw = [0; PAGE_SIZE];
        for (i, &byte) in plain.iter().enumerate() {
            let stored = (i + 121) % SECTOR_SIZE;
            raw[stored] = byte
                .wrapping_add(53)
                .wrapping_add((stored as u8).wrapping_mul(77));
        }
        raw[4080..4082].copy_from_slice(&((slots - 1) as u16).to_le_bytes());
        raw[4082] = b'E';
        seal(&mut raw);
        raw
    }

    fn other_column(row: &[u8], id: u32) -> Vec<u8> {
        let mut bytes = row.to_vec();
        bytes[8..12].copy_from_slice(&id.to_le_bytes());
        bytes
    }

    #[test]
    fn repeated_page_keeps_only_length_and_field_checked_occupied_slots() {
        let (ctx, layout, _, row, _) = fixture();
        let layouts = [None, Some(layout)];
        let other = other_column(&row, 14);
        let mut unknown = other_column(&row, 15);
        unknown[4..8].copy_from_slice(&43u32.to_le_bytes()); // missing from first pass
        let mut bad_length = other_column(&row, 16);
        bad_length[0] += 1;
        let mut bad_version = other_column(&row, 17);
        let version = bad_version.len() - 4;
        bad_version[version..].copy_from_slice(&256u32.to_le_bytes());
        let rows = [row.clone(), unknown, other.clone(), bad_length, bad_version];
        let raw = catalog_page(2, &rows, true, false);
        let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
        assert!(matches!(
            RowPageHeader::recover(page),
            Err(RowHeaderError::Ambiguous { .. })
        ));
        let out = ctx.recover_repeated_page(page, &layouts).unwrap().unwrap();
        assert_eq!((out.owner, out.kind), (2, 3));
        assert_eq!(out.rows, vec![(0, row), (2, other)]);
        assert_eq!(out.unverified_slots, 4); // three invalid and the delimiter
        assert!(
            ctx.recover_repeated_page(page, &[None, None])
                .unwrap()
                .is_none()
        );
        assert!(
            CatalogRecoveryContext::default()
                .recover_repeated_page(page, &layouts)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn table_definitions_need_two_different_known_table_ids() {
        let mut ctx = CatalogRecoveryContext::default();
        let defs = [
            ("table_id", 21, 4, false),
            ("counter1", 23, 8, true),
            ("counter2", 23, 8, false),
            ("counter3", 23, 8, false),
            ("counter4", 23, 8, false),
            ("counter5", 23, 8, false),
            ("number", 21, 4, false),
            ("small", 1, 2, false),
            ("table_name", 8, 128, false),
            ("current_schema", 21, 4, false),
        ];
        let mut columns = Vec::new();
        for (i, (name, domain_id, width, nullable)) in defs.into_iter().enumerate() {
            let column_id = i as u32 + 1;
            ctx.observe(&CatalogFragment::Column {
                table_id: 1,
                column_id,
                name,
                domain_id,
                width,
                nullable,
                scale: 0,
                object_id: u64::from(column_id),
            });
            columns.push(RecordColumn {
                column_id,
                domain_id,
                width,
                nullable,
            });
        }
        for id in [42, 43] {
            ctx.observe(&CatalogFragment::Table {
                table_id: id,
                name: "fixture",
            });
        }
        let layouts = [Some(RecordLayout::new(columns).unwrap()), None];
        let definition = |id: u32, name: u8| {
            let mut row = vec![0; 60];
            row[..2].copy_from_slice(&60u16.to_le_bytes());
            row[3] = 0x80;
            row[4..8].copy_from_slice(&id.to_le_bytes());
            row[54..56].copy_from_slice(&[1, name]);
            row
        };
        for (id, expect) in [(43, true), (42, false), (44, false)] {
            let rows = [definition(42, b'a'), definition(id, b'b')];
            let raw = catalog_page(1, &rows, true, false);
            let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
            let result = ctx.recover_repeated_page(page, &layouts).unwrap();
            assert_eq!(result.is_some(), expect);
            if let Some(confirmed) = result {
                assert_eq!(confirmed.owner, 1);
                assert_eq!(confirmed.unverified_slots, 1);
                assert_eq!(
                    confirmed.rows,
                    rows.into_iter()
                        .enumerate()
                        .map(|(slot, row)| (slot as u16, row))
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn duplicate_and_single_identities_cannot_confirm_a_repeated_page() {
        let (ctx, layout, _, row, _) = fixture();
        let layouts = [None, Some(layout)];
        // A different name and object id still denote the same (table, column).
        let mut duplicate = row.clone();
        duplicate[22] += 1;
        duplicate[39] = b't';
        for rows in [vec![row.clone()], vec![row, duplicate]] {
            let raw = catalog_page(2, &rows, true, false);
            let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
            assert!(ctx.recover_repeated_page(page, &layouts).unwrap().is_none());
        }
    }

    #[test]
    fn ordinary_or_multiple_structural_keys_never_use_repeated_page_route() {
        let (ctx, layout, _, row, _) = fixture();
        let layouts = [None, Some(layout)];
        let rows = [row.clone(), other_column(&row, 14)];
        for (repeated, competing) in [(false, false), (true, true)] {
            let mut raw = catalog_page(2, &rows, repeated, competing);
            let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
            let candidates = RowPageHeader::structural_candidates(page).unwrap().count();
            assert_eq!(candidates, if competing { 2 } else { 1 });
            assert!(ctx.recover_repeated_page(page, &layouts).unwrap().is_none());
            raw[2900] ^= 1;
            let corrupt = Page::from_bytes(u64::from(PN), &raw).unwrap();
            assert!(matches!(
                ctx.recover_repeated_page(corrupt, &layouts),
                Err(RowHeaderError::Integrity(_))
            ));
        }
    }
    const FORWARD_SOURCE: u32 = 63;
    const FORWARD_TARGET: u32 = 64;

    fn pointer(target: u32, slot: u16) -> Vec<u8> {
        let mut row = vec![9, 0, 4];
        row.extend(target.to_le_bytes());
        row.extend(slot.to_le_bytes());
        row
    }

    fn forward_store(src: [u8; PAGE_SIZE], dst: [u8; PAGE_SIZE]) -> crate::PageStore {
        let mut bytes = vec![0; (FORWARD_TARGET as usize + 1) * PAGE_SIZE];
        bytes[FORWARD_SOURCE as usize * PAGE_SIZE..][..PAGE_SIZE].copy_from_slice(&src);
        bytes[FORWARD_TARGET as usize * PAGE_SIZE..][..PAGE_SIZE].copy_from_slice(&dst);
        crate::PageStore::from_bytes_unchecked(bytes).unwrap()
    }

    #[test]
    fn forwarded_catalog_record_uses_the_originating_layout_and_keeps_both_slots() {
        let (ctx, layout, col) = sample_column();
        let layouts = [None, Some(layout)];
        let terminal = other_column(&col, 99);
        let mut bad_stub = pointer(FORWARD_TARGET, 0);
        bad_stub[0] = 8;
        let src = [
            col.clone(),
            other_column(&col, 14),
            pointer(FORWARD_TARGET, 0),
            bad_stub,
        ];
        for repeated in [false, true] {
            let ordinary = stored_catalog_page(FORWARD_SOURCE, 2, 3, &src, repeated, false);
            let target = stored_catalog_page(
                FORWARD_TARGET,
                2,
                0x12,
                std::slice::from_ref(&terminal),
                false,
                false,
            );
            let db = forward_store(ordinary, target);
            let cal = CalibratedStore::new(&db);
            let page = db.page(u64::from(FORWARD_SOURCE)).unwrap();
            if repeated {
                let p = ctx.recover_repeated_page(page, &layouts).unwrap().unwrap();
                assert_eq!(p.forward_slots, vec![(2, (FORWARD_TARGET, 0))]);
                assert_eq!(p.rows.len(), 2);
                assert_eq!(p.unverified_slots, 3); // two stubs and the delimiter
            } else {
                RowPageHeader::recover(page).unwrap();
            }
            let forwarded = ctx
                .corroborated_forwarded_slot(&cal, FORWARD_SOURCE, 2, &layouts)
                .unwrap();
            assert_eq!(forwarded.owner_id, 2);
            assert_eq!(
                (forwarded.source.page, forwarded.source.slot),
                (FORWARD_SOURCE, 2)
            );
            assert_eq!(
                (forwarded.target.page, forwarded.target.slot),
                (FORWARD_TARGET, 0)
            );
            assert_eq!(forwarded.source.bytes, src[2]);
            assert_eq!(forwarded.target.bytes, terminal);
            for slot in [0, 3] {
                assert!(
                    ctx.corroborated_forwarded_slot(&cal, FORWARD_SOURCE, slot, &layouts)
                        .is_none()
                );
            }
            assert!(
                ctx.corroborated_forwarded_slot(&cal, FORWARD_SOURCE, 2, &[None, None])
                    .is_none()
            );
        }
    }

    #[test]
    fn targets_cannot_supply_their_own_source_page_corroboration() {
        let (ctx, layout, col) = sample_column();
        let layouts = [None, Some(layout)];
        let target_row = other_column(&col, 99);
        let target = stored_catalog_page(FORWARD_TARGET, 2, 0x12, &[target_row], false, false);
        for (second_id, competing) in [(13, false), (14, true)] {
            let src = [
                col.clone(),
                other_column(&col, second_id),
                pointer(FORWARD_TARGET, 0),
            ];
            let source = stored_catalog_page(FORWARD_SOURCE, 2, 3, &src, true, competing);
            let db = forward_store(source, target);
            let cal = CalibratedStore::new(&db);
            assert!(
                ctx.recover_repeated_page(db.page(u64::from(FORWARD_SOURCE)).unwrap(), &layouts)
                    .unwrap()
                    .is_none()
            );
            assert!(
                ctx.corroborated_forwarded_slot(&cal, FORWARD_SOURCE, 2, &layouts)
                    .is_none()
            );
        }
    }

    #[test]
    fn forwarded_catalog_targets_require_a_unique_header_same_owner_and_checked_fields() {
        let (ctx, layout, col) = sample_column();
        let layouts = [None, Some(layout)];
        let source = stored_catalog_page(
            FORWARD_SOURCE,
            2,
            3,
            &[pointer(FORWARD_TARGET, 0)],
            false,
            false,
        );
        let mut foreign = col.clone();
        foreign[4..8].copy_from_slice(&43u32.to_le_bytes());
        let mut wrong_schema = col.clone();
        let at = wrong_schema.len() - 4;
        wrong_schema[at..].copy_from_slice(&256u32.to_le_bytes());
        for (row, owner, kind, repeated) in [
            (&col, 2, 0x12, true),
            (&col, 1, 0x12, false),
            (&col, 2, 3, false),
            (&foreign, 2, 0x12, false),
            (&wrong_schema, 2, 0x12, false),
            (&pointer(FORWARD_SOURCE, 0), 2, 0x12, false),
        ] {
            let target = stored_catalog_page(
                FORWARD_TARGET,
                owner,
                kind,
                std::slice::from_ref(row),
                repeated,
                false,
            );
            let db = forward_store(source, target);
            let cal = CalibratedStore::new(&db);
            assert!(
                ctx.corroborated_forwarded_slot(&cal, FORWARD_SOURCE, 0, &layouts)
                    .is_none()
            );
        }
    }

    #[test]
    fn omitting_a_source_field_does_not_relax_schema_matching() {
        let (ctx, _, raw, _, _) = fixture();
        let wrong = RecordLayout::new(vec![RecordColumn {
            column_id: 1,
            domain_id: 21,
            width: 4,
            nullable: false,
        }])
        .unwrap();
        let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
        assert!(matches!(
            recover_catalog_slot(page, 0, &wrong, &ctx),
            Err(CatalogRecoveryError::UnknownLayout)
        ));
    }
    #[test]
    fn withholding_length_does_not_let_it_select_a_structural_match() {
        let mut candidates = MaskedCandidates::new(3);
        candidates
            .test(vec![3, 0, 12], |masked| masked[2] == 12)
            .unwrap();
        assert!(matches!(
            candidates.test(vec![4, 0, 12], |masked| masked[2] == 12),
            Err(CatalogRecoveryError::Ambiguous)
        ));
        let mut candidates = MaskedCandidates::new(3);
        candidates.test(vec![3, 0, 12], |_| true).unwrap();
        assert!(matches!(
            candidates.finish(),
            Err(CatalogRecoveryError::NoHoldout)
        ));
        let mut candidates = MaskedCandidates::new(3);
        candidates
            .test(vec![4, 0, 12], |masked| masked == [3, 0, 12])
            .unwrap();
        candidates
            .test(vec![3, 0, 10], |masked| masked == [3, 0, 12])
            .unwrap();
        assert!(matches!(
            candidates.finish(),
            Err(CatalogRecoveryError::LengthMismatch)
        ));
        for r in (1u8..=255).step_by(2) {
            assert_eq!(inverse_odd(r).wrapping_mul(r), 1)
        }
    }
}
