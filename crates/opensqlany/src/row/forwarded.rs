//! An observed row forward contains length 9, flags 0x04 or 0x44, a
//! little-endian page number (u32) and a zero-based slot number (u16).
//! Both forms store the address at byte 3. A 0x04 source references a
//! flags-zero terminal. A 0x44 source references a 0x40 terminal that carries
//! its own schema byte. The resolver returns both complete physical slots.
//! Logical membership and the applicable typed layout require separate evidence.

use crate::{
    CalibratedPage, CalibratedStore, CalibrationGap, RowHeaderError, RowLengthMismatch,
    RowSectorRecovery, RowSlotRecovery, RowSlotSector, RowTailError,
};

/// One fully length-checked physical slot and its sector evidence.
#[derive(Debug)]
pub struct ForwardedSlot<'a> {
    /// Physical page number.
    pub page: u32,
    /// Zero-based physical slot on that page.
    pub slot: u16,
    /// Inclusive logical start within the page.
    pub start: usize,
    /// Entire physical record, including its own stored length and flags.
    pub bytes: Vec<u8>,
    /// Evidence for all regions used to reconstruct these bytes.
    pub sectors: Vec<RowSlotSector<'a>>,
}

/// One physical nine-byte forward and its terminal same-owner record.
#[derive(Debug)]
pub struct ForwardedRow<'a> {
    /// Owner independently recovered from both headers.
    pub owner_id: u32,
    /// Original nine-byte record from an ordinary row page.
    pub source: ForwardedSlot<'a>,
    /// Terminal record from the referenced chunk page, including its schema
    /// byte when the source uses the versioned form.
    pub target: ForwardedSlot<'a>,
}

impl<'a> CalibratedStore<'a> {
    /// Resolve one observed physical row forward. Both slots are bounded by
    /// complete directories and checked against their own stored length words.
    /// Every target is read from this store using its ordinary header checks.
    pub fn resolve_forwarded_row(
        &self,
        page: u32,
        slot: u16,
    ) -> Result<ForwardedRow<'a>, ForwardedRowError> {
        self.page(page)
            .map_err(|source| ForwardedRowError::Header { page, source })?
            .resolve_forwarded_row(slot)
    }
}

pub(crate) fn from_page<'a>(
    store: &CalibratedStore<'a>,
    reader: &CalibratedPage<'_, 'a>,
    slot: u16,
) -> Result<ForwardedRow<'a>, ForwardedRowError> {
    from_selected_page(store, reader, slot, false)
}

pub(crate) fn from_mapped_page<'a>(
    store: &CalibratedStore<'a>,
    reader: &CalibratedPage<'_, 'a>,
    slot: u16,
) -> Result<ForwardedRow<'a>, ForwardedRowError> {
    from_selected_page(store, reader, slot, true)
}

fn from_selected_page<'a>(
    store: &CalibratedStore<'a>,
    reader: &CalibratedPage<'_, 'a>,
    slot: u16,
    mapped: bool,
) -> Result<ForwardedRow<'a>, ForwardedRowError> {
    let (source, page, target_slot) = forward_source(store, reader, slot)?;
    let target_reader =
        match store.page(page) {
            Ok(target) => target,
            Err(prior @ RowHeaderError::Ambiguous { .. }) if mapped => {
                let stored = store.store().page(u64::from(page)).map_err(|error| {
                    ForwardedRowError::Header {
                        page,
                        source: RowHeaderError::Integrity(error),
                    }
                })?;
                let header = crate::RowPageHeader::sole_repeated_lob(
                    stored,
                    reader.header().owner_id(),
                    target_slot,
                )
                .map_err(|source| ForwardedRowError::Header { page, source })?
                .ok_or(ForwardedRowError::Header {
                    page,
                    source: prior,
                })?;
                store.page_with_header(stored, header)
            }
            Err(source) => return Err(ForwardedRowError::Header { page, source }),
        };
    forward_target(
        source,
        reader.header().owner_id(),
        &target_reader,
        target_slot,
    )
}

pub(crate) fn forward_source<'a>(
    store: &CalibratedStore<'a>,
    reader: &CalibratedPage<'_, 'a>,
    slot: u16,
) -> Result<(ForwardedSlot<'a>, u32, u16), ForwardedRowError> {
    let header = reader.header();
    if !(1..=4).contains(&header.page_kind()) {
        return Err(ForwardedRowError::SourceKind(header.page_kind()));
    }
    let source = checked_slot(reader, slot)?;
    let (page, slot) = forwarded_row_address(&source.bytes).ok_or(ForwardedRowError::SourceForm)?;
    if page == source.page {
        if slot == source.slot {
            return Err(ForwardedRowError::Cycle);
        }
        return Err(ForwardedRowError::SamePage(page));
    }
    let pages = store.store().page_count();
    if page == 0 || u64::from(page) >= pages {
        return Err(ForwardedRowError::TargetRange { page, pages });
    }
    Ok((source, page, slot))
}

// Both callers validate the source in this same store and open the target
// page at the address returned by forward_source before entering here.
pub(crate) fn forward_target<'a>(
    source: ForwardedSlot<'a>,
    owner_id: u32,
    target_reader: &CalibratedPage<'_, 'a>,
    slot: u16,
) -> Result<ForwardedRow<'a>, ForwardedRowError> {
    let header = target_reader.header();
    if header.owner_id() != owner_id {
        return Err(ForwardedRowError::Owner {
            expected: owner_id,
            actual: header.owner_id(),
        });
    }
    if !(0x11..=0x14).contains(&header.page_kind()) {
        return Err(ForwardedRowError::TargetKind(header.page_kind()));
    }
    let target = checked_slot(target_reader, slot)?;
    let source_flags = source.bytes[2]; // forward_source checked its exact nine-byte frame.
    match (source_flags, target.bytes.get(2).copied()) {
        (0x44, Some(0x40)) if target.bytes.len() < 4 => Err(ForwardedRowError::TruncatedTarget),
        (0x04, Some(0x00)) | (0x44, Some(0x40)) => Ok(ForwardedRow {
            owner_id,
            source,
            target,
        }),
        (_, Some(0x04 | 0x44)) => {
            // Classify a visible cycle without reading another page or slot.
            if forwarded_row_address(&target.bytes).is_some_and(|next| {
                next == (source.page, source.slot) || next == (target.page, target.slot)
            }) {
                return Err(ForwardedRowError::Cycle);
            }
            Err(ForwardedRowError::Nonterminal)
        }
        (_, Some(flags)) => Err(ForwardedRowError::TargetFlags(flags)),
        (_, None) => Err(ForwardedRowError::TruncatedTarget),
    }
}

/// Parse the stored address of an exact nine-byte 0x04 or 0x44 forward.
/// Use the store or page resolver to corroborate the two slots, page kinds,
/// ownership and paired terminal flags.
pub fn forwarded_row_address(bytes: &[u8]) -> Option<(u32, u16)> {
    let &[9, 0, 0x04 | 0x44, p0, p1, p2, p3, s0, s1] = bytes else {
        return None;
    };
    Some((
        u32::from_le_bytes([p0, p1, p2, p3]),
        u16::from_le_bytes([s0, s1]),
    ))
}

fn checked_slot<'a>(
    reader: &CalibratedPage<'_, 'a>,
    slot: u16,
) -> Result<ForwardedSlot<'a>, ForwardedRowError> {
    let page = reader.header().page_number();
    match reader.read_slot(slot) {
        None => Err(ForwardedRowError::SlotRange { page, slot }),
        Some(RowSlotRecovery::Vacant) => Err(ForwardedRowError::Vacant { page, slot }),
        Some(RowSlotRecovery::IncompleteDirectory) => {
            Err(ForwardedRowError::PartialDirectory(page))
        }
        Some(RowSlotRecovery::LengthMismatch { error, .. }) => Err(error.into()),
        Some(RowSlotRecovery::Unavailable { sectors, .. }) => {
            for region in sectors {
                match region {
                    RowSlotSector::Full {
                        index,
                        recovery: RowSectorRecovery::Ambiguous { .. },
                    } => {
                        return Err(ForwardedRowError::AmbiguousSector {
                            page,
                            slot,
                            sector: index,
                        });
                    }
                    RowSlotSector::TailGap(RowTailError::Ambiguous { .. }) => {
                        return Err(ForwardedRowError::AmbiguousSector {
                            page,
                            slot,
                            sector: 7,
                        });
                    }
                    RowSlotSector::CalibrationGap { index, reason } => {
                        return Err(ForwardedRowError::Calibration {
                            page,
                            slot,
                            sector: index,
                            reason,
                        });
                    }
                    _ => {}
                }
            }
            Err(ForwardedRowError::Unavailable { page, slot })
        }
        Some(RowSlotRecovery::Candidate {
            start,
            bytes,
            sectors,
        }) => Ok(ForwardedSlot {
            page,
            slot,
            start,
            bytes,
            sectors,
        }),
    }
}

/// Why a single physical row forward could not be corroborated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ForwardedRowError {
    /// The explicit source bitmap did not verify the requested source member.
    #[error(transparent)]
    SourceMap(#[from] crate::PageBitmapError),
    /// The source or target page did not have a uniquely validated header.
    #[error("forward page {page} could not be read: {source}")]
    Header {
        /// Address of the page.
        page: u32,
        /// Underlying reason, including ambiguity or integrity failure.
        source: RowHeaderError,
    },
    /// The referring row is not on an ordinary data page.
    #[error("unsupported source page kind {0:#04x}")]
    SourceKind(u8),
    /// The source bytes do not exactly match the nine-byte direct-forward form.
    #[error("source row is not a nine-byte 0x04 or 0x44 forward")]
    SourceForm,
    /// The target points into the source page, outside the observed form.
    #[error("forward refers to another slot on the source page {0}")]
    SamePage(u32),
    /// The source points to itself, or the next visible pointer repeats an endpoint.
    #[error("physical row forward contains a cycle")]
    Cycle,
    /// The target is not a data page in this store.
    #[error("forward page {page} is outside data pages in a {pages}-page store")]
    TargetRange {
        /// Requested page number.
        page: u32,
        /// Number of physical pages in the store.
        pages: u64,
    },
    /// The target belongs to a different owner.
    #[error("forward target owner is {actual}, source owner is {expected}")]
    Owner {
        /// Owner of the source page.
        expected: u32,
        /// Owner of the target page.
        actual: u32,
    },
    /// The target is outside the corroborated chunk-page family.
    #[error("unsupported forward target page kind {0:#04x}")]
    TargetKind(u8),
    /// The requested source or target slot lies outside the directory.
    #[error("page {page} has no slot {slot}")]
    SlotRange {
        /// Physical page number.
        page: u32,
        /// Requested slot.
        slot: u16,
    },
    /// The directory slot contains zero.
    #[error("page {page} slot {slot} is vacant")]
    Vacant {
        /// Physical page number.
        page: u32,
        /// Requested slot.
        slot: u16,
    },
    /// Without complete slot boundaries the stored record cannot be confirmed.
    #[error("forward page {0} has an incomplete slot directory")]
    PartialDirectory(u32),
    /// A physically bounded slot disagrees with its stored length word.
    #[error(transparent)]
    Length(#[from] RowLengthMismatch),
    /// No complete bytes could be obtained for this slot.
    #[error("page {page} slot {slot} has unresolved sectors")]
    Unavailable {
        /// Physical page number.
        page: u32,
        /// Requested slot.
        slot: u16,
    },
    /// Multiple sector plaintexts remained possible.
    #[error("page {page} slot {slot} has an ambiguous sector {sector}")]
    AmbiguousSector {
        /// Physical page number.
        page: u32,
        /// Requested slot.
        slot: u16,
        /// Sector with conflicting plaintexts.
        sector: usize,
    },
    /// A calibrated region could not be independently corroborated.
    #[error("page {page} slot {slot} sector {sector}: {reason}")]
    Calibration {
        /// Physical page number.
        page: u32,
        /// Requested slot.
        slot: u16,
        /// Unavailable sector number.
        sector: usize,
        /// Why calibration declined.
        reason: CalibrationGap,
    },
    /// The target slot is too short to contain the required flags or schema byte.
    #[error("forward target has a truncated record header")]
    TruncatedTarget,
    /// The target carries another forward instead of a terminal record.
    #[error("forward target is not terminal")]
    Nonterminal,
    /// The target flags do not match the source forward form.
    #[error("unsupported forward target flags {0:#04x}")]
    TargetFlags(u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PAGE_SIZE, PageStore};

    const SOURCE: u32 = 2;
    const TARGET: u32 = 5;
    const OWNER: u32 = 77;

    fn pointer(page: u32, slot: u16) -> Vec<u8> {
        let mut bytes = vec![9, 0, 4];
        bytes.extend(page.to_le_bytes());
        bytes.extend(slot.to_le_bytes());
        bytes
    }

    fn data_page(pn: u32, owner: u32, kind: u8, row: &[u8], repeated: bool) -> [u8; PAGE_SIZE] {
        data_page_rows(pn, owner, kind, &[row], repeated)
    }

    fn data_page_rows(
        pn: u32,
        owner: u32,
        kind: u8,
        rows: &[&[u8]],
        repeated: bool,
    ) -> [u8; PAGE_SIZE] {
        let slot = usize::from(pn == TARGET);
        let start = if slot == 0 { 140 } else { 180 };
        let mut plain = [0x9bu8; 512];
        plain[..4].copy_from_slice(&pn.to_le_bytes());
        plain[16] = 4;
        plain[17] = kind;
        plain[20..22].copy_from_slice(&((start - 28) as u16).to_le_bytes());
        plain[22..24].copy_from_slice(&((slot + rows.len() + 1) as u16).to_le_bytes());
        plain[24..28].copy_from_slice(&owner.to_le_bytes());
        plain[28..34].fill(0);
        let mut cursor = start;
        for (index, row) in rows.iter().enumerate() {
            let dir = 28 + 2 * (slot + index);
            plain[dir..dir + 2].copy_from_slice(&((cursor - 28) as u16).to_le_bytes());
            plain[cursor..cursor + row.len()].copy_from_slice(row);
            cursor += row.len();
            plain[dir + 2..dir + 4].copy_from_slice(&((cursor - 28) as u16).to_le_bytes());
        }
        if repeated {
            plain[400..404].copy_from_slice(&pn.to_le_bytes());
        }
        let mut raw = [0; PAGE_SIZE];
        for (logical, value) in plain.iter().copied().enumerate() {
            let at = (logical + 63) % 512;
            raw[at] = value
                .wrapping_add(97)
                .wrapping_add((at as u8).wrapping_mul(11));
        }
        raw[4080] = if slot == 0 { rows.len() as u8 + 1 } else { 2 };
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    // Keep a self-pointer's physical page number outside the header sector.
    // Three different physical lengths constrain the sector independent of
    // the six bytes used for the address.
    fn body_pointer_page(pn: u32, kind: u8, row: &[u8]) -> [u8; PAGE_SIZE] {
        let slot = usize::from(pn == TARGET);
        let mut raw = data_page(pn, OWNER, kind, &[3, 0, 0], false);
        let set_word = |raw: &mut [u8], logical: usize, n: usize| {
            for (j, v) in (n as u16).to_le_bytes().into_iter().enumerate() {
                let i = (logical + j + 63) % 512;
                raw[i] = v.wrapping_add(97).wrapping_add(11u8.wrapping_mul(i as u8));
            }
        };
        let starts = [560, 560 + row.len(), 760, 960];
        set_word(&mut raw, 20, starts[0] - 28);
        set_word(&mut raw, 22, starts.len() + slot);
        let mut body: [u8; 512] = std::array::from_fn(|i| ((i * i + 17 * i) / 13) as u8);
        for (index, &at) in starts.iter().enumerate() {
            set_word(&mut raw, 28 + (slot + index) * 2, at - 28);
            let end = starts.get(index + 1).copied().unwrap_or(4092);
            body[at - 512..at - 510].copy_from_slice(&((end - at) as u16).to_le_bytes());
        }
        body[48..48 + row.len()].copy_from_slice(row);
        let rotation = 71usize;
        let d = 63u8.wrapping_mul(11);
        let step = (0u8..=255)
            .find(|k| k.wrapping_mul(rotation as u8) == d)
            .unwrap();
        for (logical, v) in body.iter().copied().enumerate() {
            let at = (rotation + logical) % 512;
            raw[512 + at] = v.wrapping_add(98).wrapping_add(step.wrapping_mul(at as u8));
        }
        raw[4080] = starts.len() as u8;
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    fn store(source: [u8; PAGE_SIZE], target: [u8; PAGE_SIZE]) -> PageStore {
        let mut bytes = vec![0; PAGE_SIZE * (TARGET as usize + 1)];
        bytes[SOURCE as usize * PAGE_SIZE..][..PAGE_SIZE].copy_from_slice(&source);
        bytes[TARGET as usize * PAGE_SIZE..][..PAGE_SIZE].copy_from_slice(&target);
        PageStore::from_bytes_unchecked(bytes).unwrap()
    }

    fn from_rows(source: &[u8], target: &[u8]) -> PageStore {
        store(
            data_page(SOURCE, OWNER, 3, source, false),
            data_page(TARGET, OWNER, 0x11, target, false),
        )
    }

    #[test]
    fn address_parser_checks_every_framing_byte_and_both_little_endian_fields() {
        let bytes = [9, 0, 4, 4, 3, 2, 1, 6, 5];
        assert_eq!(forwarded_row_address(&bytes), Some((0x01020304, 0x0506)));
        let mut versioned = bytes;
        versioned[2] = 0x44;
        assert_eq!(
            forwarded_row_address(&versioned),
            forwarded_row_address(&bytes)
        );
        for position in [0, 1, 2] {
            let mut bad = bytes;
            bad[position] ^= 1;
            assert!(forwarded_row_address(&bad).is_none());
        }
        assert!(forwarded_row_address(&bytes[..8]).is_none());
        assert!(forwarded_row_address(&[bytes.as_slice(), &[0]].concat()).is_none());
        for flags in [0, 8, 0x40, 0x45, 0x84] {
            versioned[2] = flags;
            assert!(forwarded_row_address(&versioned).is_none());
        }
    }

    #[test]
    fn pairs_forward_forms_with_their_own_terminal_header() {
        let plain = pointer(TARGET, 1);
        let mut versioned = plain.clone();
        versioned[2] = 0x44;
        let body = [5, 0, 0x40, 7, 0xe2];
        let db = from_rows(&versioned, &body);
        let reader = CalibratedStore::new(&db);
        let pair = reader.resolve_forwarded_row(SOURCE, 0).unwrap();
        assert_eq!(pair.source.bytes, versioned);
        assert_eq!(pair.target.bytes, body);
        assert_eq!((pair.target.page, pair.target.slot), (TARGET, 1));
        let error = |s: &[u8], t: &[u8]| {
            let store = from_rows(s, t);
            CalibratedStore::new(&store)
                .resolve_forwarded_row(SOURCE, 0)
                .unwrap_err()
        };
        assert!(matches!(
            error(&plain, &body),
            ForwardedRowError::TargetFlags(0x40)
        ));
        assert!(matches!(
            error(&versioned, &[3, 0, 0]),
            ForwardedRowError::TargetFlags(0)
        ));
        assert!(matches!(
            error(&versioned, &[3, 0, 0x40]),
            ForwardedRowError::TruncatedTarget
        ));
        let mut next = pointer(99, 0);
        next[2] = 0x44;
        assert!(matches!(
            error(&versioned, &next),
            ForwardedRowError::Nonterminal
        ));
        let mut cycle = pointer(SOURCE, 0);
        cycle[2] = 0x44;
        assert!(matches!(
            error(&versioned, &cycle),
            ForwardedRowError::Cycle
        ));
    }

    #[test]
    fn preserves_both_complete_slots_and_their_independent_provenance() {
        let pointer = pointer(TARGET, 1);
        let terminal = [7, 0, 0, 0xa3, 0, 0xff, 0x10];
        let live = [8, 0, 0x40, 0, 3, 0, 0, 0];
        let deleted = [7, 0, 1, 171, 0, 0, 0];
        let db = store(
            data_page_rows(SOURCE, OWNER, 3, &[&pointer, &live, &deleted], false),
            data_page(TARGET, OWNER, 0x11, &terminal, false),
        );
        let calibrated = CalibratedStore::new(&db);
        let read = calibrated.resolve_forwarded_row(SOURCE, 0).unwrap();
        assert_eq!(read.owner_id, OWNER);
        assert_eq!(
            (read.source.page, read.source.slot, read.source.start),
            (SOURCE, 0, 140)
        );
        assert_eq!(read.source.bytes, pointer);
        assert_eq!(
            (read.target.page, read.target.slot, read.target.start),
            (TARGET, 1, 180)
        );
        assert_eq!(read.target.bytes, terminal);
        assert!(matches!(
            read.source.sectors.as_slice(),
            [RowSlotSector::Header]
        ));
        assert!(matches!(
            read.target.sectors.as_slice(),
            [RowSlotSector::Header]
        ));
        let read = calibrated
            .page(SOURCE)
            .unwrap()
            .resolve_forwarded_row(0)
            .unwrap();
        assert_eq!(read.target.bytes, terminal);
        let page = calibrated.page(SOURCE).unwrap();
        let Some(RowSlotRecovery::Candidate { bytes, .. }) = page.read_slot(1) else {
            panic!("the adjacent versioned live record must remain length-checked");
        };
        assert_eq!(bytes, live);
        let layout = crate::RecordLayout::new(vec![crate::RecordColumn {
            column_id: 1,
            domain_id: 21,
            width: 4,
            nullable: false,
        }])
        .unwrap();
        let row = layout.decode(&bytes).unwrap();
        assert_eq!(row.extra, Some(0));
        assert_eq!(row.fields, [crate::PhysicalValue::UnsignedInteger(3)]);
        let Some(RowSlotRecovery::Candidate { bytes, .. }) = page.read_slot(2) else {
            panic!("the adjacent deleted record must retain its physical bytes");
        };
        assert_eq!(bytes, deleted);
    }

    #[test]
    fn verified_forward_reference_can_bind_a_sole_repeated_target_header() {
        let terminal = [7, 0, 0, 0xa3, 0, 0xff, 0x10];
        let target = |owner, kind| {
            let mut raw = data_page(TARGET, owner, kind, &terminal, true);
            // Target slot zero is vacant, so its occupied directory prefix is zero.
            raw[4080..4082].fill(0);
            let crc = crc32fast::hash(&raw[..4092]);
            raw[4092..].copy_from_slice(&crc.to_le_bytes());
            raw
        };
        let db = store(
            data_page(SOURCE, OWNER, 3, &pointer(TARGET, 1), false),
            target(OWNER, 0x11),
        );
        let reader = CalibratedStore::new(&db);
        assert!(matches!(
            reader.page(TARGET),
            Err(RowHeaderError::Ambiguous { .. })
        ));
        assert!(matches!(
            reader.resolve_forwarded_row(SOURCE, 0),
            Err(ForwardedRowError::Header { .. })
        ));
        let encoded: Vec<_> = [32u32, 1, 1 << SOURCE]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let map = crate::TablePageBitmap::decode(&encoded, db.page_count(), 1).unwrap();
        let pair = map
            .resolve_forwarded_row(&reader, OWNER, SOURCE, 0)
            .unwrap();
        assert_eq!(pair.target.bytes, terminal);
        assert_eq!((pair.target.page, pair.target.slot), (TARGET, 1));
        assert!(matches!(
            map.resolve_forwarded_row(&reader, OWNER, TARGET, 1),
            Err(ForwardedRowError::SourceMap(
                crate::PageBitmapError::NotMember { .. }
            ))
        ));
        for (owner, kind, slot) in [
            (OWNER + 1, 0x11, 1),
            (OWNER, 3, 1),
            (OWNER, 0x11, 0),
            (OWNER, 0x11, 99),
        ] {
            let db = store(
                data_page(SOURCE, OWNER, 3, &pointer(TARGET, slot), false),
                target(owner, kind),
            );
            assert!(
                map.resolve_forwarded_row(&CalibratedStore::new(&db), OWNER, SOURCE, 0)
                    .is_err()
            );
        }
    }

    #[test]
    fn only_exact_flags_and_a_different_in_range_target_page_are_accepted() {
        let terminal = &[3, 0, 0];
        let resolve = |s: &[u8]| {
            let db = from_rows(s, terminal);
            CalibratedStore::new(&db)
                .resolve_forwarded_row(SOURCE, 0)
                .unwrap_err()
        };
        let same = |slot| {
            let db = store(
                body_pointer_page(SOURCE, 3, &pointer(SOURCE, slot)),
                data_page(TARGET, OWNER, 0x11, terminal, false),
            );
            CalibratedStore::new(&db)
                .resolve_forwarded_row(SOURCE, 0)
                .unwrap_err()
        };
        assert!(matches!(same(0), ForwardedRowError::Cycle));
        assert!(matches!(same(1), ForwardedRowError::SamePage(SOURCE)));
        for page in [0, 99] {
            assert!(matches!(
                resolve(&pointer(page, 1)),
                ForwardedRowError::TargetRange { .. }
            ));
        }
        assert!(matches!(
            resolve(&pointer(TARGET, 0)),
            ForwardedRowError::Vacant {
                page: TARGET,
                slot: 0
            }
        ));
        assert!(matches!(
            resolve(&pointer(TARGET, 4)),
            ForwardedRowError::SlotRange {
                page: TARGET,
                slot: 4
            }
        ));
        let mut s = pointer(TARGET, 1);
        s[2] |= 1;
        assert!(matches!(resolve(&s), ForwardedRowError::SourceForm));
        s[0] = 10;
        s[2] = 4;
        s.push(0);
        assert!(matches!(resolve(&s), ForwardedRowError::SourceForm));
        s[0] = 9;
        assert!(matches!(
            resolve(&s),
            ForwardedRowError::Length(RowLengthMismatch {
                expected: 10,
                stored: Some(9),
                ..
            })
        ));
    }

    #[test]
    fn rejects_competing_headers_wrong_owner_kind_and_unchecked_target_length() {
        let stub = pointer(TARGET, 1);
        let terminal = [4, 0, 0, 0xff];
        let ordinary = data_page(SOURCE, OWNER, 3, &stub, false);
        let error = |source, target| {
            let db = store(source, target);
            CalibratedStore::new(&db)
                .resolve_forwarded_row(SOURCE, 0)
                .unwrap_err()
        };
        assert!(matches!(
            error(ordinary, data_page(TARGET, 78, 0x12, &terminal, false)),
            ForwardedRowError::Owner {
                expected: OWNER,
                actual: 78
            }
        ));
        assert!(matches!(
            error(ordinary, data_page(TARGET, OWNER, 3, &terminal, false)),
            ForwardedRowError::TargetKind(3)
        ));
        assert!(matches!(
            error(ordinary, data_page(TARGET, OWNER, 0x12, &terminal, true)),
            ForwardedRowError::Header {
                page: TARGET,
                source: RowHeaderError::Ambiguous { .. }
            }
        ));
        let target = data_page(TARGET, OWNER, 0x12, &terminal, false);
        assert!(matches!(
            error(data_page(SOURCE, OWNER, 0x12, &stub, false), target),
            ForwardedRowError::SourceKind(0x12)
        ));
        assert!(matches!(
            error(data_page(SOURCE, OWNER, 3, &stub, true), target),
            ForwardedRowError::Header {
                page: SOURCE,
                source: RowHeaderError::Ambiguous { .. }
            }
        ));
        assert!(matches!(
            error(
                ordinary,
                data_page(TARGET, OWNER, 0x12, &[6, 0, 0, 0xff], false)
            ),
            ForwardedRowError::Length(RowLengthMismatch { page: TARGET, .. })
        ));
        let mut corrupted = target;
        corrupted[2800] ^= 1;
        assert!(matches!(
            error(ordinary, corrupted),
            ForwardedRowError::Header {
                page: TARGET,
                source: RowHeaderError::Integrity(_)
            }
        ));
    }

    #[test]
    fn never_follows_a_second_reference_or_interprets_continuations() {
        let stub = pointer(TARGET, 1);
        let error = |t: &[u8]| {
            let db = store(
                data_page(SOURCE, OWNER, 3, &stub, false),
                body_pointer_page(TARGET, 0x11, t),
            );
            CalibratedStore::new(&db)
                .resolve_forwarded_row(SOURCE, 0)
                .unwrap_err()
        };
        assert!(matches!(
            error(&pointer(SOURCE, 0)),
            ForwardedRowError::Cycle
        ));
        assert!(matches!(
            error(&pointer(TARGET, 1)),
            ForwardedRowError::Cycle
        ));
        assert!(matches!(
            error(&pointer(9999, 0)),
            ForwardedRowError::Nonterminal
        ));
        assert!(matches!(error(&[3, 0, 4]), ForwardedRowError::Nonterminal));
        assert!(matches!(
            error(&[3, 0, 0x40]),
            ForwardedRowError::TargetFlags(0x40)
        ));
        assert!(matches!(error(&[2, 0]), ForwardedRowError::TruncatedTarget));
    }
}
