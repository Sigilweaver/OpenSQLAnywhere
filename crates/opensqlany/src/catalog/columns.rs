//! Membership of physical ISYSTABCOL pages. Only the exact positive ISYSTAB
//! descriptor can name the members. A repeated page-number anchor on an
//! otherwise unique member header additionally needs independently recognized
//! column definitions under the fixed ordinary catalog bootstrap.

use crate::{
    CalibratedPage, CalibratedStore, CatalogRecoveryContext, PageBitmapError, PhysicalValue,
    RecordLayout, RowHeaderError, RowPageHeader, TableMapRead, TablePageBitmap, TablePageCounts,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Physical occupied source slots on catalog owner 2's verified data pages.
#[derive(Debug, Default)]
pub struct ColumnCatalogSlots {
    /// Zero-based slots positively present in complete directories or their
    /// recovered prefixes. See the map's `occupied_slots` total for completeness.
    pub occupied: BTreeSet<(u32, u16)>,
    /// Pages with a unique repeated-anchor header additionally corroborated by
    /// two distinct fully decoded column identities from the fixed catalog context.
    pub repeated_pages: Vec<u32>,
}

/// A column catalog's actual page-list bitmap and corresponding slot membership.
#[derive(Debug)]
pub struct ColumnCatalogMap {
    /// Read of the owner-2 bitmap and verified member counts.
    pub read: TableMapRead,
    /// Physical source slots; presence does not establish version or liveness.
    pub slots: ColumnCatalogSlots,
    /// Read access to this verified map's members on the original calibrated store.
    pub members: ColumnCatalogMembers,
}

/// Evidence for reopening the physical pages named by one verified ISYSTABCOL
/// map. Repeated headers come from the same ordinary catalog bootstrap that
/// corroborated membership; callers cannot add pages or substitute a header.
pub struct ColumnCatalogMembers {
    store: Arc<()>,
    bitmap: TablePageBitmap,
    repeated: BTreeMap<u32, RowPageHeader>,
}

impl std::fmt::Debug for ColumnCatalogMembers {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("ColumnCatalogMembers")
            .field("mapped_pages", &self.bitmap.len())
            .field("repeated_pages", &self.repeated.len())
            .finish_non_exhaustive()
    }
}

impl ColumnCatalogMembers {
    /// Open a named owner-2 data page on the original calibrated store. Ordinary
    /// header checks take precedence. Only an ambiguous result may use the sole
    /// structural header already corroborated by two distinct catalog identities.
    /// Reading individual slots still requires the normal length and sector checks.
    pub fn page<'r, 's>(
        &self,
        store: &'r CalibratedStore<'s>,
        page: u32,
    ) -> Result<CalibratedPage<'r, 's>, PageBitmapError> {
        if !Arc::ptr_eq(&self.store, &store.identity) {
            return Err(PageBitmapError::DifferentMemberStore);
        }
        if !self.bitmap.contains(page) {
            return Err(PageBitmapError::NotColumnCatalogMember { page });
        }
        match store.page(page) {
            Ok(reader) => Ok(reader),
            Err(source @ RowHeaderError::Ambiguous { .. }) => {
                let header = self
                    .repeated
                    .get(&page)
                    .filter(|h| h.directory_prefix_matches() == Some(true))
                    .ok_or(PageBitmapError::Header { page, source })?;
                let stored = store.store().page(u64::from(page))?;
                Ok(store.page_with_header(stored, header.clone()))
            }
            Err(source) => Err(PageBitmapError::Header { page, source }),
        }
    }
}

fn member_slots(
    store: &CalibratedStore<'_>,
    bitmap: &TablePageBitmap,
    repeated: Option<(&CatalogRecoveryContext, &[Option<RecordLayout>; 2])>,
) -> Result<(TablePageCounts, ColumnCatalogSlots, ColumnCatalogMembers), PageBitmapError> {
    let mut counts = TablePageCounts {
        live_slots: 0,
        occupied_slots: Some(0),
    };
    let mut slots = ColumnCatalogSlots::default();
    let mut repeated_headers = BTreeMap::new();
    for page in bitmap.pages() {
        let stored = store.store().page(u64::from(page))?;
        let header = match RowPageHeader::recover(stored) {
            Ok(header) => header,
            Err(RowHeaderError::Ambiguous { .. }) => {
                let prior = || PageBitmapError::Header {
                    page,
                    source: RowHeaderError::Ambiguous {
                        page: u64::from(page),
                    },
                };
                let (context, layouts) = repeated.ok_or_else(prior)?;
                let (header, _) = context
                    .repeated_page_with_header(stored, layouts)
                    .map_err(|source| PageBitmapError::Header { page, source })?
                    .filter(|(h, _)| h.owner_id() == 2 && (1..=4).contains(&h.page_kind()))
                    .ok_or_else(prior)?;
                slots.repeated_pages.push(page);
                repeated_headers.insert(page, header.clone());
                header
            }
            Err(source) => return Err(PageBitmapError::Header { page, source }),
        };
        if header.owner_id() != 2 {
            return Err(PageBitmapError::Owner {
                page,
                expected: 2,
                actual: header.owner_id(),
            });
        }
        if header.page_kind() > 4 {
            return Err(PageBitmapError::NotTableRow {
                page,
                kind: header.page_kind(),
            });
        }
        counts.live_slots += u64::from(header.live_count());
        let complete = header.complete_slot_starts();
        counts.occupied_slots = counts
            .occupied_slots
            .zip(complete)
            .map(|(sum, dir)| sum + dir.iter().flatten().count() as u64);
        let visible = complete.unwrap_or_else(|| header.sector0_slot_starts());
        for (i, start) in visible.iter().enumerate() {
            if start.is_some() {
                slots.occupied.insert((page, i as u16));
            }
        }
        if repeated.is_some()
            && header.page_kind() == 0
            && (header.live_count() != 0 || visible.iter().any(Option::is_some))
        {
            return Err(PageBitmapError::NotTableRow { page, kind: 0 });
        }
    }
    let members = ColumnCatalogMembers {
        store: Arc::clone(&store.identity),
        bitmap: bitmap.clone(),
        repeated: repeated_headers,
    };
    Ok((counts, slots, members))
}

impl CatalogRecoveryContext {
    /// Read the actual `tab_page_list` of ISYSTABCOL (owner 2). Callers must
    /// have verified the referring ISYSTAB record's identity and catalog fields.
    /// The ordinary table-map path takes precedence. Only an ambiguous member
    /// header or a failed sparse bitmap search can trigger the positive-map
    /// fallback. It requires exact, length-checked terminal bytes from the
    /// separate owner-1 chunk, complete membership and directories, and at least
    /// one uniquely keyed repeated member with independent catalog-field proof.
    /// No other owner's map, missing descriptor or empty-map surrogate is used.
    pub fn column_catalog_map(
        &self,
        store: &CalibratedStore<'_>,
        value: &PhysicalValue<'_>,
        declared_pages: u32,
        ordinary_layouts: &[Option<RecordLayout>; 2],
    ) -> Result<ColumnCatalogMap, PageBitmapError> {
        let PhysicalValue::OutOfRow(d) = value else {
            return Err(PageBitmapError::UnsupportedField);
        };
        if d.domain != 31 || declared_pages == 0 {
            return Err(PageBitmapError::UnsupportedField);
        }
        let prior = match store.table_page_map(value, declared_pages, 2) {
            Ok(read) => {
                let (_, slots, members) = match member_slots(store, &read.bitmap, None) {
                    Ok(value) => value,
                    Err(PageBitmapError::Header {
                        source: RowHeaderError::Ambiguous { .. },
                        ..
                    }) => {
                        // Generic member identity can now corroborate a unique
                        // repeated header. The column catalog still needs its
                        // stronger, fixed first-pass column-identity checks.
                        member_slots(store, &read.bitmap, Some((self, ordinary_layouts)))?
                    }
                    Err(error) => return Err(error),
                };
                return Ok(ColumnCatalogMap {
                    read,
                    slots,
                    members,
                });
            }
            Err(
                prior @ (PageBitmapError::Header {
                    source: RowHeaderError::Ambiguous { .. },
                    ..
                }
                | PageBitmapError::NoSparseMap),
            ) => prior,
            Err(other) => return Err(other),
        };
        let (bitmap, calibrated_sector_uses, empty_allocation) =
            TablePageBitmap::read_terminal_map(
                d,
                store.store().page_count(),
                declared_pages,
                |frame| store.resolve_byte_counted_chunk(1, frame),
            )?;
        let (counts, slots, members) =
            member_slots(store, &bitmap, Some((self, ordinary_layouts)))?;
        if counts.occupied_slots.is_none()
            || slots.repeated_pages.is_empty()
            || matches!(&prior,PageBitmapError::Header{page,..} if !slots.repeated_pages.contains(page))
        {
            return Err(prior);
        }
        Ok(ColumnCatalogMap {
            read: TableMapRead {
                empty_allocation,
                linked_map: None,
                bitmap,
                counts,
                calibrated_sector_uses,
                repeated_map_header: false,
                literal_witnesses: Vec::new(),
                conflict_witnesses: Vec::new(),
            },
            slots,
            members,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::recovery::tests::{sample_column, stored_catalog_page};
    use crate::{LongDescriptor, PAGE_SIZE, PageStore};

    fn descriptor() -> PhysicalValue<'static> {
        PhysicalValue::OutOfRow(LongDescriptor {
            domain: 31,
            tag: 0,
            prefix: &[64, 0],
            total_len: 12,
            first_page: 61,
            unknown: 0,
            slot: 0,
        })
    }
    fn fixture(
        rows: &[Vec<u8>],
        competing: bool,
        other_owner: u32,
        other_kind: u8,
        flags: u8,
    ) -> PageStore {
        let payload = [64u32, 129, (1u32 << 30) | (1u32 << 31)]
            .into_iter()
            .flat_map(u32::to_le_bytes);
        let mut terminal = vec![15, 0, flags];
        terminal.extend(payload);
        let mut bytes = vec![0; 64 * PAGE_SIZE];
        for (pn, mut page) in [
            (
                61,
                stored_catalog_page(61, 1, 0x11, &[terminal], false, false),
            ),
            (62, stored_catalog_page(62, 2, 3, rows, true, competing)),
            (
                63,
                stored_catalog_page(63, other_owner, other_kind, rows, false, false),
            ),
        ] {
            // In this fixture the vacant slot follows the named rows, with
            // one additional occupied span beyond the vacant slot.
            let prefix = if pn == 61 { 1 } else { rows.len() as u16 };
            page[4080..4082].copy_from_slice(&prefix.to_le_bytes());
            let crc = crc32fast::hash(&page[..4092]);
            page[4092..].copy_from_slice(&crc.to_le_bytes());
            bytes[pn * PAGE_SIZE..(pn + 1) * PAGE_SIZE].copy_from_slice(&page);
        }
        PageStore::from_bytes_unchecked(bytes).unwrap()
    }

    #[test]
    fn mapped_owner_evidence_extends_only_an_independent_selected_context() {
        let (original, layout, first) = sample_column();
        let mut second = first.clone();
        second[8..12].copy_from_slice(&14u32.to_le_bytes());
        let mut novel = first.clone();
        novel[4..8].copy_from_slice(&9999u32.to_le_bytes());
        let db = fixture(
            &[first.clone(), second.clone(), novel.clone()],
            false,
            2,
            3,
            0,
        );
        let store = CalibratedStore::new(&db);
        let layouts = [None, Some(layout.clone())];
        let selected = original
            .column_catalog_map(&store, &descriptor(), 2, &layouts)
            .unwrap();
        let (mut later, _, _) = sample_column();
        for (page, slot) in [(61, 0), (62, 4)] {
            assert!(
                later
                    .observe_mapped_column_owner(&store, &selected.members, page, slot, &layout)
                    .is_none()
            );
        }
        assert!(
            later
                .observe_mapped_column_owner(
                    &CalibratedStore::new(&db),
                    &selected.members,
                    62,
                    2,
                    &layout,
                )
                .is_none()
        );
        let mut wrong_columns = layout.columns().to_vec();
        wrong_columns[0].domain_id = 2;
        assert!(
            later
                .observe_mapped_column_owner(
                    &store,
                    &selected.members,
                    62,
                    2,
                    &RecordLayout::new(wrong_columns).unwrap(),
                )
                .is_none()
        );
        let source = db.page(62).unwrap();
        assert_eq!(
            later
                .recover_repeated_page(source, &layouts)
                .unwrap()
                .unwrap()
                .rows
                .len(),
            2
        );
        assert_eq!(
            later.observe_mapped_column_owner(&store, &selected.members, 62, 2, &layout),
            Some(9999)
        );
        let recovered = later
            .recover_repeated_page(source, &layouts)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.rows.len(), 3);
        assert_eq!(recovered.rows[2], (2, novel.clone()));
        assert_eq!(
            original
                .recover_repeated_page(source, &layouts)
                .unwrap()
                .unwrap()
                .rows
                .len(),
            2
        );

        // A selected member still cannot contribute an unsupported/deleted body.
        novel[2] = 1;
        let db = fixture(&[first, second, novel], false, 2, 3, 0);
        let store = CalibratedStore::new(&db);
        let selected = original
            .column_catalog_map(&store, &descriptor(), 2, &layouts)
            .unwrap();
        let (mut later, _, _) = sample_column();
        assert!(
            later
                .observe_mapped_column_owner(&store, &selected.members, 62, 2, &layout)
                .is_none()
        );
    }

    #[test]
    fn additional_definitions_need_the_selected_member_and_exact_fixed_catalog_layout() {
        let (ctx, layout, first) = sample_column();
        let mut second = first.clone();
        second[8..12].copy_from_slice(&14u32.to_le_bytes());
        let mut novel = first.clone();
        novel[4..8].copy_from_slice(&9999u32.to_le_bytes());
        let db = fixture(
            &[first.clone(), second.clone(), novel.clone()],
            false,
            2,
            3,
            0,
        );
        let cal = CalibratedStore::new(&db);
        let selected = ctx
            .column_catalog_map(&cal, &descriptor(), 2, &[None, Some(layout.clone())])
            .unwrap();
        assert_eq!(
            ctx.corroborated_mapped_column_slot(&cal, &selected.members, 62, 2, &layout),
            Some(novel)
        );
        assert!(
            ctx.corroborated_mapped_column_slot(&cal, &selected.members, 61, 0, &layout)
                .is_none()
        );
        assert!(
            ctx.corroborated_mapped_column_slot(
                &CalibratedStore::new(&db),
                &selected.members,
                62,
                2,
                &layout
            )
            .is_none()
        );
        assert!(
            ctx.corroborated_mapped_column_slot(&cal, &selected.members, 62, 4, &layout)
                .is_none()
        );
        let mut wrong_columns = layout.columns().to_vec();
        wrong_columns[0].domain_id = 2;
        let wrong = RecordLayout::new(wrong_columns).unwrap();
        assert!(
            ctx.corroborated_mapped_column_slot(&cal, &selected.members, 62, 2, &wrong)
                .is_none()
        );
        // The novel row cannot select a repeated header on its own. Removing
        // the two independent known identities leaves the map unverified.
        let mut other_novel = first;
        other_novel[4..8].copy_from_slice(&9998u32.to_le_bytes());
        second[4..8].copy_from_slice(&9997u32.to_le_bytes());
        let db = fixture(&[other_novel, second], false, 2, 3, 0);
        assert!(
            ctx.column_catalog_map(
                &CalibratedStore::new(&db),
                &descriptor(),
                2,
                &[None, Some(layout)]
            )
            .is_err()
        );
    }

    #[test]
    fn repeated_reader_is_limited_to_the_verified_members_of_its_store() {
        let (ctx, layout, row) = sample_column();
        let mut second = row.clone();
        second[8..12].copy_from_slice(&14u32.to_le_bytes());
        let rows = [row, second];
        let db = fixture(&rows, false, 2, 3, 0);
        let store = CalibratedStore::new(&db);
        let mut result = ctx
            .column_catalog_map(&store, &descriptor(), 2, &[None, Some(layout)])
            .unwrap();

        assert!(matches!(
            store.page(62),
            Err(RowHeaderError::Ambiguous { .. })
        ));
        let recovered = result.members.page(&store, 62).unwrap();
        assert_eq!(recovered.header().owner_id(), 2);
        for (slot, expected) in rows.iter().enumerate() {
            assert!(matches!(
                recovered.read_slot(slot as u16),
                Some(crate::RowSlotRecovery::Candidate { bytes, .. }) if bytes == *expected
            ));
        }
        // Confirming a member's header never confirms its remaining record bytes.
        assert!(matches!(
            recovered.read_slot(3),
            Some(
                crate::RowSlotRecovery::Unavailable { .. }
                    | crate::RowSlotRecovery::LengthMismatch { .. }
            )
        ));
        assert!(matches!(
            result.members.page(&store, 61),
            Err(PageBitmapError::NotColumnCatalogMember { page: 61 })
        ));
        let equivalent = fixture(&rows, false, 2, 3, 0);
        for other in [CalibratedStore::new(&db), CalibratedStore::new(&equivalent)] {
            assert!(matches!(
                result.members.page(&other, 62),
                Err(PageBitmapError::DifferentMemberStore)
            ));
        }
        // Removing the private proof makes the ordinary ambiguity visible.
        // Adding it at a different location cannot override an ordinary header.
        let header = result.members.repeated.remove(&62).unwrap();
        result.members.repeated.insert(63, header);
        assert!(matches!(
            result.members.page(&store, 62),
            Err(PageBitmapError::Header {
                page: 62,
                source: RowHeaderError::Ambiguous { .. }
            })
        ));
        assert_eq!(
            result
                .members
                .page(&store, 63)
                .unwrap()
                .header()
                .page_number(),
            63
        );
    }
    #[test]
    fn only_an_exact_map_with_independent_repeated_member_proof_can_pass() {
        let (ctx, layout, row) = sample_column();
        let mut other = row.clone();
        other[8..12].copy_from_slice(&14u32.to_le_bytes());
        let rows = [row.clone(), other];
        let layouts = [None, Some(layout)];
        let db = fixture(&rows, false, 2, 3, 0);
        let cal = CalibratedStore::new(&db);
        // Generic membership can corroborate this sole header. Reopening the
        // column catalog must still retain its independent two-identity proof.
        let generic = cal.table_page_map(&descriptor(), 2, 2).unwrap();
        assert!(
            !generic
                .bitmap
                .page(&cal, 2, 62)
                .unwrap()
                .header()
                .mapped_number_offsets()
                .is_empty()
        );
        let result = ctx
            .column_catalog_map(&cal, &descriptor(), 2, &layouts)
            .unwrap();
        assert_eq!(result.slots.repeated_pages, vec![62]);
        assert_eq!(
            result.read.counts,
            TablePageCounts {
                live_slots: 4,
                occupied_slots: Some(6)
            }
        );
        assert_eq!(
            result.slots.occupied,
            BTreeSet::from([(62, 0), (62, 1), (62, 3), (63, 0), (63, 1), (63, 3)])
        );
        assert_eq!(result.read.bitmap.pages().collect::<Vec<_>>(), vec![62, 63]);
        assert!(!result.read.repeated_map_header);
        assert!(
            ctx.column_catalog_map(&cal, &PhysicalValue::Null, 2, &layouts)
                .is_err()
        );
        assert!(
            ctx.column_catalog_map(&cal, &descriptor(), 1, &layouts)
                .is_err()
        );
        assert!(
            CatalogRecoveryContext::default()
                .column_catalog_map(&cal, &descriptor(), 2, &layouts)
                .is_err()
        );
        for db in [
            fixture(&[row], false, 2, 3, 0),
            fixture(&rows, true, 2, 3, 0),
            fixture(&rows, false, 9, 3, 0),
            fixture(&rows, false, 2, 0x11, 0),
            fixture(&rows, false, 2, 3, 4),
        ] {
            assert!(
                ctx.column_catalog_map(&CalibratedStore::new(&db), &descriptor(), 2, &layouts)
                    .is_err()
            );
        }
    }
}
