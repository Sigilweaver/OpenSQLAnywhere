//! Use an independently verified, positive ISYSTAB page map as a witness
//! for another catalog chunk on the same physical page. The witness is
//! admitted only after membership and ownership of every named data page have
//! been checked and the chunk page has exactly one structural key.

use std::collections::{BTreeMap, BTreeSet};

use crate::record::long_value::{check_reference, read_chunk};
use crate::row::forwarded::{forward_source, forward_target};
use crate::{
    CalibratedPage, CalibratedStore, ForwardedRow, ForwardedRowError, PageBitmapError,
    PhysicalValue, RowHeaderError, RowPageHeader, TableMapRead, TablePageBitmap,
};

/// Location of an independently checked positive bitmap on the same chunk page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogChunkWitness {
    /// Physical chunk page of the verified positive map.
    pub page: u32,
    /// Zero-based physical chunk slot of that map.
    pub slot: u16,
}

/// A checked catalog result and the separate physical slot that confirmed its header.
#[derive(Debug)]
pub struct Witnessed<T> {
    /// Independently verified physical result.
    pub value: T,
    /// Positive map used for this other slot on its page.
    pub witness: CatalogChunkWitness,
}

/// Witnesses from first-pass physical catalog map fields, bound to one
/// immutable calibrated store. The registry retains only verified addresses.
pub struct CatalogChunkWitnesses<'reader, 'store> {
    store: &'reader CalibratedStore<'store>,
    slots: BTreeMap<u32, BTreeSet<u16>>,
}

impl<'reader, 'store> CatalogChunkWitnesses<'reader, 'store> {
    /// Start an empty registry for this calibration.
    pub fn new(store: &'reader CalibratedStore<'store>) -> Self {
        Self {
            store,
            slots: BTreeMap::new(),
        }
    }

    /// Verify an actual positive domain-31 table map from the caller's
    /// independently recovered catalog. Return true when it used the sole
    /// repeated header and its slot is now eligible to witness a distinct slot.
    /// An ordinary verified map returns false. A rejected map adds no witness.
    pub fn observe_positive_map(
        &mut self,
        value: &PhysicalValue<'_>,
        declared_pages: u32,
        table_owner: u32,
    ) -> Result<bool, PageBitmapError> {
        let PhysicalValue::OutOfRow(descriptor) = value else {
            return Err(PageBitmapError::UnsupportedField);
        };
        if declared_pages == 0 || descriptor.domain != 31 {
            return Err(PageBitmapError::UnsupportedField);
        }
        let map = self
            .store
            .table_page_map(value, declared_pages, table_owner)?;
        if map.repeated_map_header {
            self.slots
                .entry(descriptor.first_page)
                .or_default()
                .insert(descriptor.slot);
        }
        Ok(map.repeated_map_header)
    }

    /// Resolve a physical catalog table forward whose ordinarily ambiguous
    /// target has a separate verified positive bitmap on the same page.
    /// The returned terminal record still needs a catalog layout and identity
    /// check before using it as a table definition. No second hop is followed.
    pub fn resolve_forwarded_row(
        &self,
        source: &CalibratedPage<'_, 'store>,
        source_slot: u16,
    ) -> Result<Witnessed<ForwardedRow<'store>>, CatalogChunkWitnessError> {
        if !source.belongs_to(self.store) {
            return Err(CatalogChunkWitnessError::DifferentStore);
        }
        if source.header().owner_id() != 1 {
            return Err(CatalogChunkWitnessError::SourceOwner(
                source.header().owner_id(),
            ));
        }
        let (source, target_page, target_slot) = forward_source(self.store, source, source_slot)?;
        let (target, witness) = self.witnessed_page(target_page, target_slot)?;
        let value = forward_target(source, 1, &target, target_slot)?;
        Ok(Witnessed { value, witness })
    }

    /// Resolve only an out-of-row empty domain-31 catalog map using its own
    /// exact terminal slot or the corroborated four-byte/six-zero empty form.
    /// A different positive map supplies the repeated-header evidence.
    pub fn empty_table_map(
        &self,
        value: &PhysicalValue<'_>,
        declared_pages: u32,
        table_owner: u32,
    ) -> Result<Witnessed<TableMapRead>, CatalogChunkWitnessError> {
        let PhysicalValue::OutOfRow(descriptor) = value else {
            return Err(CatalogChunkWitnessError::NotEmptyMap);
        };
        if declared_pages != 0 || descriptor.domain != 31 {
            return Err(CatalogChunkWitnessError::NotEmptyMap);
        }
        check_reference(self.store.store(), descriptor).map_err(PageBitmapError::Chunk)?;
        let (target, witness) = self.witnessed_page(descriptor.first_page, descriptor.slot)?;
        let (bitmap, calibrated_sector_uses, empty_allocation) =
            TablePageBitmap::read_terminal_map(
                descriptor,
                self.store.store().page_count(),
                0,
                |frame| read_chunk(1, frame, target.header(), |slot| target.read_slot(slot)),
            )?;
        let value = TableMapRead {
            empty_allocation,
            linked_map: None,
            counts: bitmap.verify_owner(self.store.store(), table_owner)?,
            bitmap,
            calibrated_sector_uses,
            repeated_map_header: true,
            literal_witnesses: Vec::new(),
            conflict_witnesses: Vec::new(),
        };
        Ok(Witnessed { value, witness })
    }

    fn witnessed_page(
        &self,
        page: u32,
        slot: u16,
    ) -> Result<(CalibratedPage<'_, 'store>, CatalogChunkWitness), CatalogChunkWitnessError> {
        let witness_slot = self
            .slots
            .get(&page)
            .and_then(|slots| slots.iter().copied().find(|&w| w != slot))
            .ok_or(CatalogChunkWitnessError::NoDistinctWitness { page, slot })?;
        let raw = self
            .store
            .store()
            .page(u64::from(page))
            .map_err(RowHeaderError::Integrity)?;
        // Each registered witness already underwent the ordinary ambiguous
        // header rejection. Recheck the immutable page's unique repeated
        // structural key; reject every competing key even if its slot is unusable.
        let header = RowPageHeader::sole_repeated_candidate(raw)?
            .ok_or(CatalogChunkWitnessError::UnverifiedHeader(page))?;
        let reader = self.store.page_with_header(raw, header);
        Ok((
            reader,
            CatalogChunkWitness {
                page,
                slot: witness_slot,
            },
        ))
    }
}

/// Why a separately witnessed catalog chunk could not be corroborated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogChunkWitnessError {
    /// The referring page is bound to a different store or calibration.
    #[error("catalog page and witnesses use different calibrated stores")]
    DifferentStore,
    /// The observed forwarded catalog table record requires source owner 1.
    #[error("catalog table-forward source has owner {0}")]
    SourceOwner(u32),
    /// Only zero-page out-of-row domain-31 fields are handled by this fallback.
    #[error("field is not an out-of-row zero-page catalog map")]
    NotEmptyMap,
    /// There is no eligible positive bitmap in a different slot on this page.
    #[error("page {page} slot {slot} lacks a distinct positive catalog map witness")]
    NoDistinctWitness {
        /// Requested physical chunk page.
        page: u32,
        /// Requested zero-based physical slot.
        slot: u16,
    },
    /// This immutable page did not supply exactly one repeating structural key.
    #[error("page {0} lacks a sole repeated header")]
    UnverifiedHeader(u32),
    /// Integrity or structural validation of the witness page failed.
    #[error(transparent)]
    Header(#[from] RowHeaderError),
    /// Source or target framing, ownership or physical slot validation failed.
    #[error(transparent)]
    Forward(#[from] ForwardedRowError),
    /// The requested empty catalog map failed its framing or map checks.
    #[error(transparent)]
    Map(#[from] PageBitmapError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LongDescriptor, LongValueError, PAGE_SIZE, PageStore};

    // Entirely invented physical store. The ordinary source page at 2 points
    // to slot 1 on chunk page 4. Slot 0 there holds the positive map for owner
    // 77, independently corroborated by its named physical page 6.
    fn record(flags: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = ((3 + body.len()) as u16).to_le_bytes().to_vec();
        bytes.push(flags);
        bytes.extend(body);
        bytes
    }

    fn page(
        pn: u32,
        owner: u32,
        kind: u8,
        rows: &[Vec<u8>],
        repeated: bool,
        rival: bool,
    ) -> [u8; PAGE_SIZE] {
        let mut logical = [0x79u8; 512];
        logical[..4].copy_from_slice(&pn.to_le_bytes());
        logical[16] = 4;
        logical[17] = kind;
        logical[24..28].copy_from_slice(&owner.to_le_bytes());
        let slots = if rows.is_empty() { 0 } else { rows.len() + 1 };
        logical[22..24].copy_from_slice(&(slots as u16).to_le_bytes());
        logical[20..22].copy_from_slice(&if slots == 0 { 0u16 } else { 100 }.to_le_bytes());
        let mut at = 128;
        for i in 0..slots {
            let dir = 28 + i * 2;
            logical[dir..dir + 2].copy_from_slice(&((at - 28) as u16).to_le_bytes());
            if let Some(row) = rows.get(i) {
                logical[at..at + row.len()].copy_from_slice(row);
                at += row.len();
            }
        }
        if repeated {
            logical[450..454].copy_from_slice(&pn.to_le_bytes());
        }
        if rival {
            logical.copy_within(..90, 256);
        }
        let mut raw = [0u8; PAGE_SIZE];
        for (logical, value) in logical.iter().copied().enumerate() {
            let i = (logical + 63) % 512;
            raw[i] = value
                .wrapping_add(97)
                .wrapping_add((i as u8).wrapping_mul(11));
        }
        raw[4080] = slots as u8;
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    fn fixture(repeated: bool, rival: bool) -> PageStore {
        let mut raw = vec![0; PAGE_SIZE * 7];
        let positive: Vec<_> = [32u32, 1, 1 << 6]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let target = vec![
            record(0, &positive),
            record(0, &[9, 8, 7]),
            record(0, &[0; 4]),
            record(0, &[0; 6]),
            record(0, &[0, 0, 0, 0, 0, 1]),
            record(4, &[9, 0, 0, 0]),
        ];
        let from = record(4, &[4, 0, 0, 0, 1, 0]);
        let same = record(4, &[4, 0, 0, 0, 0, 0]);
        let elsewhere = record(4, &[5, 0, 0, 0, 1, 0]);
        for (pn, data) in [
            (2, page(2, 1, 3, &[from, same, elsewhere], false, false)),
            (
                3,
                page(3, 78, 3, &[record(4, &[4, 0, 0, 0, 1, 0])], false, false),
            ),
            (4, page(4, 1, 0x12, &target, repeated, rival)),
            (5, page(5, 1, 0x12, &target, true, false)),
            (6, page(6, 77, 3, &[], false, false)),
        ] {
            raw[pn * PAGE_SIZE..(pn + 1) * PAGE_SIZE].copy_from_slice(&data);
        }
        PageStore::from_bytes_unchecked(raw).unwrap()
    }

    fn field(page: u32, slot: u16, total_len: u32, prefix: &[u8]) -> PhysicalValue<'_> {
        PhysicalValue::OutOfRow(LongDescriptor {
            domain: 31,
            tag: 0,
            prefix,
            total_len,
            first_page: page,
            unknown: 0,
            slot,
        })
    }

    #[test]
    fn positive_map_unlocks_only_other_verified_records_on_that_same_chunk_page() {
        let store = fixture(true, false);
        let reader = CalibratedStore::new(&store);
        let mut witnesses = CatalogChunkWitnesses::new(&reader);
        let source = reader.page(2).unwrap();
        assert!(matches!(
            source.resolve_forwarded_row(0),
            Err(ForwardedRowError::Header {
                page: 4,
                source: RowHeaderError::Ambiguous { .. }
            })
        ));
        assert!(matches!(
            witnesses.resolve_forwarded_row(&source, 0),
            Err(CatalogChunkWitnessError::NoDistinctWitness { page: 4, slot: 1 })
        ));
        assert!(
            witnesses
                .observe_positive_map(&field(4, 0, 12, &[32, 0]), 1, 77)
                .unwrap()
        );
        let forwarded = witnesses.resolve_forwarded_row(&source, 0).unwrap();
        assert_eq!(forwarded.witness, CatalogChunkWitness { page: 4, slot: 0 });
        assert_eq!(forwarded.value.source.bytes, record(4, &[4, 0, 0, 0, 1, 0]));
        assert_eq!(forwarded.value.target.bytes, record(0, &[9, 8, 7]));
        assert_eq!(
            (forwarded.value.target.page, forwarded.value.target.slot),
            (4, 1)
        );
        for slot in [2, 3] {
            let empty = witnesses
                .empty_table_map(&field(4, slot, 4, &[]), 0, 96)
                .unwrap();
            assert_eq!(empty.witness, forwarded.witness);
            assert!(empty.value.bitmap.is_empty());
            assert_eq!(empty.value.calibrated_sector_uses, 0);
            assert!(empty.value.repeated_map_header);
        }
        assert!(matches!(
            witnesses.empty_table_map(&field(4, 0, 12, &[]), 0, 77),
            Err(CatalogChunkWitnessError::NoDistinctWitness { page: 4, slot: 0 })
        ));
        assert!(matches!(
            witnesses.resolve_forwarded_row(&source, 1),
            Err(CatalogChunkWitnessError::NoDistinctWitness { page: 4, slot: 0 })
        ));
        assert!(matches!(
            witnesses.resolve_forwarded_row(&source, 2),
            Err(CatalogChunkWitnessError::NoDistinctWitness { page: 5, slot: 1 })
        ));
        assert!(matches!(
            witnesses.empty_table_map(&field(5, 2, 4, &[]), 0, 77),
            Err(CatalogChunkWitnessError::NoDistinctWitness { page: 5, slot: 2 })
        ));
        assert!(matches!(
            witnesses.resolve_forwarded_row(&reader.page(3).unwrap(), 0),
            Err(CatalogChunkWitnessError::SourceOwner(78))
        ));
        let other = fixture(true, false);
        let other_reader = CalibratedStore::new(&other);
        assert!(matches!(
            witnesses.resolve_forwarded_row(&other_reader.page(2).unwrap(), 0),
            Err(CatalogChunkWitnessError::DifferentStore)
        ));
    }

    #[test]
    fn empty_map_retains_surplus_and_keeps_length_prefix_and_terminal_checks() {
        let store = fixture(true, false);
        let reader = CalibratedStore::new(&store);
        let mut witnesses = CatalogChunkWitnesses::new(&reader);
        assert!(
            witnesses
                .observe_positive_map(&field(4, 0, 12, &[]), 1, 77)
                .unwrap()
        );
        let empty = witnesses
            .empty_table_map(&field(4, 4, 4, &[]), 0, 77)
            .unwrap();
        assert!(empty.value.bitmap.is_empty());
        assert_eq!(
            empty.value.empty_allocation,
            Some(crate::EmptyMapAllocation {
                page: 4,
                slot: 4,
                payload: [0, 0, 0, 0, 0, 1],
            })
        );
        assert!(matches!(
            witnesses.empty_table_map(&field(4, 3, 4, &[0]), 0, 77),
            Err(CatalogChunkWitnessError::Map(PageBitmapError::Chunk(
                LongValueError::Length { .. }
            )))
        ));
        assert!(matches!(
            witnesses.empty_table_map(&field(4, 2, 4, &[1]), 0, 77),
            Err(CatalogChunkWitnessError::Map(PageBitmapError::Chunk(
                LongValueError::Prefix
            )))
        ));
        assert!(matches!(
            witnesses.empty_table_map(&field(4, 5, 4, &[]), 0, 77),
            Err(CatalogChunkWitnessError::Map(PageBitmapError::Chunk(
                LongValueError::Continuation
            )))
        ));
        assert!(matches!(
            witnesses.empty_table_map(&field(4, 2, 4, &[]), 1, 77),
            Err(CatalogChunkWitnessError::NotEmptyMap)
        ));
    }

    #[test]
    fn invalid_or_ordinary_maps_and_competing_structural_keys_add_no_witness() {
        let store = fixture(true, false);
        let reader = CalibratedStore::new(&store);
        let mut witnesses = CatalogChunkWitnesses::new(&reader);
        assert!(
            witnesses
                .observe_positive_map(&field(4, 0, 12, &[]), 2, 77)
                .is_err()
        );
        assert!(
            witnesses
                .observe_positive_map(&field(4, 0, 12, &[]), 1, 78)
                .is_err()
        );
        assert!(
            witnesses
                .observe_positive_map(&field(4, 0, 12, &[99]), 1, 77)
                .is_err()
        );
        assert!(
            witnesses
                .observe_positive_map(&field(4, 2, 4, &[]), 0, 77)
                .is_err()
        );
        assert!(matches!(
            witnesses.empty_table_map(&field(4, 3, 4, &[]), 0, 77),
            Err(CatalogChunkWitnessError::NoDistinctWitness { .. })
        ));
        let ordinary = fixture(false, false);
        let reader = CalibratedStore::new(&ordinary);
        let mut witnesses = CatalogChunkWitnesses::new(&reader);
        assert!(
            !witnesses
                .observe_positive_map(&field(4, 0, 12, &[]), 1, 77)
                .unwrap()
        );
        assert!(matches!(
            witnesses.empty_table_map(&field(4, 2, 4, &[]), 0, 77),
            Err(CatalogChunkWitnessError::NoDistinctWitness { .. })
        ));
        let rival = fixture(true, true);
        assert_eq!(
            RowPageHeader::structural_candidates(rival.page(4).unwrap())
                .unwrap()
                .count(),
            2
        );
        let reader = CalibratedStore::new(&rival);
        let mut witnesses = CatalogChunkWitnesses::new(&reader);
        assert!(matches!(
            witnesses.observe_positive_map(&field(4, 0, 12, &[]), 1, 77),
            Err(PageBitmapError::Chunk(LongValueError::Header(
                RowHeaderError::Ambiguous { .. }
            )))
        ));
        assert!(matches!(
            witnesses.empty_table_map(&field(4, 2, 4, &[]), 0, 77),
            Err(CatalogChunkWitnessError::NoDistinctWitness { .. })
        ));
    }
}
