//! Apply store-local, length-anchored chunk recovery only to positive table maps
//! that the ordinary owner-checked path could not reconstruct.

use super::{PageBitmapError, TablePageBitmap, TablePageCounts};
use crate::record::long_value::{check_reference, read_chunk};
use crate::{
    CalibratedStore, LongValueError, PhysicalValue, RowHeaderError, RowPageHeader, RowSlotSector,
};

/// A decoded table map and counts from its corroborated physical pages.
#[derive(Debug)]
pub struct TableMapRead {
    /// Retained nonzero physical surplus beyond a four-byte empty map.
    pub empty_allocation: Option<super::EmptyMapAllocation>,
    /// Stored chain and corroborated logical payload of a high-tag catalog map.
    pub linked_map: Option<super::LinkedMapEvidence>,
    /// Physical map that exactly matches the catalog's page count.
    pub bitmap: TablePageBitmap,
    /// Raw directory prefix counts and complete occupied-slot totals across
    /// the owner-checked pages. Physical row visibility requires separate evidence.
    pub counts: TablePageCounts,
    /// Calibrated chunk-sector reads needed for this map. Zero for an ordinary
    /// map or a map obtained by independent bitmap recovery.
    pub calibrated_sector_uses: usize,
    /// The chunk page had a sole structural header whose physical page number
    /// also occurred elsewhere in its sector. The positive map was verified
    /// through this specific chunk and all its named data pages.
    pub repeated_map_header: bool,
    /// Positive literal members withheld from model selection; one entry for
    /// each length-unanchored sector corroborated by this bitmap-specific path.
    pub literal_witnesses: Vec<super::BitmapSectorWitness>,
    /// Independent wrong-owner data-page evidence for each excluded rival
    /// payload, separate from the literal witnesses.
    pub conflict_witnesses: Vec<super::BitmapConflictWitness>,
}

impl CalibratedStore<'_> {
    /// Read an ISYSTAB table map. The ordinary owner-checked resolver, including
    /// bitmap-specific single-gap recovery, takes precedence. For a positive map
    /// with missing coverage or insufficient length evidence, the store can also
    /// supply a terminal chunk with a matching length word in each modeled sector.
    /// An ambiguous bitmap, malformed bytes, count or ownership conflict cannot
    /// trigger a retry. A separate positive-map case accepts a repeated
    /// page number only when its structural header key is unique and both the
    /// terminal chunk and all physical map members pass their ordinary checks.
    pub fn table_page_map(
        &self,
        value: &PhysicalValue<'_>,
        declared_pages: u32,
        owner_id: u32,
    ) -> Result<TableMapRead, PageBitmapError> {
        let store = self.store();
        let ordinary =
            TablePageBitmap::from_catalog_value_for_owner(store, value, declared_pages, owner_id);
        let (chunk, repeated_map_header) = match (ordinary, value) {
            (Ok(bitmap), _) => {
                let (calibrated_sector_uses, empty_allocation) = match value {
                    PhysicalValue::OutOfRow(descriptor)
                        if declared_pages == 0 && descriptor.domain == 31 =>
                    {
                        let (_, uses, allocation) = TablePageBitmap::read_terminal_map(
                            descriptor,
                            store.page_count(),
                            0,
                            |frame| self.resolve_byte_counted_chunk(1, frame),
                        )?;
                        (uses, allocation)
                    }
                    _ => (0, None),
                };
                return Ok(TableMapRead {
                    empty_allocation,
                    linked_map: None,
                    counts: bitmap.verify_owner(store, owner_id)?,
                    bitmap,
                    calibrated_sector_uses,
                    repeated_map_header: false,
                    literal_witnesses: Vec::new(),
                    conflict_witnesses: Vec::new(),
                });
            }
            (
                Err(prior @ (PageBitmapError::SparseBounds | PageBitmapError::NoBitmapWitness)),
                PhysicalValue::OutOfRow(descriptor),
            ) if declared_pages > 0 && descriptor.domain == 31 => {
                let chunk = match self.resolve_byte_counted_chunk(1, descriptor) {
                    Ok(chunk) => chunk,
                    // Keep the existing independent bitmap diagnostic if this
                    // store cannot supply additional evidence for those bytes.
                    Err(LongValueError::Calibration(crate::CalibrationGap::NoAnchor)) => {
                        return super::regions::recover(
                            self,
                            descriptor,
                            declared_pages,
                            owner_id,
                            prior,
                            None,
                        );
                    }
                    Err(LongValueError::Unavailable | LongValueError::Calibration(_)) => {
                        return Err(prior);
                    }
                    Err(error) => return Err(error.into()),
                };
                (chunk, false)
            }
            (
                Err(
                    prior @ PageBitmapError::Chunk(LongValueError::Header(
                        RowHeaderError::Ambiguous { .. },
                    )),
                ),
                PhysicalValue::OutOfRow(descriptor),
            ) if declared_pages > 0 && descriptor.domain == 31 => {
                check_reference(store, descriptor)?;
                let page = store.page(u64::from(descriptor.first_page))?;
                let Some(header) =
                    RowPageHeader::sole_repeated_candidate(page).map_err(LongValueError::Header)?
                else {
                    return Err(prior);
                };
                let reader = self.page_with_header(page, header);
                let chunk = read_chunk(1, descriptor, reader.header(), |slot| {
                    reader.read_slot(slot)
                })?;
                (chunk, true)
            }
            (Err(error), _) => return Err(error),
        };
        let calibrated_sector_uses = chunk
            .sectors
            .iter()
            .filter(|s| matches!(s, RowSlotSector::Calibrated { .. }))
            .count();
        let bitmap = TablePageBitmap::decode(&chunk.bytes, store.page_count(), declared_pages)?;
        let counts = bitmap.verify_owner(store, owner_id)?;
        Ok(TableMapRead {
            empty_allocation: None,
            linked_map: None,
            bitmap,
            counts,
            calibrated_sector_uses,
            repeated_map_header,
            literal_witnesses: Vec::new(),
            conflict_witnesses: Vec::new(),
        })
    }
}
