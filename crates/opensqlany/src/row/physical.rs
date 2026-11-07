//! Physical row spans from a complete, recovered slot directory.
//!
//! Slot occupancy establishes an allocation boundary, not row visibility.
//! A stored length must still agree with that boundary before bytes are used.

use crate::{RowPageHeader, SECTOR_SIZE};

// The last twelve logical row bytes precede the CRC but reside in the header stash.
const ROW_AREA_END: usize = 4092;

/// The extent of an occupied slot in a QBW row page, in logical byte order.
/// Checkpoint copies and inactive rows can both have occupied slots.
#[derive(Debug, Clone, Copy)]
pub struct PhysicalRow<'a> {
    header: &'a RowPageHeader,
    slot: u16,
    start: usize,
    end: usize,
}

impl PhysicalRow<'_> {
    /// Zero-based slot number in the physical directory.
    pub fn slot(&self) -> u16 {
        self.slot
    }

    /// Inclusive logical page offset.
    pub fn start(&self) -> usize {
        self.start
    }

    /// Exclusive logical page offset.
    pub fn end(&self) -> usize {
        self.end
    }

    /// Length inferred from the next occupied slot or the end of the row area.
    pub fn length(&self) -> usize {
        self.end - self.start
    }

    /// Read a whole record contained in the recovered first sector. A record
    /// crossing into another sector returns `Ok(None)`. A conflicting stored
    /// length returns an error, so callers can account for rejected records.
    pub fn sector0_bytes(&self) -> Result<Option<&[u8]>, RowLengthMismatch> {
        if self.end > SECTOR_SIZE {
            return Ok(None);
        }
        let bytes = &self.header.sector0()[self.start..self.end];
        let stored = bytes
            .first_chunk::<2>()
            .map(|word| u16::from_le_bytes(*word));
        if stored.map(usize::from) != Some(bytes.len()) {
            return Err(RowLengthMismatch {
                page: self.header.page_number(),
                slot: self.slot,
                expected: bytes.len(),
                stored,
            });
        }
        Ok(Some(bytes))
    }
}

/// An occupied slot's stored length disagrees with the directory span.
#[derive(Debug, thiserror::Error)]
#[error("page {page}, slot {slot}: expected row length {expected}, stored {stored:?}")]
pub struct RowLengthMismatch {
    /// Physical page index.
    pub page: u32,
    /// Slot number in the original directory.
    pub slot: u16,
    /// Gap to the next row start.
    pub expected: usize,
    /// Length word, if both bytes fit in the slot.
    pub stored: Option<u16>,
}

impl RowPageHeader {
    /// Return all occupied slots in logical offset order. If the directory
    /// has unresolved slots, its boundaries may change and this returns
    /// `None`. Spans alone establish neither a record's
    /// stored length nor its membership in the current logical table.
    pub fn physical_rows(&self) -> Option<Vec<PhysicalRow<'_>>> {
        let mut starts: Vec<_> = self
            .complete_slot_starts()?
            .iter()
            .enumerate()
            .filter_map(|(slot, &start)| start.map(|offset| (usize::from(offset), slot as u16)))
            .collect();
        starts.sort_unstable();
        let rows = starts
            .iter()
            .enumerate()
            .map(|(i, &(start, slot))| PhysicalRow {
                header: self,
                slot,
                start,
                end: starts
                    .get(i + 1)
                    .map_or(ROW_AREA_END, |&(offset, _)| offset),
            });
        Some(rows.collect())
    }
}
