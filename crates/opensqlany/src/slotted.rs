//! Slotted-page directory parser.
//!
//! SA17 catalog and data pages use the classic slotted-page layout: a
//! header region at the start of the page, row bodies growing down from
//! near the page end, and a descending array of little-endian u16 row
//! offsets that points at each row body.
//!
//! Observed quirks (see `SPECIFICATION.md §6`):
//!
//! * the slot array may start on either byte alignment,
//! * a leading `0x0000` word may precede the first live offset,
//! * deleted slots appear as interior zero words,
//! * the bytes immediately before the array contain the minimum row
//!   offset and the slot count, but other fields are per-type.

use crate::page::Page;

const TRAILER_START: usize = 0xFF0;
const SEARCH_LIMIT: usize = 0x300;
const SLOT_OFFSET_MIN: u16 = 0x20;
const SLOT_OFFSET_MAX: u16 = TRAILER_START as u16;
const MIN_LIVE_SLOTS: usize = 8;

/// Decoded slot directory.
#[derive(Debug, Clone)]
pub struct SlotDirectory {
    /// Byte offset at which scanning started (may be a sentinel).
    pub scan_start: usize,
    /// Byte offset of the first actual slot entry.
    pub array_start: usize,
    /// Byte offset immediately after the last slot entry.
    pub end: usize,
    /// All u16 slot entries, in array order. Zero entries represent
    /// deleted slots.
    pub slots: Vec<u16>,
    /// `true` iff a `0x0000` sentinel word preceded the array.
    pub leading_zero: bool,
}

impl SlotDirectory {
    /// Live (non-deleted) row offsets.
    pub fn live_slots(&self) -> impl Iterator<Item = u16> + '_ {
        self.slots.iter().copied().filter(|&s| s != 0)
    }

    /// Number of live slots.
    pub fn live_count(&self) -> usize {
        self.slots.iter().filter(|&&s| s != 0).count()
    }

    /// Number of deleted (zero) slots between live entries.
    pub fn deleted_count(&self) -> usize {
        self.slots.len() - self.live_count()
    }

    /// Minimum live row offset, if any.
    pub fn min_offset(&self) -> Option<u16> {
        self.live_slots().min()
    }
}

/// A page that has been parsed for its slotted-directory layout.
#[derive(Debug, Clone)]
pub struct SlottedPage<'a> {
    /// The underlying page.
    pub page: Page<'a>,
    /// The directory, if one was found.
    pub directory: Option<SlotDirectory>,
}

impl<'a> SlottedPage<'a> {
    /// Scan `page` for a plausible descending slot directory. The page
    /// contents must already be plaintext (any QBW-style obfuscation must
    /// be removed by the caller).
    pub fn parse(page: Page<'a>) -> Self {
        let directory = find_slot_directory(page.bytes());
        SlottedPage { page, directory }
    }

    /// Return the raw row bytes for each live slot, in array order.
    ///
    /// Row boundaries are inferred from the (descending) offsets of the
    /// neighbouring slot and the start of the trailer. This is a
    /// best-effort slicing - it does not yet decode any row header.
    pub fn row_bytes(&self) -> Vec<(u16, &'a [u8])> {
        let Some(dir) = &self.directory else {
            return Vec::new();
        };
        let bytes = self.page.bytes();

        // Collect live offsets in ascending order so each row ends at the
        // next-higher live offset (or the trailer start).
        let mut live: Vec<u16> = dir.live_slots().collect();
        live.sort_unstable();

        let mut out = Vec::with_capacity(live.len());
        for (i, &off) in live.iter().enumerate() {
            let start = off as usize;
            let end = live
                .get(i + 1)
                .map(|n| *n as usize)
                .unwrap_or(TRAILER_START);
            if start < end && end <= TRAILER_START {
                out.push((off, &bytes[start..end]));
            }
        }
        out
    }

    /// Return the page-boundary overflow prefix, if present.
    ///
    /// When a QB record spans two SA17 pages the tail fragment is written at
    /// `page[0x000..array_start)` - before the slot directory - on the page
    /// that contains the next records. No slot points to this region, so it is
    /// invisible to [`SlottedPage::row_bytes`].
    ///
    /// Returns `Some(bytes)` when the bytes before the slot directory are
    /// non-zero (i.e. contain row continuation data).  Returns `None` when
    /// there is no slot directory or the prefix region is all zeros (clean
    /// page start).
    pub fn overflow_prefix(&self) -> Option<&'a [u8]> {
        let dir = self.directory.as_ref()?;
        let end = dir.array_start;
        if end == 0 {
            return None;
        }
        let bytes = self.page.bytes();
        let prefix = &bytes[..end];
        if prefix.iter().all(|&b| b == 0) {
            None
        } else {
            Some(prefix)
        }
    }
}

fn u16le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn is_slot_offset(value: u16) -> bool {
    (SLOT_OFFSET_MIN..SLOT_OFFSET_MAX).contains(&value)
}

fn scan_from(plain: &[u8], start: usize) -> Option<SlotDirectory> {
    let mut pos = start;
    let mut leading_zero = false;
    let mut slots: Vec<u16> = Vec::new();
    let mut prev: u32 = 0x10000;

    if pos + 3 < SEARCH_LIMIT && u16le(plain, pos) == 0 && is_slot_offset(u16le(plain, pos + 2)) {
        leading_zero = true;
        pos += 2;
    }

    let array_start = pos;
    let mut seen_live = false;

    while pos + 1 < SEARCH_LIMIT {
        let value = u16le(plain, pos);
        if value == 0 && seen_live {
            slots.push(0);
            pos += 2;
            continue;
        }
        if is_slot_offset(value) && (value as u32) < prev {
            slots.push(value);
            prev = value as u32;
            seen_live = true;
            pos += 2;
            continue;
        }
        break;
    }

    let live_count = slots.iter().filter(|&&s| s != 0).count();
    if live_count < MIN_LIVE_SLOTS {
        return None;
    }

    Some(SlotDirectory {
        scan_start: start,
        array_start,
        end: pos,
        slots,
        leading_zero,
    })
}

fn find_slot_directory(plain: &[u8]) -> Option<SlotDirectory> {
    let mut best: Option<SlotDirectory> = None;
    for start in 0..SEARCH_LIMIT {
        let Some(cand) = scan_from(plain, start) else {
            continue;
        };
        let better = match &best {
            None => true,
            Some(b) => {
                let cand_live = cand.slots.iter().filter(|&&s| s != 0).count();
                let best_live = b.slots.iter().filter(|&&s| s != 0).count();
                cand_live > best_live
                    || (cand_live == best_live && cand.slots.len() > b.slots.len())
            }
        };
        if better {
            best = Some(cand);
        }
    }
    best
}
