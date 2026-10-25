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
//! * the bytes immediately before the array contain the slot count (a u16
//!   four bytes before the array, or six when a zero word precedes it),
//!   but other fields are per-type.
//!
//! A directory is accepted when that declared count equals the plaintext
//! trailer's count byte (`0xFF0`) and exactly that many valid entries
//! follow. Without that confirmation the old scan heuristic still finds
//! candidates, but they are errors unless [`Leniency::DIRECTORY`] is set.

use crate::error::{Error, Result};
use crate::options::{Leniency, ReadOptions};
use crate::page::Page;
use crate::warning::{Warning, WarningKind};

const TRAILER_START: usize = 0xFF0;
const SEARCH_LIMIT: usize = 0x300;
const SLOT_OFFSET_MIN: u16 = 0x20;
const SLOT_OFFSET_MAX: u16 = TRAILER_START as u16;
/// Unconfirmed candidates with at least this many live slots count as a
/// directory (and as an error when they cannot be trusted).
const MIN_LIVE_SLOTS: usize = 8;
/// Unconfirmed candidates with fewer live slots than this are treated as
/// noise: random in-range descending u16 runs of this length are rare.
const MIN_EVIDENCE_SLOTS: usize = 4;
/// Smallest declared count the prelude can confirm. The pair `(1, 0)` or
/// `(2, 0)` is among the commonest words in page data: asking for a directory
/// of count 1 finds one on 63 % of genuine pages with 12 or more rows.
const MIN_CONFIRMED_COUNT: usize = 4;

/// Decoded slot directory.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SlotDirectory {
    array_start: usize,
    end: usize,
    slots: Vec<u16>,
    /// The declared slot count confirmed by the trailer, when there was one.
    declared: Option<usize>,
}

impl SlotDirectory {
    /// Byte offset of the first actual slot entry.
    pub fn array_start(&self) -> usize {
        self.array_start
    }

    /// Byte offset immediately after the last slot entry.
    pub fn end(&self) -> usize {
        self.end
    }

    /// All u16 slot entries, in array order. Zero entries represent
    /// deleted slots.
    pub fn slots(&self) -> &[u16] {
        &self.slots
    }

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

    /// The slot count the page prelude declares, when the prelude confirmed
    /// the directory. `None` means the directory was found by scanning.
    pub fn declared_count(&self) -> Option<usize> {
        self.declared
    }

    /// Live offsets that point into the directory itself, `array_start <= o <
    /// end`. Offsets below `array_start` are legitimate rows: catalog rows can
    /// sit between the page header and the directory.
    fn offsets_inside(&self) -> Vec<u16> {
        self.live_slots()
            .filter(|&o| (self.array_start..self.end).contains(&(o as usize)))
            .collect()
    }

    /// Minimum live row offset, if any.
    pub fn min_offset(&self) -> Option<u16> {
        self.live_slots().min()
    }
}

/// One row slice cut from a slotted page.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Row<'a> {
    offset: u16,
    bytes: &'a [u8],
    exact: bool,
}

impl<'a> Row<'a> {
    /// Page offset at which the row starts.
    pub fn offset(&self) -> u16 {
        self.offset
    }

    /// The row bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// `true` when the slice length was read from the row itself. `false`
    /// when it was inferred from the neighbouring slot offset, in which case
    /// the slice may carry free space or the residue of a deleted row after
    /// the real row.
    pub fn exact(&self) -> bool {
        self.exact
    }
}

/// A page that has been parsed for its slotted-directory layout.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SlottedPage<'a> {
    page: Page<'a>,
    directory: Option<SlotDirectory>,
    warnings: Vec<Warning>,
}

impl<'a> SlottedPage<'a> {
    /// Find the slot directory of `page`. The page contents must already be
    /// plaintext (any QBW-style obfuscation must be removed by the caller).
    ///
    /// `Ok` with no directory means nothing on the page looks like one.
    ///
    /// # Errors
    ///
    /// * [`Error::AmbiguousSlotDirectory`] when more than one position is
    ///   confirmed by the prelude.
    /// * [`Error::SlotDirectoryTruncated`] when the prelude declares more
    ///   entries than the page holds.
    /// * [`Error::SlotOffsetInDirectory`] when a row offset points into the
    ///   directory itself.
    /// * [`Error::NoSlotDirectory`] when slot-like data exists but the
    ///   prelude does not confirm it, or it has too few entries.
    ///
    /// All of these become warnings under [`Leniency::DIRECTORY`]: the scan
    /// heuristic is used in place of a directory the prelude rejects, and
    /// offsets inside the directory are left out of [`SlottedPage::rows`].
    pub fn parse(page: Page<'a>, opts: &ReadOptions) -> Result<Self> {
        let lenient = opts.leniency.contains(Leniency::DIRECTORY);
        let plain = page.bytes();
        let pn = page.index();
        let count = plain[TRAILER_START] as usize;
        let mut warnings: Vec<Warning> = Vec::new();
        let mut warn = |kind: WarningKind| warnings.push(Warning::new(kind).on_page(pn));

        let directory = if (1..MIN_CONFIRMED_COUNT).contains(&count) {
            // A count of 1 to 3 matches the commonest words in page data, so a
            // directory cannot be confirmed from it.
            let mut found = prelude_candidates(plain, count).found;
            if !lenient {
                return Err(if found.is_empty() {
                    Error::UnknownPrelude { page: pn }
                } else {
                    Error::NoSlotDirectory {
                        page: pn,
                        reason: "a declared count below 4 cannot be confirmed",
                    }
                });
            }
            match found.len() {
                0 => {
                    warn(WarningKind::UnknownPrelude);
                    None
                }
                1 => {
                    warn(WarningKind::UnverifiedDirectory);
                    found.pop()
                }
                _ => {
                    warn(WarningKind::AmbiguousSlotDirectory);
                    None
                }
            }
        } else if count >= MIN_CONFIRMED_COUNT {
            let mut cands = prelude_candidates(plain, count);
            match cands.found.len() {
                1 => cands.found.pop(),
                0 => {
                    if let Some((found, stopped_at)) = cands.truncated {
                        if !lenient {
                            return Err(Error::SlotDirectoryTruncated {
                                page: pn,
                                found,
                                expected: count,
                                stopped_at,
                            });
                        }
                        warn(WarningKind::SlotDirectoryTruncated {
                            found,
                            expected: count,
                        });
                    }
                    unconfirmed(plain, pn, lenient, true, &mut warn)?
                }
                _ => {
                    if !lenient {
                        return Err(Error::AmbiguousSlotDirectory { page: pn });
                    }
                    warn(WarningKind::AmbiguousSlotDirectory);
                    unconfirmed(plain, pn, lenient, true, &mut warn)?
                }
            }
        } else {
            unconfirmed(plain, pn, lenient, false, &mut warn)?
        };

        if let Some(dir) = &directory {
            let inside = dir.offsets_inside();
            if let Some(&off) = inside.first() {
                if !lenient {
                    return Err(Error::SlotOffsetInDirectory {
                        page: pn,
                        offset: off,
                        directory_end: dir.end,
                    });
                }
                warn(WarningKind::SlotOffsetsInDirectory {
                    dropped: inside.len(),
                });
            }
        }
        Ok(SlottedPage {
            page,
            directory,
            warnings,
        })
    }

    /// The underlying page.
    pub fn page(&self) -> Page<'a> {
        self.page
    }

    /// The directory, if one was found.
    pub fn directory(&self) -> Option<&SlotDirectory> {
        self.directory.as_ref()
    }

    /// Conditions accepted under lenient [`ReadOptions`].
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    /// Return the raw row bytes for each live slot, in ascending offset
    /// order.
    ///
    /// Row boundaries are inferred from the offsets of the neighbouring
    /// slot and the start of the trailer, so every [`Row::exact`] is
    /// `false`: a slice can carry free space or the residue of a deleted
    /// row after the real row, and this does not yet decode any row header.
    pub fn rows(&self) -> Vec<Row<'a>> {
        let Some(dir) = &self.directory else {
            return Vec::new();
        };
        let bytes = self.page.bytes();

        // An offset inside the directory is never a row (lenient reads only,
        // and `parse` reports their number). Offsets below the array are rows.
        let inside = dir.offsets_inside();
        let mut live: Vec<u16> = dir.live_slots().filter(|o| !inside.contains(o)).collect();
        live.sort_unstable();

        let mut out = Vec::with_capacity(live.len());
        for (i, &off) in live.iter().enumerate() {
            let start = off as usize;
            let end = live
                .get(i + 1)
                .map(|n| *n as usize)
                .unwrap_or(TRAILER_START);
            if start < end && end <= TRAILER_START {
                out.push(Row {
                    offset: off,
                    bytes: &bytes[start..end],
                    exact: false,
                });
            }
        }
        out
    }
}

fn u16le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn is_slot_offset(value: u16) -> bool {
    (SLOT_OFFSET_MIN..SLOT_OFFSET_MAX).contains(&value)
}

/// Read exactly `count` entries from `start`: zero (deleted) or a valid
/// offset strictly below the previous live one. Returns the entries read and
/// whether all `count` were valid.
fn read_declared(plain: &[u8], start: usize, count: usize) -> (Vec<u16>, bool) {
    let mut slots = Vec::with_capacity(count);
    let mut prev: u32 = 0x10000;
    for k in 0..count {
        let at = start + 2 * k;
        if at + 2 > TRAILER_START {
            return (slots, false);
        }
        let value = u16le(plain, at);
        if value == 0 {
            slots.push(0);
        } else if is_slot_offset(value) && (value as u32) < prev {
            prev = value as u32;
            slots.push(value);
        } else {
            return (slots, false);
        }
    }
    (slots, true)
}

struct PreludeCandidates {
    /// Directories read whole through the prelude layouts.
    found: Vec<SlotDirectory>,
    /// The longest array that starts like a directory but breaks before the
    /// declared count: entries read, and the byte offset where it broke.
    truncated: Option<(usize, usize)>,
}

/// Directories whose prelude count equals the trailer's count byte.
///
/// The count sits in a u16 four bytes before the array, or six bytes before
/// it when a zero word precedes it. Only counts up to 255 can match the
/// one-byte trailer value.
fn prelude_candidates(plain: &[u8], count: usize) -> PreludeCandidates {
    let mut found: Vec<SlotDirectory> = Vec::new();
    let mut truncated: Option<(usize, usize)> = None;
    if count == 0 {
        return PreludeCandidates { found, truncated };
    }
    for field in 0..SEARCH_LIMIT {
        if field + 2 > TRAILER_START || u16le(plain, field) as usize != count {
            continue;
        }
        for gap in [4usize, 6] {
            let start = field + gap;
            // With the six-byte layout the word before the array is zero.
            if gap == 6 && u16le(plain, field + 4) != 0 {
                continue;
            }
            let (slots, complete) = read_declared(plain, start, count);
            // A real array starts with its highest offset, a live slot.
            if !slots.first().is_some_and(|&s| s != 0) {
                continue;
            }
            if complete {
                found.push(SlotDirectory {
                    array_start: start,
                    end: start + 2 * count,
                    slots,
                    declared: Some(count),
                });
            } else if slots.iter().filter(|&&s| s != 0).count() >= MIN_EVIDENCE_SLOTS
                && truncated.is_none_or(|(n, _)| slots.len() > n)
            {
                truncated = Some((slots.len(), start + 2 * slots.len()));
            }
        }
    }
    // The same array can be read through both layouts; keep distinct starts.
    found.sort_by_key(|d| d.array_start);
    found.dedup_by_key(|d| d.array_start);
    PreludeCandidates { found, truncated }
}

/// No prelude-confirmed directory: the scan heuristic's candidate is an
/// error unless lenient, and nothing at all on a page that declared rows is
/// an unrecognised prelude.
fn unconfirmed(
    plain: &[u8],
    pn: u64,
    lenient: bool,
    declared: bool,
    warn: &mut impl FnMut(WarningKind),
) -> Result<Option<SlotDirectory>> {
    match scanned_directory(plain) {
        Some(dir) => {
            let reason = if dir.live_count() < MIN_LIVE_SLOTS {
                "fewer than 8 live slots and no confirming prelude"
            } else {
                "not confirmed by the page prelude"
            };
            if !lenient {
                return Err(Error::NoSlotDirectory { page: pn, reason });
            }
            warn(WarningKind::UnverifiedDirectory);
            Ok(Some(dir))
        }
        None if declared => {
            if !lenient {
                return Err(Error::UnknownPrelude { page: pn });
            }
            warn(WarningKind::UnknownPrelude);
            Ok(None)
        }
        // The page declares no rows and nothing looks like a directory.
        None => Ok(None),
    }
}

fn scan_from(plain: &[u8], start: usize) -> Option<SlotDirectory> {
    let mut pos = start;
    let mut slots: Vec<u16> = Vec::new();
    let mut prev: u32 = 0x10000;

    if pos + 3 < SEARCH_LIMIT && u16le(plain, pos) == 0 && is_slot_offset(u16le(plain, pos + 2)) {
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

    // Trailing zeros are padding, not deleted slots.
    while slots.last() == Some(&0) {
        slots.pop();
        pos -= 2;
    }
    let live_count = slots.iter().filter(|&&s| s != 0).count();
    if live_count < MIN_EVIDENCE_SLOTS {
        return None;
    }

    Some(SlotDirectory {
        array_start,
        end: pos,
        slots,
        declared: None,
    })
}

/// The scan heuristic: the start with the most live slots wins, ties keep
/// the earliest. Unconfirmed; see the module documentation.
pub(crate) fn scanned_directory(plain: &[u8]) -> Option<SlotDirectory> {
    let mut best: Option<SlotDirectory> = None;
    for start in 0..SEARCH_LIMIT {
        let Some(cand) = scan_from(plain, start) else {
            continue;
        };
        let better = match &best {
            None => true,
            Some(b) => {
                cand.live_count() > b.live_count()
                    || (cand.live_count() == b.live_count() && cand.slots.len() > b.slots.len())
            }
        };
        if better {
            best = Some(cand);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::PAGE_SIZE;

    /// A plaintext page with a prelude (`count`, `1`, `0`), a descending
    /// array of `slots` starting at `array_start`, and the trailer count.
    fn page_with(array_start: usize, slots: &[u16], count: u8) -> Vec<u8> {
        let mut p = vec![0u8; PAGE_SIZE];
        let field = array_start - 6;
        p[field..field + 2].copy_from_slice(&(count as u16).to_le_bytes());
        p[field + 2..field + 4].copy_from_slice(&1u16.to_le_bytes());
        for (k, s) in slots.iter().enumerate() {
            p[array_start + 2 * k..array_start + 2 * k + 2].copy_from_slice(&s.to_le_bytes());
        }
        p[TRAILER_START] = count;
        p
    }

    fn descending(n: usize) -> Vec<u16> {
        (0..n).map(|k| 0xF00 - 0x21 * k as u16).collect()
    }

    fn lenient() -> ReadOptions {
        ReadOptions::default().with_leniency(Leniency::DIRECTORY)
    }

    fn parse(bytes: &[u8], opts: &ReadOptions) -> Result<(Option<SlotDirectory>, usize)> {
        let sp = SlottedPage::parse(Page::from_bytes(7, bytes).unwrap(), opts)?;
        let warnings = sp.warnings().len();
        Ok((sp.directory().cloned(), warnings))
    }

    #[test]
    fn small_confirmed_directory_is_read() {
        // Audit finding 13: 7 valid slots returned no directory and no rows.
        let p = page_with(0x80, &descending(7), 7);
        let (dir, warnings) = parse(&p, &ReadOptions::default()).unwrap();
        let dir = dir.expect("directory");
        assert_eq!(dir.live_count(), 7);
        assert_eq!(dir.declared_count(), Some(7));
        assert_eq!(warnings, 0);
        let sp =
            SlottedPage::parse(Page::from_bytes(7, &p).unwrap(), &ReadOptions::default()).unwrap();
        assert_eq!(sp.rows().len(), 7);
        assert!(sp.rows().iter().all(|r| !r.exact()));
    }

    #[test]
    fn stray_value_after_a_zero_gap_is_not_a_slot() {
        // Audit finding 6: 8 real slots, zero padding, then 0x0040 later in
        // the search window was accepted as a ninth slot and produced a row
        // over the page header.
        let mut p = page_with(0x80, &descending(8), 8);
        p[0x200..0x202].copy_from_slice(&0x0040u16.to_le_bytes());
        let (dir, _) = parse(&p, &ReadOptions::default()).unwrap();
        let dir = dir.unwrap();
        assert_eq!(dir.live_count(), 8);
        assert_eq!(dir.slots().len(), 8);
        assert_eq!(dir.end(), 0x80 + 16);
    }

    #[test]
    fn unconfirmed_directory_is_an_error_unless_lenient() {
        // Audit finding 7: the layout was guessed with no cross-check.
        let mut p = page_with(0x80, &descending(10), 10);
        p[TRAILER_START] = 0; // the trailer no longer agrees with the prelude
        let err = parse(&p, &ReadOptions::default()).unwrap_err();
        assert!(
            matches!(err, Error::NoSlotDirectory { page: 7, .. }),
            "{err:?}"
        );
        let (dir, warnings) = parse(&p, &lenient()).unwrap();
        assert_eq!(dir.unwrap().declared_count(), None);
        assert_eq!(warnings, 1);
    }

    #[test]
    fn two_confirmed_directories_are_ambiguous() {
        let mut p = page_with(0x80, &descending(9), 9);
        let second = page_with(0x180, &descending(9), 9);
        p[0x17A..0x180 + 18].copy_from_slice(&second[0x17A..0x180 + 18]);
        let err = parse(&p, &ReadOptions::default()).unwrap_err();
        assert!(
            matches!(err, Error::AmbiguousSlotDirectory { page: 7 }),
            "{err:?}"
        );
    }

    #[test]
    fn declared_count_beyond_the_valid_entries_is_truncation() {
        // Audit finding 14: the scan stopped at the first out-of-order entry
        // and dropped the rest without saying so.
        let mut slots = descending(12);
        slots[9] = 0xFFF0; // out of range: breaks the array after 9 entries
        let p = page_with(0x80, &slots, 12);
        let err = parse(&p, &ReadOptions::default()).unwrap_err();
        assert!(
            matches!(
                err,
                Error::SlotDirectoryTruncated {
                    page: 7,
                    found: 9,
                    expected: 12,
                    stopped_at: 0x92,
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn directory_longer_than_the_old_search_limit_is_read_whole() {
        let slots: Vec<u16> = (0..200).map(|k| 0xF00 - 8 * k as u16).collect();
        let p = page_with(0x2A0, &slots, 200);
        let (dir, _) = parse(&p, &ReadOptions::default()).unwrap();
        assert_eq!(dir.unwrap().live_count(), 200);
    }

    #[test]
    fn offset_inside_the_directory_is_an_error() {
        let mut slots = descending(8);
        slots[7] = 0x84; // lands inside the 8-entry array at 0x80..0x90
        let p = page_with(0x80, &slots, 8);
        let err = parse(&p, &ReadOptions::default()).unwrap_err();
        assert!(
            matches!(
                err,
                Error::SlotOffsetInDirectory {
                    page: 7,
                    offset: 0x84,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn page_without_slot_data_has_no_directory() {
        let p = vec![0u8; PAGE_SIZE];
        let (dir, warnings) = parse(&p, &ReadOptions::default()).unwrap();
        assert!(dir.is_none());
        assert_eq!(warnings, 0);
    }

    #[test]
    fn small_declared_counts_are_not_confirmed() {
        // Review B2: for a count of 1 or 2 the pair (count, 0) is the commonest
        // word in page data, so "a directory of that count follows" held on
        // most pages and produced a bogus row.
        let p = page_with(0x80, &descending(2), 2);
        let err = parse(&p, &ReadOptions::default()).unwrap_err();
        assert!(
            matches!(err, Error::NoSlotDirectory { page: 7, .. }),
            "{err:?}"
        );
        let (dir, warnings) = parse(&p, &lenient()).unwrap();
        assert_eq!(dir.unwrap().live_count(), 2);
        assert_eq!(warnings, 1);

        // A page full of `01 00` words and descending values: every position
        // is a candidate, none can be trusted.
        let mut noisy = vec![0u8; PAGE_SIZE];
        for k in 0..60usize {
            noisy[0x40 + 8 * k..0x40 + 8 * k + 2].copy_from_slice(&1u16.to_le_bytes());
            let off = 0xF00u16 - 0x30 * k as u16;
            noisy[0x44 + 8 * k..0x44 + 8 * k + 2].copy_from_slice(&off.to_le_bytes());
        }
        noisy[TRAILER_START] = 1;
        assert!(parse(&noisy, &ReadOptions::default()).is_err());
        let (dir, warnings) = parse(&noisy, &lenient()).unwrap();
        assert!(dir.is_none());
        assert_eq!(warnings, 1);
    }

    #[test]
    fn declared_rows_without_a_directory_are_not_silently_none() {
        // Review S5: count 9 and no layout matched returned Ok(None).
        let mut p = vec![0u8; PAGE_SIZE];
        p[TRAILER_START] = 9;
        let err = parse(&p, &ReadOptions::default()).unwrap_err();
        assert!(matches!(err, Error::UnknownPrelude { page: 7 }), "{err:?}");
        let sp = SlottedPage::parse(Page::from_bytes(7, &p).unwrap(), &lenient()).unwrap();
        assert!(sp.directory().is_none());
        assert!(matches!(sp.warnings()[0].kind, WarningKind::UnknownPrelude));
    }

    #[test]
    fn rows_below_the_directory_are_rows() {
        // Review S4: the in-directory test was `offset < end`, which also
        // rejected rows that sit below the array (catalog rows at 0x2a..).
        let mut slots = descending(8);
        slots[6] = 0x90;
        slots[7] = 0x2A;
        let p = page_with(0x1A0, &slots, 8);
        let sp =
            SlottedPage::parse(Page::from_bytes(7, &p).unwrap(), &ReadOptions::default()).unwrap();
        assert_eq!(sp.rows().len(), 8);
        assert!(sp.rows().iter().any(|r| r.offset() == 0x2A));
        assert!(sp.warnings().is_empty());
    }

    #[test]
    fn lenient_reads_count_the_rows_they_leave_out() {
        // Review S4: lenient mode dropped rows with a warning that had no
        // count.
        let mut slots = descending(8);
        slots[6] = 0x84;
        slots[7] = 0x82;
        let p = page_with(0x80, &slots, 8);
        let page = Page::from_bytes(7, &p).unwrap();
        let sp = SlottedPage::parse(page, &lenient()).unwrap();
        assert_eq!(sp.rows().len(), 6);
        assert!(matches!(
            sp.warnings()[0].kind,
            WarningKind::SlotOffsetsInDirectory { dropped: 2 }
        ));
    }

    #[test]
    fn deleted_slots_are_zero_entries_within_the_declared_count() {
        let mut slots = descending(10);
        slots[4] = 0;
        let p = page_with(0x80, &slots, 10);
        let (dir, _) = parse(&p, &ReadOptions::default()).unwrap();
        let dir = dir.unwrap();
        assert_eq!(dir.live_count(), 9);
        assert_eq!(dir.deleted_count(), 1);
    }
}

#[cfg(test)]
mod lenient_tests {
    use super::*;

    #[test]
    fn lenient_reads_flag_a_rejected_directory() {
        let mut p = vec![0u8; crate::page::PAGE_SIZE];
        for k in 0..10usize {
            let off = 0xF00u16 - 0x21 * k as u16;
            p[0x80 + 2 * k..0x80 + 2 * k + 2].copy_from_slice(&off.to_le_bytes());
        }
        p[0x7A..0x7C].copy_from_slice(&14u16.to_le_bytes()); // declares 14, holds 10
        p[0x80 + 20..0x80 + 22].copy_from_slice(&0xFFF0u16.to_le_bytes());
        p[TRAILER_START] = 14;
        let page = Page::from_bytes(3, &p).unwrap();
        assert!(matches!(
            SlottedPage::parse(page, &ReadOptions::default()),
            Err(Error::SlotDirectoryTruncated {
                found: 10,
                expected: 14,
                ..
            })
        ));
        let opts = ReadOptions::default().with_leniency(Leniency::DIRECTORY);
        let sp = SlottedPage::parse(page, &opts).unwrap();
        assert_eq!(sp.directory().unwrap().live_count(), 10);
        assert_eq!(sp.warnings().len(), 2);
        assert!(matches!(
            sp.warnings()[0].kind,
            WarningKind::SlotDirectoryTruncated {
                found: 10,
                expected: 14
            }
        ));
    }
}
