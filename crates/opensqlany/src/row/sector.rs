//! Recover candidate bytes in the six full sectors after a QBW row-page header.
//! An occupied slot's distance to the next physical row gives a proposed
//! little-endian length word. For an odd rotation, the product of the byte
//! step and the rotation gives the increment along the rotation cycle. The
//! header supplies that increment, subject to two observed counter carries.
//! Matching a length word constrains those bytes, not an entire row's meaning.
//! See the [format observations](https://github.com/Sigilweaver/OpenSQLAnywhere/issues/16).

use std::sync::OnceLock;

use crate::row::tail::{STASH_START, permutations};
use crate::{
    Page, RowHeaderError, RowLengthMismatch, RowPageHeader, RowTail, RowTailError, SECTOR_SIZE,
};

/// A CRC-checked QBW row page and the physical row-length constraints its
/// complete slot directory supplies. Each sector is searched only on request.
#[derive(Debug)]
pub struct RowSectorReader<'a> {
    page: Page<'a>,
    header: RowPageHeader,
    spans: Option<Vec<(usize, u16)>>,
    span_by_slot: Vec<Option<usize>>,
    sectors: [OnceLock<RowSectorRecovery<'a>>; 6],
    tail: OnceLock<Result<RowTail, RowTailError>>,
}

// Only these ordinary outcomes are eligible for the opt-in store model.
// A contradiction or a key outside the local family cannot enter this path.
#[derive(Clone, Copy)]
pub(crate) enum LocalEvidence {
    Sparse(usize),
    Ambiguous,
}

impl<'a> RowSectorReader<'a> {
    /// Recover the header from these same stored bytes. Sector recovery needs
    /// a complete directory, including a corroborated suffix when it crosses
    /// into sector one.
    pub fn new(page: Page<'a>) -> Result<Self, RowHeaderError> {
        let header = RowPageHeader::recover(page)?;
        Ok(Self::from_header(page, header))
    }

    // The caller must have recovered this header from these same stored bytes.
    pub(crate) fn from_header(page: Page<'a>, header: RowPageHeader) -> Self {
        let mut span_by_slot = vec![None; usize::from(header.slot_count())];
        let spans = header.physical_rows().map(|rows| {
            rows.iter()
                .enumerate()
                .map(|(i, row)| {
                    span_by_slot[usize::from(row.slot())] = Some(i);
                    (row.start(), row.length() as u16)
                })
                .collect()
        });
        Self {
            page,
            header,
            spans,
            span_by_slot,
            sectors: std::array::from_fn(|_| OnceLock::new()),
            tail: OnceLock::new(),
        }
    }

    /// The recovered header, including the logical first sector.
    pub fn header(&self) -> &RowPageHeader {
        &self.header
    }

    /// Try every supported odd rotation of full sectors 1 through 6.
    /// Return `None` for other sector numbers. Sector 7 needs separate
    /// handling for its displaced bytes.
    pub fn recover(&self, sector: usize) -> Option<RowSectorRecovery<'a>> {
        let cache = self.sectors.get(sector.checked_sub(1)?)?;
        Some(cache.get_or_init(|| self.solve(sector)).clone())
    }

    fn solve(&self, sector: usize) -> RowSectorRecovery<'a> {
        let Some(spans) = &self.spans else {
            return RowSectorRecovery::IncompleteDirectory;
        };
        if spans.iter().any(|&(_, length)| length < 2) {
            return RowSectorRecovery::InvalidRowSpans;
        }
        let start = sector * SECTOR_SIZE;
        let stored = &self.page.bytes()[start..start + SECTOR_SIZE];
        let increment = self
            .header
            .step()
            .wrapping_mul(self.header.rotation() as u8);
        match_sector(stored, start, self.header.base(), increment, spans)
    }

    /// Read a physical slot using its complete directory span. Returns `None`
    /// outside the declared directory. All touched full-sector solves are
    /// cached on this reader, including unsuccessful attempts.
    pub fn read_slot(&self, slot: u16) -> Option<RowSlotRecovery<'a>> {
        self.read_with(slot, |_, _, _, _, _| None)
    }

    // A caller may supply alternative evidence only after the ordinary solver
    // either found too few anchors or found competing modeled plaintexts.
    pub(crate) fn read_with(
        &self,
        slot: u16,
        mut calibrated: impl FnMut(
            usize,
            LocalEvidence,
            usize,
            usize,
            &mut Vec<u8>,
        ) -> Option<RowSlotSector<'a>>,
    ) -> Option<RowSlotRecovery<'a>> {
        let index = self.span_by_slot.get(usize::from(slot))?;
        let Some(spans) = &self.spans else {
            return Some(RowSlotRecovery::IncompleteDirectory);
        };
        let Some(i) = index else {
            return Some(RowSlotRecovery::Vacant);
        };
        let (start, length) = spans[*i];
        let end = start + usize::from(length);
        let mut sectors = Vec::new();
        let mut bytes = Vec::with_capacity(usize::from(length));
        for sector in start / SECTOR_SIZE..=(end - 1) / SECTOR_SIZE {
            let sector_start = sector * SECTOR_SIZE;
            let from = start.saturating_sub(sector_start);
            let to = (end - sector_start).min(SECTOR_SIZE);
            if sector == 0 {
                bytes.extend_from_slice(&self.header.sector0()[from..to]);
                sectors.push(RowSlotSector::Header);
            } else if let Some(recovery) = self.recover(sector) {
                let local = match &recovery {
                    RowSectorRecovery::Unique(candidate) => {
                        bytes.extend((from..to).map(|offset| candidate.decode(offset)));
                        None
                    }
                    RowSectorRecovery::Equivalent { bytes: agreed, .. } => {
                        bytes.extend_from_slice(&agreed[from..to]);
                        None
                    }
                    RowSectorRecovery::InsufficientLengths { words } => {
                        Some(LocalEvidence::Sparse(*words))
                    }
                    RowSectorRecovery::Ambiguous { .. } => Some(LocalEvidence::Ambiguous),
                    _ => None,
                };
                let evidence =
                    local.and_then(|local| calibrated(sector, local, from, to, &mut bytes));
                sectors.push(evidence.unwrap_or(RowSlotSector::Full {
                    index: sector,
                    recovery,
                }));
            } else {
                let at = sector_start + from;
                if at < STASH_START {
                    match self
                        .tail
                        .get_or_init(|| RowTail::recover_from_header(self.page, &self.header))
                    {
                        Ok(tail) => {
                            let limit = end.min(STASH_START) - sector_start;
                            bytes.extend_from_slice(&tail.bytes()[from..limit]);
                            sectors.push(RowSlotSector::Tail {
                                words: tail.anchor_count(),
                                rotation: tail.rotation(),
                                phase: tail.phase(),
                            });
                        }
                        Err(error) => {
                            let local = match error {
                                RowTailError::InsufficientAnchors { count, .. } => {
                                    Some(LocalEvidence::Sparse(*count))
                                }
                                RowTailError::Ambiguous { .. } => Some(LocalEvidence::Ambiguous),
                                _ => None,
                            };
                            let limit = end.min(STASH_START) - sector_start;
                            let evidence = local.and_then(|local| {
                                calibrated(sector, local, from, limit, &mut bytes)
                            });
                            sectors.push(
                                evidence.unwrap_or_else(|| RowSlotSector::TailGap(error.clone())),
                            );
                        }
                    }
                }
                if end > STASH_START {
                    bytes.extend_from_slice(
                        &self.header.row_tail_stash()
                            [at.saturating_sub(STASH_START)..end - STASH_START],
                    );
                    sectors.push(RowSlotSector::HeaderStash);
                }
            }
        }
        if bytes.len() != usize::from(length) {
            return Some(RowSlotRecovery::Unavailable {
                start,
                end,
                sectors,
            });
        }
        let stored = bytes
            .first_chunk::<2>()
            .map(|word| u16::from_le_bytes(*word));
        if stored != Some(length) {
            let error = RowLengthMismatch {
                page: self.header.page_number(),
                slot,
                expected: usize::from(length),
                stored,
            };
            return Some(RowSlotRecovery::LengthMismatch { error, sectors });
        }
        Some(RowSlotRecovery::Candidate {
            start,
            bytes,
            sectors,
        })
    }
}

/// Evidence for each region touched by a physical row, in page order. The
/// tail body and the twelve bytes displaced into the header are distinct.
#[derive(Debug)]
#[non_exhaustive]
pub enum RowSlotSector<'a> {
    /// Bytes from the uniquely recovered logical first sector.
    Header,
    /// A sector that was tested against its available in-sector row lengths.
    Full {
        /// Physical sector number, 1 through 6.
        index: usize,
        /// Outcome of testing the length constraints for this sector.
        recovery: RowSectorRecovery<'a>,
    },
    /// Independently constrained bytes in the 496-byte final-sector body.
    Tail {
        /// Number of complete length words checked against that body.
        words: usize,
        /// Rotation if all matching solutions agreed on it.
        rotation: Option<usize>,
        /// Starting phase if all matching solutions agreed on it.
        phase: Option<u8>,
    },
    /// The final-sector body could not be recovered under the length constraints.
    TailGap(RowTailError),
    /// A store-calibrated model agreed on the key for this region and every
    /// available length byte matched, including a complete word in this sector.
    Calibrated {
        /// Sector 1 through 7.
        index: usize,
        /// Number of complete locally checked row-length words. One denotes
        /// a sparse sector. Two or more denote a supported local ambiguity
        /// for which all retained held-out models identified the same key.
        words: usize,
    },
    /// A separately checked complete-page key supplies an unresolved sector:
    /// either no local word exists, or the ordinary calibrated key family
    /// cannot unanimously distinguish competing local plaintexts.
    /// The source page and complete key-selection evidence must be retained
    /// when publishing records that use these bytes.
    WholePage {
        /// Sector 1 through 7.
        index: usize,
        /// Complete reconstruction and independent fold validation counts.
        evidence: std::sync::Arc<crate::WholePageRecovery>,
    },
    /// The ordinary sector reader lacked sufficient anchors and calibration
    /// did not supply the missing bytes.
    CalibrationGap {
        /// Sector 1 through 7.
        index: usize,
        /// Why this region remains unresolved.
        reason: crate::CalibrationGap,
    },
    /// Bytes from logical offsets 4080..4092 restored directly from sector zero.
    HeaderStash,
}

/// Result of trying to reconstruct one physical slot. A `Candidate` has
/// the length stated by its stored first two bytes. Its interior and liveness
/// still require independent checks.
#[derive(Debug)]
#[non_exhaustive]
pub enum RowSlotRecovery<'a> {
    /// Unknown slots can change this row's endpoints.
    IncompleteDirectory,
    /// Zero entry in the slot array.
    Vacant,
    /// Some part of this row lies in an unresolved sector.
    Unavailable {
        /// Inclusive logical row start.
        start: usize,
        /// Exclusive logical row end.
        end: usize,
        /// Coverage and limitations of each sector touched.
        sectors: Vec<RowSlotSector<'a>>,
    },
    /// All bytes could be assembled, but their length word disagrees with the physical span.
    LengthMismatch {
        /// Expected and stored lengths.
        error: RowLengthMismatch,
        /// Coverage and limitations of each sector touched.
        sectors: Vec<RowSlotSector<'a>>,
    },
    /// All bytes could be assembled and the stored length matched the span.
    Candidate {
        /// Inclusive logical row start.
        start: usize,
        /// Candidate record, including the two-byte length word.
        bytes: Vec<u8>,
        /// Coverage and limitations of each sector touched.
        sectors: Vec<RowSlotSector<'a>>,
    },
}

/// What the row-length equations establish for a requested sector.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RowSectorRecovery<'a> {
    /// Some slots lie outside the recovered directory.
    IncompleteDirectory,
    /// At least one physical span cannot hold its own length word.
    InvalidRowSpans,
    /// Fewer than two complete, independent length words are available.
    InsufficientLengths {
        /// Number of complete length words in this sector.
        words: usize,
    },
    /// No rotation and step match the observed length bytes under either
    /// the within-page increment model or the older length-only search.
    NoMatch {
        /// Number of complete length words tested.
        words: usize,
    },
    /// More than one supported key satisfies all length bytes but the
    /// resulting plaintexts disagree.
    Ambiguous {
        /// Number of complete length words tested.
        words: usize,
        /// Number of matching keys.
        candidates: usize,
    },
    /// All supported keys that fit the observed lengths reconstruct identical
    /// bytes. Their individual parameters are not selected.
    Equivalent {
        /// Number of complete length words checked.
        words: usize,
        /// Number of matching keys.
        candidates: usize,
        /// Plaintext common to every one of those keys.
        bytes: Box<[u8; SECTOR_SIZE]>,
    },
    /// No supported within-page key matched, but the older search with an
    /// unconstrained step and sector-zero base plus sector number matched.
    /// Such candidates are available for inspection and are never assembled
    /// by [`RowSectorReader::read_slot`].
    Unmodeled {
        /// Number of complete length words checked.
        words: usize,
        /// Number of length-only matching keys.
        candidates: usize,
        /// The sole matching candidate when the weaker search had only one.
        candidate: Option<RowSectorCandidate<'a>>,
    },
    /// Exactly one rotation and key in the supported model matched the observed
    /// length bytes. Row payloads still need independent validation.
    Unique(RowSectorCandidate<'a>),
}

/// A single candidate under the additive sector-base and physical row-length
/// models. Its interior bytes may include fragments of several rows.
#[derive(Debug, Clone)]
pub struct RowSectorCandidate<'a> {
    stored: &'a [u8],
    rotation: usize,
    base: u8,
    step: u8,
    words: usize,
}

impl RowSectorCandidate<'_> {
    /// Stored position of logical byte zero within this sector.
    pub fn rotation(&self) -> usize {
        self.rotation
    }

    /// Additive base used to decode stored bytes.
    pub fn base(&self) -> u8 {
        self.base
    }

    /// Per-byte additive step.
    pub fn step(&self) -> u8 {
        self.step
    }

    /// Number of complete independent length words that matched. Any byte of
    /// a split length word falling in this sector was checked as well.
    pub fn matched_length_words(&self) -> usize {
        self.words
    }

    /// Reconstruct the sector under the matching key and rotation. Only the
    /// constrained length bytes have been checked against the directory.
    pub fn candidate_bytes(&self) -> [u8; SECTOR_SIZE] {
        std::array::from_fn(|index| self.decode(index))
    }

    fn decode(&self, index: usize) -> u8 {
        let stored_index = (self.rotation + index) % SECTOR_SIZE;
        self.stored[stored_index]
            .wrapping_sub(self.base)
            .wrapping_sub((stored_index as u8).wrapping_mul(self.step))
    }
}

pub(crate) fn match_sector<'a>(
    stored: &'a [u8],
    start: usize,
    header_base: u8,
    increment: u8,
    spans: &[(usize, u16)],
) -> RowSectorRecovery<'a> {
    let end = start + SECTOR_SIZE;
    let mut bytes = Vec::new();
    let mut words = 0;
    let mut anchor = None;
    for &(at, length) in spans {
        if at + 1 < start || at >= end {
            continue;
        }
        let [lo, hi] = length.to_le_bytes();
        if at >= start {
            bytes.push((at - start, lo));
        }
        if at + 1 < end {
            bytes.push((at + 1 - start, hi));
        }
        if at >= start && at + 1 < end {
            words += 1;
            anchor.get_or_insert((at - start, lo, hi));
        }
    }
    let Some((offset, lo, hi)) = anchor.filter(|_| words >= 2) else {
        return RowSectorRecovery::InsufficientLengths { words };
    };
    let sector = (start / SECTOR_SIZE) as u8;
    let nominal_base = header_base.wrapping_add(sector);
    let streams = sector_streams(header_base, increment, sector);
    let mut supported = Vec::new();
    let mut unmodeled = 0;
    let mut fallback = None;
    for rotation in 0..SECTOR_SIZE {
        let i = (rotation + offset) % SECTOR_SIZE;
        let j = (i + 1) % SECTOR_SIZE;
        // The stored-index increment from 511 to 0 is also +1 modulo 256.
        let step = stored[j]
            .wrapping_sub(stored[i])
            .wrapping_sub(hi.wrapping_sub(lo));
        let base = stored[i]
            .wrapping_sub((i as u8).wrapping_mul(step))
            .wrapping_sub(lo);
        // For odd rotations, checking this product is equivalent to deriving
        // the step from the increment times the rotation's modular inverse.
        let delta = (rotation as u8).wrapping_mul(step);
        let modeled = rotation % 2 == 1
            && streams
                .iter()
                .flatten()
                .any(|&(_, d, b)| (delta, base) == (d, b));
        if !modeled && base != nominal_base {
            continue;
        }
        let candidate = RowSectorCandidate {
            stored,
            rotation,
            base,
            step,
            words,
        };
        if bytes
            .iter()
            .all(|&(at, value)| candidate.decode(at) == value)
        {
            if modeled {
                supported.push(candidate);
            } else {
                unmodeled += 1;
                fallback = Some(candidate);
            }
        }
    }
    let Some(first) = supported.pop() else {
        return if unmodeled == 0 {
            RowSectorRecovery::NoMatch { words }
        } else {
            RowSectorRecovery::Unmodeled {
                words,
                candidates: unmodeled,
                candidate: fallback.filter(|_| unmodeled == 1),
            }
        };
    };
    if supported.is_empty() {
        return RowSectorRecovery::Unique(first);
    }
    let bytes = Box::new(first.candidate_bytes());
    let candidates = supported.len() + 1;
    if supported
        .iter()
        .all(|other| (0..SECTOR_SIZE).all(|i| other.decode(i) == bytes[i]))
    {
        RowSectorRecovery::Equivalent {
            words,
            candidates,
            bytes,
        }
    } else {
        RowSectorRecovery::Ambiguous { words, candidates }
    }
}

/// (Starting phase, increment along the rotation cycle, additive sector
/// base). In full sectors the two nominal phases give the same byte transform.
/// In the tail, omitting the sixteen trailer positions makes their phases distinct.
pub(crate) fn sector_streams(base: u8, increment: u8, sector: u8) -> [Option<(u8, u8, u8)>; 4] {
    let sector_base = base.wrapping_add(sector);
    let zero_phase_counter = base.wrapping_add(increment).wrapping_sub(1);
    [
        Some((0, increment, sector_base)),
        Some((16, increment, sector_base)),
        zero_phase_counter.checked_add(sector).is_none().then_some((
            0,
            increment.wrapping_add(2),
            sector_base.wrapping_sub(2),
        )),
        base.checked_add(sector)
            .is_none()
            .then_some((16, increment.wrapping_sub(2), sector_base)),
    ]
}

/// Visit every modeled rotation and stream for sectors 1..=7. The callback's
/// input is a local logical offset within the 512-byte full sector or the
/// 496-byte final body. No model is selected or accepted by this iterator.
pub(crate) fn visit_sector_candidates<E>(
    page: Page<'_>,
    h: &RowPageHeader,
    gap: usize,
    mut consider: impl FnMut(&dyn Fn(usize) -> u8) -> Result<(), E>,
) -> Result<(), E> {
    debug_assert!((1..=7).contains(&gap));
    let sector_start = gap * SECTOR_SIZE;
    let increment = h.step().wrapping_mul(h.rotation() as u8);
    let streams = sector_streams(h.base(), increment, gap as u8);
    if gap == 7 {
        for map in permutations() {
            for &(phase, delta, base) in streams.iter().flatten() {
                let raw = &page.bytes()[sector_start..STASH_START];
                let adjusted = base.wrapping_add(delta.wrapping_mul(phase));
                consider(&|i| map.decode(raw, i, adjusted, delta))?;
            }
        }
    } else {
        for rotation in (1..SECTOR_SIZE).step_by(2) {
            let inverse = inverse_odd(rotation as u8);
            for &(_, delta, base) in streams
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != 1)
                .filter_map(|(_, key)| key.as_ref())
            {
                let step = delta.wrapping_mul(inverse);
                consider(&|i| {
                    let at = (rotation + i) % SECTOR_SIZE;
                    page.bytes()[sector_start + at]
                        .wrapping_sub(base)
                        .wrapping_sub((at as u8).wrapping_mul(step))
                })?;
            }
        }
    }
    Ok(())
}

pub(crate) fn inverse_odd(value: u8) -> u8 {
    // For any odd x, x*x = 1 modulo 8. Each Newton iteration doubles
    // the number of correct bits, reaching all eight after two iterations.
    let mut inv = value;
    for _ in 0..2 {
        inv = inv.wrapping_mul(2u8.wrapping_sub(value.wrapping_mul(inv)));
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PAGE_SIZE;

    fn encode(data: &[u8; SECTOR_SIZE], rotation: usize, base: u8, step: u8) -> [u8; SECTOR_SIZE] {
        std::array::from_fn(|i| {
            data[(i + SECTOR_SIZE - rotation) % SECTOR_SIZE]
                .wrapping_add(base)
                .wrapping_add((i as u8).wrapping_mul(step))
        })
    }

    fn varied_bytes() -> [u8; SECTOR_SIZE] {
        let mut state = 14u32;
        std::array::from_fn(|_| {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 24) as u8
        })
    }

    #[test]
    fn full_page_recovers_sector_with_wrapping_anchor() {
        let pn = 0x1234_5678u32;
        let mut raw = [0u8; PAGE_SIZE];
        let mut header = [0u8; SECTOR_SIZE];
        header[..4].copy_from_slice(&pn.to_le_bytes());
        header[16] = 4;
        header[17] = 3;
        let starts = [528u16, 567, 881, 1398];
        header[20..22].copy_from_slice(&(starts[0] - 28).to_le_bytes());
        header[22..24].copy_from_slice(&(starts.len() as u16).to_le_bytes());
        for (i, at) in starts.iter().enumerate() {
            header[28 + i * 2..30 + i * 2].copy_from_slice(&(at - 28).to_le_bytes());
        }
        raw[..SECTOR_SIZE].copy_from_slice(&encode(&header, 103, 255, 93));
        let mut logical = varied_bytes();
        for pair in starts.windows(2) {
            let at = usize::from(pair[0]) - SECTOR_SIZE;
            logical[at..at + 2].copy_from_slice(&(pair[1] - pair[0]).to_le_bytes());
        }
        // The first length word is stored at 511 and 0, and the sector base wraps to 0.
        raw[512..1024].copy_from_slice(&encode(&logical, 495, 0, 69));
        raw[4080] = starts.len() as u8;
        raw[4082] = b'e';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        let page = Page::from_bytes(u64::from(pn), &raw).unwrap();
        let reader = RowSectorReader::new(page).unwrap();
        assert_eq!(reader.header().page_number(), pn);
        let Some(RowSectorRecovery::Unique(sector)) = reader.recover(1) else {
            panic!("expected one wrapping key");
        };
        assert_eq!(
            (sector.rotation(), sector.base(), sector.step()),
            (495, 0, 69)
        );
        assert_eq!(sector.matched_length_words(), 3);
        assert_eq!(sector.candidate_bytes(), logical);
        assert!(matches!(
            reader.recover(2),
            Some(RowSectorRecovery::InsufficientLengths { words: 1 })
        ));
        assert!(reader.recover(0).is_none() && reader.recover(7).is_none());
    }

    #[test]
    fn both_halves_of_split_length_words_are_checked() {
        let spans = [(511, 7), (518, 153), (671, 352), (1023, 145)];
        let mut bytes = varied_bytes();
        bytes[0] = 0;
        bytes[6..8].copy_from_slice(&153u16.to_le_bytes());
        bytes[159..161].copy_from_slice(&352u16.to_le_bytes());
        bytes[511] = 145;
        let raw = encode(&bytes, 85, 105, 199);
        assert!(matches!(
            match_sector(&raw, 512, 104, 19, &spans),
            RowSectorRecovery::Unique(_)
        ));
        for index in [0, 511] {
            let mut corrupted = raw;
            corrupted[(85 + index) % SECTOR_SIZE] ^= 1;
            assert!(matches!(
                match_sector(&corrupted, 512, 104, 19, &spans),
                RowSectorRecovery::NoMatch { words: 2 }
            ));
        }
    }

    #[test]
    fn nominal_and_counter_wraps_match_the_same_page_length_constraints() {
        let spans = [(3078, 153), (3231, 171), (3402, 150)];
        let mut data = varied_bytes();
        for &(start, length) in &spans {
            let i = start - 3072;
            data[i..i + 2].copy_from_slice(&u16::to_le_bytes(length));
        }
        // Sector six, header increment 5. A phase-zero carry from 250+5-1
        // changes both fields. A phase-16 carry from 255 changes only d.
        for (header_base, base, sector_increment) in [(93u8, 99u8, 5u8), (250, 254, 7), (255, 5, 3)]
        {
            let rotation = 355usize;
            let step = (0u8..=255)
                .find(|k| (rotation as u8).wrapping_mul(*k) == sector_increment)
                .unwrap();
            let raw = encode(&data, rotation, base, step);
            let RowSectorRecovery::Unique(candidate) =
                match_sector(&raw, 3072, header_base, 5, &spans)
            else {
                panic!("expected a unique supported key");
            };
            assert_eq!(
                (candidate.base(), candidate.rotation(), candidate.step()),
                (base, rotation, step)
            );
            assert_eq!(candidate.candidate_bytes(), data);
        }
    }

    #[test]
    fn equal_plaintexts_do_not_identify_an_arbitrary_rotation() {
        let spans = [(514, 257), (771, 257)];
        let raw = [1; SECTOR_SIZE];
        let RowSectorRecovery::Equivalent {
            words,
            candidates,
            bytes,
        } = match_sector(&raw, 512, 255, 0, &spans)
        else {
            panic!("same plaintext from all rotations");
        };
        assert_eq!(words, 2);
        assert_eq!(candidates, 256);
        assert_eq!(*bytes, raw);
    }

    #[test]
    fn different_plaintexts_remain_ambiguous_when_both_fit_the_lengths() {
        let spans = [(514usize, 157u16), (671, 198)];
        let mut raw = varied_bytes();
        // Two different within-page keys can satisfy the same two length
        // words at disjoint physical positions.
        for rotation in [31usize, 131] {
            let step = (0u8..=255)
                .find(|k| (rotation as u8).wrapping_mul(*k) == 57)
                .unwrap();
            for &(start, len) in &spans {
                for (j, value) in len.to_le_bytes().into_iter().enumerate() {
                    let i = (start - 512 + j + rotation) % SECTOR_SIZE;
                    raw[i] = value
                        .wrapping_add(101)
                        .wrapping_add((i as u8).wrapping_mul(step));
                }
            }
        }
        assert!(matches!(
            match_sector(&raw, 512, 100, 57, &spans),
            RowSectorRecovery::Ambiguous {
                words: 2,
                candidates: 2..
            }
        ));
    }

    #[test]
    fn nominal_base_alone_cannot_promote_a_length_only_candidate() {
        let spans = [(514usize, 157u16), (671, 198), (869, 225)];
        let mut data = varied_bytes();
        for &(at, len) in &spans {
            data[at - 512..at - 510].copy_from_slice(&len.to_le_bytes());
        }
        // An odd but incorrect increment and an even rotation are separately
        // possible in the old unconstrained search. Neither is a modeled key.
        for (rotation, step) in [(85usize, 199u8), (84, 199)] {
            let raw = encode(&data, rotation, 101, step);
            let RowSectorRecovery::Unmodeled {
                words: 3,
                candidates: 1,
                candidate: Some(candidate),
            } = match_sector(&raw, 512, 100, 5, &spans)
            else {
                panic!("expected length-only evidence");
            };
            assert_eq!(candidate.candidate_bytes(), data);
        }
    }

    #[test]
    fn a_slot_crossing_a_sector_is_assembled_only_when_every_piece_is_available() {
        let pn = 0x4217_3168u32;
        let mut raw = [0u8; PAGE_SIZE];
        let mut header = varied_bytes();
        let mut middle = varied_bytes();
        // Original slot numbers deliberately disagree with physical offset order.
        let slots = [544u16, 300, 0, 511, 810, 1220, 3570];
        header[..4].copy_from_slice(&pn.to_le_bytes());
        header[16] = 4;
        header[17] = 3;
        header[20..22].copy_from_slice(&(300u16 - 28).to_le_bytes());
        header[22..24].copy_from_slice(&(slots.len() as u16).to_le_bytes());
        for (i, start) in slots.into_iter().enumerate() {
            header[28 + 2 * i..30 + 2 * i].copy_from_slice(&start.saturating_sub(28).to_le_bytes());
        }
        // A bad length entirely within sector zero is reported separately.
        header[300..302].copy_from_slice(&99u16.to_le_bytes());
        // The record from 511..544 has its length word split across sectors.
        header[511] = 33;
        middle[0] = 0;
        middle[32..34].copy_from_slice(&266u16.to_le_bytes());
        middle[298..300].copy_from_slice(&410u16.to_le_bytes());
        raw[..512].copy_from_slice(&encode(&header, 209, 88, 13));
        raw[512..1024].copy_from_slice(&encode(&middle, 133, 89, 57));
        raw[4080] = 6;
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        let page = Page::from_bytes(u64::from(pn), &raw).unwrap();
        let reader = RowSectorReader::new(page).unwrap();
        let Some(RowSlotRecovery::Candidate {
            start,
            bytes,
            sectors,
        }) = reader.read_slot(3)
        else {
            panic!("crossed row should be complete");
        };
        assert_eq!(start, 511);
        assert_eq!(bytes, [&header[511..512], &middle[..32]].concat());
        assert!(matches!(
            sectors.as_slice(),
            [
                RowSlotSector::Header,
                RowSlotSector::Full {
                    index: 1,
                    recovery: RowSectorRecovery::Unique(_)
                }
            ]
        ));
        assert!(matches!(
            reader.read_slot(1),
            Some(RowSlotRecovery::LengthMismatch {
                error: RowLengthMismatch {
                    expected: 211,
                    stored: Some(99),
                    ..
                },
                ..
            })
        ));
        assert!(matches!(reader.read_slot(2), Some(RowSlotRecovery::Vacant)));
        assert!(reader.read_slot(7).is_none());
        assert!(matches!(
            reader.read_slot(4),
            Some(RowSlotRecovery::Unavailable {
                start: 810,
                end: 1220,
                ..
            })
        ));
        let Some(RowSlotRecovery::Unavailable { sectors, .. }) = reader.read_slot(6) else {
            panic!("row crossing into sector seven should have explicit gaps");
        };
        assert!(matches!(
            sectors.as_slice(),
            [
                RowSlotSector::Full {
                    index: 6,
                    recovery: RowSectorRecovery::InsufficientLengths { .. }
                },
                RowSlotSector::TailGap(RowTailError::InsufficientAnchors { .. }),
                RowSlotSector::HeaderStash,
            ]
        ));
    }

    #[test]
    fn all_matching_keys_are_counted_without_choosing_one() {
        let spans = [(514, 257), (771, 257)];
        assert!(matches!(
            match_sector(&[1; 512], 512, 255, 1, &spans),
            RowSectorRecovery::Unmodeled {
                words: 2,
                candidates: 512,
                candidate: None,
            }
        ));
        assert!(matches!(
            match_sector(&[0; 512], 512, 255, 1, &spans),
            RowSectorRecovery::NoMatch { words: 2 }
        ));
        assert!(matches!(
            match_sector(&[1; 512], 512, 255, 1, &[]),
            RowSectorRecovery::InsufficientLengths { words: 0 }
        ));
    }

    #[test]
    fn final_body_and_displaced_stash_have_separate_evidence() {
        let pn = 0x2468_ac13u32;
        let starts = [3700u16, 3850, 4075, 4086];
        let mut raw = [0u8; PAGE_SIZE];
        let mut header = varied_bytes();
        let varied = varied_bytes();
        let mut tail: [u8; 508] = std::array::from_fn(|i| varied[i]);
        for (i, &start) in starts.iter().enumerate() {
            let at = usize::from(start) - 3584;
            let end = starts.get(i + 1).copied().unwrap_or(4092);
            tail[at..at + 2].copy_from_slice(&(end - start).to_le_bytes());
            header[28 + 2 * i..30 + 2 * i].copy_from_slice(&(start - 28).to_le_bytes());
        }
        header[..4].copy_from_slice(&pn.to_le_bytes());
        header[16] = 4;
        header[17] = 3;
        header[20..22].copy_from_slice(&(starts[0] - 28).to_le_bytes());
        header[22..24].copy_from_slice(&(starts.len() as u16).to_le_bytes());
        header[18..20].copy_from_slice(&tail[496..498]);
        header[6..16].copy_from_slice(&tail[498..]);
        raw[..512].copy_from_slice(&encode(&header, 1, 12, 93));
        // Rotation one walks the 496 stored positions in their natural order.
        for (i, &value) in tail[..496].iter().enumerate() {
            let at = (i + 1) % 496;
            raw[3584 + at] = value
                .wrapping_add(19)
                .wrapping_add(((i + 1) as u8).wrapping_mul(93));
        }
        raw[4080] = starts.len() as u8;
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        let page = Page::from_bytes(u64::from(pn), &raw).unwrap();
        let reader = RowSectorReader::new(page).unwrap();
        let Some(RowSlotRecovery::Candidate { bytes, sectors, .. }) = reader.read_slot(3) else {
            panic!("a complete stash row does not need a final-sector solve");
        };
        assert_eq!(bytes, tail[502..]);
        assert!(matches!(sectors.as_slice(), [RowSlotSector::HeaderStash]));
        assert!(reader.tail.get().is_none());
        let Some(RowSlotRecovery::Candidate { bytes, sectors, .. }) = reader.read_slot(2) else {
            panic!("row should cross into the stash");
        };
        assert_eq!(bytes, tail[491..502]);
        assert!(matches!(
            sectors.as_slice(),
            [
                RowSlotSector::Tail { words: 3, .. },
                RowSlotSector::HeaderStash
            ]
        ));
        assert!(reader.tail.get().is_some());
    }
}
