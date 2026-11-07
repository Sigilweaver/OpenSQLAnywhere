//! Reconstruct logical QBW row bytes at offsets 3584..4092 from independent
//! stored row-length constraints. Sector 7 has only 496 stored body positions.
//! For each odd rotation we walk the 512-position cycle, skipping its sixteen
//! trailer positions. The step observed in sector zero determines the additive
//! increment along this cycle. Both observed starting phases and their
//! byte-counter wrap adjustments are tested.
//! A match verifies the length words used as constraints, not the meaning of
//! other bytes within a row.

use std::sync::{Arc, OnceLock};

use crate::{Page, RowHeaderError, RowPageHeader, SECTOR_SIZE};

const TAIL_START: usize = 7 * SECTOR_SIZE;
const BODY_LEN: usize = 496;
pub(crate) const STASH_START: usize = TAIL_START + BODY_LEN;
const STASH_LEN: usize = 12;
const TAIL_LEN: usize = BODY_LEN + STASH_LEN;

/// Why the final sector of a QBW row page could not be reconstructed.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum RowTailError {
    /// Sector zero did not yield a row-page header bound to this physical page.
    #[error(transparent)]
    Header(Arc<RowHeaderError>),
    /// Unknown later directory entries prevent reliable row-length constraints.
    #[error("page {page}: there is no complete physical slot directory")]
    IncompleteDirectory {
        /// Physical page index.
        page: u32,
    },
    /// Fewer than two distinct rows start with both length bytes in sector 7.
    #[error("page {page}: sector seven has only {count} complete row-length anchors")]
    InsufficientAnchors {
        /// Physical page index.
        page: u32,
        /// Number of independent complete length words available.
        count: usize,
    },
    /// No modeled rotation and starting phase satisfies the observed lengths.
    #[error("page {page}: no last-sector reconstruction matches every row length")]
    NoMatch {
        /// Physical page index.
        page: u32,
    },
    /// Matching candidates reconstruct different logical bytes.
    #[error("page {page}: multiple last-sector plaintexts satisfy the row lengths")]
    Ambiguous {
        /// Physical page index.
        page: u32,
    },
}

/// Logical row-data bytes from offset 3584 through 4091 inclusive, including
/// the twelve bytes recovered from the header stash.
#[derive(Debug, Clone)]
pub struct RowTail {
    bytes: Box<[u8; TAIL_LEN]>,
    rotation: Option<usize>,
    phase: Option<u8>,
    anchor_count: usize,
}

impl RowPageHeader {
    /// Bytes displaced from logical offsets 4080..4092 into sector zero.
    /// They can be recovered even when sector seven cannot be reconstructed.
    pub fn row_tail_stash(&self) -> [u8; STASH_LEN] {
        let mut bytes = [0; STASH_LEN];
        bytes[..2].copy_from_slice(&self.sector0()[18..20]);
        bytes[2..].copy_from_slice(&self.sector0()[6..16]);
        bytes
    }
}

impl RowTail {
    /// Recover the stored E/e page's header and final sector. Accept only if
    /// all candidates that satisfy the known lengths give identical plaintext.
    pub fn recover(page: Page<'_>) -> Result<Self, RowTailError> {
        let header = RowPageHeader::recover(page).map_err(|e| RowTailError::Header(Arc::new(e)))?;
        Self::recover_from_header(page, &header)
    }

    /// The caller has recovered `header` from the same stored `page`.
    pub(crate) fn recover_from_header(
        page: Page<'_>,
        header: &RowPageHeader,
    ) -> Result<Self, RowTailError> {
        let pn = header.page_number();
        let rows = header
            .physical_rows()
            .ok_or(RowTailError::IncompleteDirectory { page: pn })?;
        let stash = header.row_tail_stash();
        let mut constraints = Vec::new();
        let mut anchor_count = 0;
        for row in rows {
            // Keep the sector-seven side of length words crossing either
            // boundary. Only a complete word in its 496 bytes counts as an anchor.
            if row.start() + 2 <= TAIL_START {
                continue;
            }
            if row.length() < 2 {
                return Err(RowTailError::NoMatch { page: pn });
            }
            if (TAIL_START..TAIL_START + BODY_LEN - 1).contains(&row.start()) {
                anchor_count += 1;
            }
            for (i, value) in (row.length() as u16).to_le_bytes().into_iter().enumerate() {
                let Some(idx) = (row.start() + i).checked_sub(TAIL_START) else {
                    continue;
                };
                if idx < BODY_LEN {
                    constraints.push((idx, value));
                } else if stash[idx - BODY_LEN] != value {
                    return Err(RowTailError::NoMatch { page: pn });
                }
            }
        }
        if anchor_count < 2 {
            return Err(RowTailError::InsufficientAnchors {
                page: pn,
                count: anchor_count,
            });
        }

        let first_increment = header.step().wrapping_mul(header.rotation() as u8);
        let keys = crate::row::sector::sector_streams(header.base(), first_increment, 7);
        let raw = &page.bytes()[TAIL_START..STASH_START];
        let mut found: Option<Self> = None;
        for map in permutations() {
            for &(phase, increment, candidate_base) in keys.iter().flatten() {
                let adjusted_base = candidate_base.wrapping_add(increment.wrapping_mul(phase));
                let decode = |i| map.decode(raw, i, adjusted_base, increment);
                if !constraints.iter().all(|&(i, v)| decode(i) == v) {
                    continue;
                }
                if let Some(previous) = &mut found {
                    if (0..BODY_LEN).any(|i| previous.bytes[i] != decode(i)) {
                        return Err(RowTailError::Ambiguous { page: pn });
                    }
                    if previous.rotation != Some(map.rotation) {
                        previous.rotation = None;
                    }
                    if previous.phase != Some(phase) {
                        previous.phase = None;
                    }
                } else {
                    let mut bytes = Box::new([0; TAIL_LEN]);
                    for (i, out) in bytes[..BODY_LEN].iter_mut().enumerate() {
                        *out = decode(i);
                    }
                    bytes[BODY_LEN..].copy_from_slice(&stash);
                    found = Some(Self {
                        bytes,
                        rotation: Some(map.rotation),
                        phase: Some(phase),
                        anchor_count,
                    });
                }
            }
        }
        found.ok_or(RowTailError::NoMatch { page: pn })
    }

    /// Reconstructed logical bytes at offsets 3584..4092.
    pub fn bytes(&self) -> &[u8; TAIL_LEN] {
        &self.bytes
    }

    /// Rotation if every matching candidate has that rotation.
    pub fn rotation(&self) -> Option<usize> {
        self.rotation
    }

    /// Starting position adjustment (0 or 16) if every matching candidate
    /// has that phase. A phase is never chosen by file identity.
    pub fn phase(&self) -> Option<u8> {
        self.phase
    }

    /// Number of distinct complete row-length words in the 496-byte body.
    pub fn anchor_count(&self) -> usize {
        self.anchor_count
    }
}

pub(crate) struct TailPermutation {
    rotation: usize,
    pub(crate) positions: [u16; BODY_LEN],
    pub(crate) ordinals: [u8; BODY_LEN],
}

impl TailPermutation {
    // Positions and ordinals advance only through the 496 non-trailer bytes.
    pub(crate) fn decode(
        &self,
        stored: &[u8],
        logical: usize,
        adjusted_base: u8,
        increment: u8,
    ) -> u8 {
        stored[usize::from(self.positions[logical])]
            .wrapping_sub(adjusted_base)
            .wrapping_sub(increment.wrapping_mul(self.ordinals[logical]))
    }
}

pub(crate) fn permutations() -> &'static [TailPermutation] {
    static PERMUTATIONS: OnceLock<Vec<TailPermutation>> = OnceLock::new();
    PERMUTATIONS.get_or_init(|| {
        (1..SECTOR_SIZE)
            .step_by(2)
            .map(|rotation| {
                let mut map = TailPermutation {
                    rotation,
                    positions: [0; BODY_LEN],
                    ordinals: [0; BODY_LEN],
                };
                let mut current = 0;
                for ordinal in 1..=BODY_LEN {
                    let mut next = (current + rotation) % SECTOR_SIZE;
                    while next >= BODY_LEN {
                        next = (next + rotation) % SECTOR_SIZE;
                    }
                    map.positions[current] = next as u16;
                    map.ordinals[current] = ordinal as u8;
                    current = next;
                }
                map
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PAGE_SIZE;

    const PN: u32 = 4381;
    const FIRST_ROTATION: usize = 83;
    const STEP: u8 = 71;
    const BASE: u8 = 93;

    fn seal(raw: &mut [u8; PAGE_SIZE]) {
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
    }

    // Independent encoder: compute each ordinal by modular inverse and rank
    // subtraction, without using the decoder's cyclic traversal or its tables.
    fn encoded_position(logical: usize, r: usize) -> (usize, u8) {
        let inverse = (1..512).step_by(2).find(|k| k * r % 512 == 1).unwrap();
        let rank = |i| {
            let k = i * inverse % 512;
            if k == 0 { 512 } else { k }
        };
        let mut dst = (logical + r) % 512;
        while dst >= 496 {
            dst = (dst + r) % 512;
        }
        let skipped = (496..512).filter(|&j| rank(j) < rank(dst)).count();
        (dst, (rank(dst) - skipped) as u8)
    }

    fn write_byte(raw: &mut [u8; PAGE_SIZE], logical: usize, plain: u8, r: usize, phase: u8) {
        let (pos, ord) = encoded_position(logical, r);
        let d = STEP.wrapping_mul(FIRST_ROTATION as u8);
        raw[TAIL_START + pos] = plain
            .wrapping_add(BASE.wrapping_add(7))
            .wrapping_add(d.wrapping_mul(ord.wrapping_add(phase)));
    }

    fn fixture(starts: &[u16], r: usize, phase: u8) -> ([u8; PAGE_SIZE], [u8; TAIL_LEN]) {
        let mut logical = std::array::from_fn(|i| ((i * 4999 + i * i * 17) / 11) as u8);
        for (k, &start) in starts.iter().enumerate() {
            let end = starts.get(k + 1).copied().unwrap_or(4092);
            let off = usize::from(start) - TAIL_START;
            logical[off..off + 2].copy_from_slice(&(end - start).to_le_bytes());
        }
        let mut h = [0x39u8; SECTOR_SIZE];
        h[..4].copy_from_slice(&PN.to_le_bytes());
        h[6..16].copy_from_slice(&logical[BODY_LEN + 2..]);
        h[16] = 4;
        h[17] = 3;
        h[18..20].copy_from_slice(&logical[BODY_LEN..BODY_LEN + 2]);
        h[20..22].copy_from_slice(&(starts[0] - 28).to_le_bytes());
        h[22..24].copy_from_slice(&(starts.len() as u16).to_le_bytes());
        h[24..28].copy_from_slice(&9u32.to_le_bytes());
        for (sl, &start) in starts.iter().enumerate() {
            h[28 + 2 * sl..30 + 2 * sl].copy_from_slice(&(start - 28).to_le_bytes());
        }
        let mut raw = [0; PAGE_SIZE];
        for (j, v) in h.into_iter().enumerate() {
            let i = (j + FIRST_ROTATION) % 512;
            raw[i] = v
                .wrapping_add(BASE)
                .wrapping_add((i as u8).wrapping_mul(STEP));
        }
        for (j, &v) in logical[..BODY_LEN].iter().enumerate() {
            write_byte(&mut raw, j, v, r, phase);
        }
        raw[4080..4082].copy_from_slice(&(starts.len() as u16).to_le_bytes());
        raw[4082] = b'E';
        seal(&mut raw);
        (raw, logical)
    }

    fn page(raw: &[u8; PAGE_SIZE]) -> Page<'_> {
        Page::from_bytes(u64::from(PN), raw).unwrap()
    }

    #[test]
    fn reconstructs_both_phase_conventions_and_wrapped_rotations() {
        let starts = [3601, 3641, 3739, 3881, 4007, 4055, 4080];
        for (r, phase) in [(3, 0), (507, 16), (251, 0), (185, 16)] {
            let (raw, logical) = fixture(&starts, r, phase);
            let tail = RowTail::recover(page(&raw)).unwrap();
            assert_eq!(tail.bytes(), &logical);
            assert_eq!(tail.rotation(), Some(r));
            assert_eq!(tail.phase(), Some(phase));
            assert_eq!(tail.anchor_count(), 6);
        }
    }

    #[test]
    fn adjacent_increments_require_a_counter_wrap_and_matching_lengths() {
        let starts = [3601, 3641, 3739, 3881, 4007, 4055, 4080];
        // The synthetic sector-zero increment is 83 * 71 = 5 modulo 256.
        // These examples explicitly encode both observed wrap conventions.
        for (header_base, phase, adjusted_increment, adjusted_base, valid) in [
            (250u8, 0u8, 7u8, 255u8, true),
            (252, 16, 3, 3, true),
            (93, 0, 7, 98, false),
            (93, 16, 3, 100, false),
        ] {
            let (mut raw, logical) = fixture(&starts, 251, phase);
            for byte in &mut raw[..SECTOR_SIZE] {
                *byte = byte.wrapping_add(header_base.wrapping_sub(BASE));
            }
            for (j, &value) in logical[..BODY_LEN].iter().enumerate() {
                let (pos, ordinal) = encoded_position(j, 251);
                raw[TAIL_START + pos] = value
                    .wrapping_add(adjusted_base)
                    .wrapping_add(adjusted_increment.wrapping_mul(ordinal.wrapping_add(phase)));
            }
            seal(&mut raw);
            let result = RowTail::recover(page(&raw));
            if valid {
                let tail = result.unwrap();
                assert_eq!(tail.bytes(), &logical);
                assert_eq!(tail.phase(), Some(phase));
            } else {
                assert!(matches!(result, Err(RowTailError::NoMatch { .. })));
            }
        }
    }

    #[test]
    fn retains_stash_even_with_insufficient_anchors() {
        let (raw, logical) = fixture(&[4007, 4079, 4084], 3, 0);
        let h = RowPageHeader::recover(page(&raw)).unwrap();
        assert_eq!(h.row_tail_stash(), logical[496..]);
        assert!(matches!(
            RowTail::recover(page(&raw)),
            Err(RowTailError::InsufficientAnchors { count: 1, .. })
        ));
    }

    #[test]
    fn refuses_different_plaintexts_that_fit_the_same_two_length_words() {
        let starts = [3660, 3927];
        let (mut raw, logical) = fixture(&starts, 3, 0);
        // The two assignments constrain disjoint stored positions for these
        // row starts, so both rotations survive while interior bytes disagree.
        for &start in &starts {
            for j in 0..2 {
                let off = usize::from(start) - TAIL_START + j;
                write_byte(&mut raw, off, logical[off], 143, 16);
            }
        }
        seal(&mut raw);
        assert!(matches!(
            RowTail::recover(page(&raw)),
            Err(RowTailError::Ambiguous { .. })
        ));
    }

    #[test]
    fn rejects_a_contradictory_displaced_length_after_storage_crc_passes() {
        let (mut raw, _) = fixture(&[3601, 3641, 3739, 4007, 4055, 4080], 3, 0);
        let stash_byte = (FIRST_ROTATION + 18) % 512;
        raw[stash_byte] = raw[stash_byte].wrapping_add(1);
        seal(&mut raw);
        assert!(matches!(
            RowTail::recover(page(&raw)),
            Err(RowTailError::NoMatch { .. })
        ));
    }
}
