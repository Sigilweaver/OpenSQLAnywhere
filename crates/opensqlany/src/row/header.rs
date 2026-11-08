//! Recover the logical first sector of a QBW row page. The sector is both
//! additively encoded and circularly rotated. Its page-number and directory
//! provide independent checks on the result. See
//! [format observations](https://github.com/Sigilweaver/OpenSQLAnywhere/issues/16).

use crate::{Error, Page, SECTOR_SIZE};

const DIRECTORY_START: usize = 28;
const ROW_AREA_END: usize = 4092;
const MAX_SLOT_COUNT: u16 = 1500;

/// Why a QBW logical row-page header could not be recovered.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RowHeaderError {
    /// The stored type is outside the supported physical row-page families.
    #[error("page {page}: unsupported row-page type 0x{page_type:02X}")]
    NotRowPage {
        /// Physical page number.
        page: u64,
        /// Stored trailer type.
        page_type: u8,
    },
    /// The on-disk page number must fit the header's four-byte field.
    #[error("page {page}: physical page number does not fit in a row-page header")]
    UnsupportedPageNumber {
        /// Physical page number.
        page: u64,
    },
    /// The stored CRC or data-page trailer failed its check.
    #[error(transparent)]
    Integrity(#[from] Error),
    /// No candidate matched this physical page number and the row structure.
    /// A checkpoint copy can carry another page's number.
    #[error("page {page}: no matching logical row-page header")]
    NoMatch {
        /// Physical page number.
        page: u64,
    },
    /// A matching key had multiple page-number anchors, or more than one
    /// reconstruction satisfied the checks.
    #[error("page {page}: ambiguous logical row-page header")]
    Ambiguous {
        /// Physical page number.
        page: u64,
    },
}

/// The recovered header and logical sector 0 of a QBW row page. Recovery checks
/// the physical page, the sector key, and the visible directory prefix.
/// A directory ending in sector one is returned whole only when its suffix
/// passes independent length checks.
#[derive(Debug, Clone)]
pub struct RowPageHeader {
    sector: Box<[u8; SECTOR_SIZE]>,
    rotation: usize,
    base: u8,
    step: u8,
    directory_prefix_count: u16,
    slot_starts: Vec<Option<u16>>,
    owner_anchor: bool,
    mapped_number_offsets: Vec<u16>,
}

impl RowPageHeader {
    /// These trailer types can contain row pages. Most A pages serve a different
    /// purpose; the stored page number, header and directory still need to match.
    pub fn supports_type(raw: u8) -> bool {
        matches!(raw.to_ascii_uppercase(), b'E' | b'A' | b'G')
    }

    /// Recover sector 0 from a **stored** page, with CRC and trailer intact.
    /// Every odd rotation is considered. At each position the first two
    /// known page-number bytes determine the additive step and base exactly.
    ///
    /// # Errors
    ///
    /// * [`RowHeaderError::Integrity`] when the CRC or stored trailer fails.
    /// * [`RowHeaderError::NotRowPage`] or
    ///   [`RowHeaderError::UnsupportedPageNumber`] for unsupported pages.
    /// * [`RowHeaderError::NoMatch`] when no structural candidate matches.
    /// * [`RowHeaderError::Ambiguous`] when the checks do not select one key
    ///   and one page-number anchor.
    pub fn recover(page: Page<'_>) -> Result<Self, RowHeaderError> {
        let pn = page.index();
        let mut candidates = Self::structural_candidates(page)?;
        let (mut header, repeated) = candidates
            .next()
            .ok_or(RowHeaderError::NoMatch { page: pn })?;
        if repeated || candidates.next().is_some() {
            return Err(RowHeaderError::Ambiguous { page: pn });
        }
        header.complete_directory(page);
        Ok(header)
    }

    // Only mapped row members may supply this independently expected owner.
    // Exhaust the structural keys before checking that owner: even a second
    // key with an incompatible owner disqualifies the page. A repeated integer
    // elsewhere in the sole header's bytes is not itself a competing header.
    // Complete row/value validation remains separate from member identity.
    pub(crate) fn recover_for_owner(page: Page<'_>, owner: u32) -> Result<Self, RowHeaderError> {
        let prior = match Self::recover(page) {
            Ok(header) => return Ok(header),
            Err(error @ RowHeaderError::Ambiguous { .. }) => error,
            Err(error) => return Err(error),
        };
        let Some(mut header) = Self::sole_repeated_candidate(page)? else {
            return Err(prior);
        };
        if header.owner_id() != owner
            || header.page_kind() > 4
            || header.complete_slot_starts().is_none()
            || header.directory_prefix_matches() != Some(true)
            || header.physical_rows().is_none()
        {
            return Err(prior);
        }
        let number = header.page_number().to_le_bytes();
        header.mapped_number_offsets = (1..SECTOR_SIZE)
            .filter(|&start| (0..4).all(|i| header.sector[(start + i) % SECTOR_SIZE] == number[i]))
            .map(|at| at as u16)
            .collect();
        header.owner_anchor =
            page.index() == u64::from(owner) && header.mapped_number_offsets == [24];
        Ok(header)
    }

    // Each candidate passes the physical page, marker, kind and directory-prefix
    // checks. Its boolean reports another occurrence of the physical page number.
    pub(crate) fn structural_candidates(
        page: Page<'_>,
    ) -> Result<impl Iterator<Item = (Self, bool)> + '_, RowHeaderError> {
        let pn = page.index();
        let page_type = page.trailer().page_type_raw();
        if pn == 0 || !Self::supports_type(page_type) {
            return Err(RowHeaderError::NotRowPage {
                page: pn,
                page_type,
            });
        }
        let number = u32::try_from(pn)
            .map_err(|_| RowHeaderError::UnsupportedPageNumber { page: pn })?
            .to_le_bytes();
        page.verify_crc()?;
        page.verify_trailer()?;
        let directory_prefix_count = u16_at(page.bytes(), 0xFF0);
        let raw = &page.bytes()[..SECTOR_SIZE];
        Ok((1..SECTOR_SIZE).step_by(2).filter_map(move |rotation| {
            let step = raw[(rotation + 1) % SECTOR_SIZE]
                .wrapping_sub(raw[rotation])
                .wrapping_sub(number[1].wrapping_sub(number[0]));
            let base = raw[rotation]
                .wrapping_sub(number[0])
                .wrapping_sub((rotation as u8).wrapping_mul(step));
            let decode = |logical: usize| {
                let i = (rotation + logical) % SECTOR_SIZE;
                raw[i]
                    .wrapping_sub(base)
                    .wrapping_sub((i as u8).wrapping_mul(step))
            };
            if decode(2) != number[2]
                || decode(3) != number[3]
                || decode(16) != 4
                || !matches!(decode(17), 0..=4 | 0x10..=0x14)
            {
                return None;
            }
            let sector = Box::new(std::array::from_fn(decode));
            let slot_starts = checked_slot_starts(&sector, directory_prefix_count)?;
            // A second occurrence can wrap across the end of the sector.
            let repeated = (1..SECTOR_SIZE)
                .any(|start| (0..4).all(|i| sector[(start + i) % SECTOR_SIZE] == number[i]));
            Some((
                Self {
                    sector,
                    rotation,
                    base,
                    step,
                    directory_prefix_count,
                    slot_starts,
                    owner_anchor: false,
                    mapped_number_offsets: Vec::new(),
                },
                repeated,
            ))
        }))
    }

    // Intended only for callers that corroborate a specific independently
    // bounded record. Even an unusable second structural key disqualifies it.
    pub(crate) fn sole_repeated_candidate(page: Page<'_>) -> Result<Option<Self>, RowHeaderError> {
        let mut candidates = Self::structural_candidates(page)?;
        let Some((mut header, true)) = candidates.next() else {
            return Ok(None);
        };
        if candidates.next().is_some() {
            return Ok(None);
        }
        header.complete_directory(page);
        Ok(Some(header))
    }

    // A current referring row supplies this owner and exact overflow slot.
    // Repeated page-number bytes alone do not supply either identity. All
    // structural keys are counted before any of these reference checks; the
    // caller must still verify the complete page, frame and logical value.
    pub(crate) fn sole_repeated_lob(
        page: Page<'_>,
        owner: u32,
        slot: u16,
    ) -> Result<Option<Self>, RowHeaderError> {
        let Some(header) = Self::sole_repeated_candidate(page)? else {
            return Ok(None);
        };
        if header.owner_id() != owner
            || !(0x11..=0x14).contains(&header.page_kind())
            || header.complete_slot_starts().is_none()
            || header.directory_prefix_matches() != Some(true)
            || !header.physical_rows().is_some_and(|rows| {
                rows.iter()
                    .any(|row| row.slot() == slot && row.length() >= 3)
            })
        {
            return Ok(None);
        }
        Ok(Some(header))
    }

    pub(crate) fn complete_directory(&mut self, page: Page<'_>) {
        if !self.directory_complete() {
            if let Some(slots) = crate::row::directory::complete(page, self) {
                self.slot_starts = slots;
            }
        }
    }

    // Used only after a frozen whole-page key has materialized a LOB page.
    // This validates a proposed directory; it neither selects that key nor
    // replaces the caller's all-model, complete-frame and byte-consensus checks.
    pub(crate) fn lob_directory_from_materialized(&self, bytes: &[u8]) -> Option<Self> {
        if !(0x11..=0x14).contains(&self.page_kind())
            || bytes.len() != crate::PAGE_SIZE
            || bytes[..SECTOR_SIZE] != self.sector0()[..]
        {
            return None;
        }
        let count = usize::from(self.slot_count());
        let end = DIRECTORY_START + 2 * count;
        if !(SECTOR_SIZE + 1..=2 * SECTOR_SIZE).contains(&end) {
            return None;
        }
        let mut slots = self.slot_starts.clone();
        for slot in slots.len()..count {
            let offset = DIRECTORY_START + 2 * slot;
            let relative = u16_at(bytes, offset);
            let start = DIRECTORY_START + usize::from(relative);
            if relative != 0 && !(end..=ROW_AREA_END - 3).contains(&start) {
                return None;
            }
            slots.push((relative != 0).then_some(start as u16));
        }
        let mut occupied: Vec<_> = slots.iter().flatten().copied().collect();
        occupied.sort_unstable();
        if occupied.first().copied().map(usize::from)
            != Some(DIRECTORY_START + usize::from(u16_at(self.sector0(), 20)))
            || occupied.windows(2).any(|pair| pair[1] - pair[0] < 3)
            || slots.iter().position(Option::is_none).unwrap_or(count)
                != usize::from(self.directory_prefix_count())
        {
            return None;
        }
        let mut complete = self.clone();
        complete.slot_starts = slots;
        Some(complete)
    }

    /// Logical first sector, in unrotated row-page coordinates.
    pub fn sector0(&self) -> &[u8; SECTOR_SIZE] {
        &self.sector
    }

    /// Physical page number confirmed by the four-byte logical header.
    pub fn page_number(&self) -> u32 {
        u32_at(&*self.sector, 0)
    }

    /// Owner identifier stored at logical offset 24.
    pub fn owner_id(&self) -> u32 {
        u32_at(&*self.sector, 24)
    }

    /// This mapped member's sole extra page-number occurrence was the owner
    /// field at offset 24, corroborated by the independently expected owner.
    /// Ordinary recovery never sets this flag, and no competing structural key
    /// or unexplained occurrence can use this exception.
    pub fn uses_owner_anchor(&self) -> bool {
        self.owner_anchor
    }

    /// Extra page-number occurrences on a mapped member whose sole structural
    /// header was corroborated with the independently expected catalog owner.
    /// Positions are logical sector-zero offsets, including wrapped occurrences.
    /// Other recovery paths return an empty slice. These bytes establish no row
    /// liveness or field value; those still require their separate checks.
    pub fn mapped_number_offsets(&self) -> &[u16] {
        &self.mapped_number_offsets
    }

    /// Raw page-kind byte at logical offset 17.
    pub fn page_kind(&self) -> u8 {
        self.sector[17]
    }

    /// Number of physical slots declared by the header, including vacant entries.
    pub fn slot_count(&self) -> u16 {
        u16_at(&*self.sector, 22)
    }

    /// The stored little-endian word at offset 0xFF0. In observed QBW row
    /// pages this is the index of the first zero slot word, or the slot count
    /// when all entries are occupied. Occupied slots may follow a vacant one.
    pub fn directory_prefix_count(&self) -> u16 {
        self.directory_prefix_count
    }

    /// Compare the trailer with the independently recovered directory, in slot
    /// order. An observed zero fixes the prefix even if the suffix is missing.
    /// With no observed zero, an incomplete directory can disprove a shorter
    /// stored prefix but cannot establish where that prefix actually ends.
    pub fn directory_prefix_matches(&self) -> Option<bool> {
        let stored = usize::from(self.directory_prefix_count());
        if let Some(first_zero) = self.slot_starts.iter().position(Option::is_none) {
            return Some(first_zero == stored);
        }
        if stored < self.slot_starts.len() {
            return Some(false);
        }
        self.complete_slot_starts()
            .map(|slots| slots.len() == stored)
    }

    /// Legacy name for [`Self::directory_prefix_count`]; use that method in
    /// new code. Both return the same raw trailer word, which describes the
    /// leading occupied directory entries. Row visibility needs other evidence.
    pub fn live_count(&self) -> u16 {
        self.directory_prefix_count()
    }

    /// Whether the entire declared slot directory fits inside sector 0.
    pub fn directory_complete(&self) -> bool {
        DIRECTORY_START + 2 * usize::from(self.slot_count()) <= SECTOR_SIZE
    }

    /// Slots present in sector 0, in slot order. An entry is an absolute
    /// logical page offset or `None` for a zero directory entry. When the
    /// directory crosses the sector boundary, only its known prefix is returned.
    pub fn sector0_slot_starts(&self) -> &[Option<u16>] {
        &self.slot_starts[..self
            .slot_starts
            .len()
            .min((SECTOR_SIZE - DIRECTORY_START) / 2)]
    }

    /// All slot starts, including a corroborated suffix in the second sector.
    /// An unresolved suffix returns `None`; the prefix remains available
    /// through [`Self::sector0_slot_starts`].
    pub fn complete_slot_starts(&self) -> Option<&[Option<u16>]> {
        (self.slot_starts.len() == usize::from(self.slot_count())).then_some(&self.slot_starts)
    }

    /// Stored position of logical byte zero inside sector 0.
    pub fn rotation(&self) -> usize {
        self.rotation
    }

    /// Additive base of sector 0, before rotation.
    pub fn base(&self) -> u8 {
        self.base
    }

    /// Additive step of sector 0, before rotation.
    pub fn step(&self) -> u8 {
        self.step
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn checked_slot_starts(sector: &[u8; SECTOR_SIZE], prefix_count: u16) -> Option<Vec<Option<u16>>> {
    let slot_count = u16_at(sector, 22);
    if slot_count > MAX_SLOT_COUNT || prefix_count > slot_count {
        return None;
    }
    let slot_count = usize::from(slot_count);
    let directory_end = DIRECTORY_START + 2 * slot_count;
    let visible = slot_count.min((SECTOR_SIZE - DIRECTORY_START) / 2);
    let mut starts = Vec::with_capacity(visible);
    let mut occupied = Vec::with_capacity(visible);
    for i in 0..visible {
        let relative = u16_at(sector, DIRECTORY_START + 2 * i);
        if relative == 0 {
            starts.push(None);
            continue;
        }
        let absolute = usize::from(relative) + DIRECTORY_START;
        if absolute < directory_end || absolute + 2 > ROW_AREA_END {
            return None;
        }
        starts.push(Some(absolute as u16));
        occupied.push(relative);
    }
    // Every entry of a leading occupied prefix must have a start. Count
    // unknown suffix entries as possible starts for this structural bound;
    // the separate prefix check can then compare the actual vacancy position.
    if usize::from(prefix_count) > occupied.len() + slot_count - visible {
        return None;
    }
    occupied.sort_unstable();
    if occupied.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }
    // A nonempty page names its lowest physical row even when that row's
    // directory entry lies beyond the visible prefix.
    let lowest = u16_at(sector, 20);
    if !occupied.is_empty() || prefix_count != 0 {
        let start = DIRECTORY_START + usize::from(lowest);
        if start < directory_end || start + 2 > ROW_AREA_END {
            return None;
        }
    }
    if let Some(&first) = occupied.first() {
        if lowest > first || (visible == slot_count && lowest != first) {
            return None;
        }
    }
    Some(starts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PAGE_SIZE;

    const PN: u32 = 0x102_0304;

    fn make_sector(slots: &[u16]) -> [u8; SECTOR_SIZE] {
        let mut s = [0x35; SECTOR_SIZE];
        s[..4].copy_from_slice(&PN.to_le_bytes());
        s[16] = 4;
        s[17] = 3;
        s[20..22].copy_from_slice(
            &slots
                .iter()
                .copied()
                .filter(|&x| x != 0)
                .min()
                .unwrap_or(0)
                .to_le_bytes(),
        );
        s[22..24].copy_from_slice(&(slots.len() as u16).to_le_bytes());
        s[24..28].copy_from_slice(&7u32.to_le_bytes());
        for (word, &value) in s[28..].chunks_exact_mut(2).zip(slots) {
            word.copy_from_slice(&value.to_le_bytes());
        }
        s
    }

    fn seal(raw: &mut [u8; PAGE_SIZE]) {
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
    }

    fn store_sector(
        s: &[u8; SECTOR_SIZE],
        rotation: usize,
        base: u8,
        step: u8,
        stored_prefix: u16,
    ) -> [u8; PAGE_SIZE] {
        let mut raw = [0; PAGE_SIZE];
        for (logical, &byte) in s.iter().enumerate() {
            let i = (logical + rotation) % SECTOR_SIZE;
            raw[i] = byte
                .wrapping_add(base)
                .wrapping_add((i as u8).wrapping_mul(step));
        }
        raw[4080..4082].copy_from_slice(&stored_prefix.to_le_bytes());
        raw[4082] = b'e';
        seal(&mut raw);
        raw
    }

    fn recover(raw: &[u8; PAGE_SIZE]) -> Result<RowPageHeader, RowHeaderError> {
        RowPageHeader::recover(Page::from_bytes(u64::from(PN), raw).unwrap())
    }

    #[test]
    fn rotated_anchor_wraps_and_nonzero_slots_do_not_establish_liveness() {
        let sector = make_sector(&[1000, 0, 580, 1500]);
        let raw = store_sector(&sector, 511, 238, 253, 1);
        let h = recover(&raw).unwrap();
        assert_eq!(h.sector0(), &sector);
        assert_eq!((h.rotation(), h.base(), h.step()), (511, 238, 253));
        assert_eq!((h.page_number(), h.owner_id(), h.page_kind()), (PN, 7, 3));
        assert_eq!((h.slot_count(), h.directory_prefix_count()), (4, 1));
        assert_eq!(h.directory_prefix_matches(), Some(true));
        assert_eq!(h.live_count(), h.directory_prefix_count());
        assert!(h.directory_complete());
        assert_eq!(
            h.sector0_slot_starts(),
            &[Some(1028), None, Some(608), Some(1528)]
        );
    }

    #[test]
    fn does_not_invent_slots_beyond_the_sector_boundary() {
        let mut s = make_sector(&[0; 242]);
        s[20..22].copy_from_slice(&1000u16.to_le_bytes());
        s[22..24].copy_from_slice(&244u16.to_le_bytes());
        let raw = store_sector(&s, 37, 23, 73, 2);
        let h = recover(&raw).unwrap();
        assert!(!h.directory_complete());
        assert_eq!(h.slot_count(), 244);
        assert_eq!(h.sector0_slot_starts(), &[None; 242]);
        // The first visible entry already contradicts this stored prefix.
        assert_eq!(h.directory_prefix_matches(), Some(false));
        assert!(h.physical_rows().is_none());
        // Only two unknown slots could account for the trailer, not three.
        assert!(matches!(
            recover(&store_sector(&s, 37, 23, 73, 3)),
            Err(RowHeaderError::NoMatch { .. })
        ));
    }

    #[test]
    fn directory_prefix_is_the_first_vacancy_or_the_full_slot_count() {
        for (slots, stored, agrees) in [
            (&[900, 700, 0, 1100, 0, 1500][..], 2, true),
            (&[900, 700, 0, 1100, 0, 1500][..], 3, false),
            (&[0, 1200, 1500][..], 0, true),
            (&[1200, 1500][..], 2, true),
            (&[1200, 1500][..], 1, false),
            (&[][..], 0, true),
        ] {
            let page = recover(&store_sector(&make_sector(slots), 37, 23, 73, stored)).unwrap();
            assert_eq!(page.directory_prefix_count(), stored);
            assert_eq!(page.directory_prefix_matches(), Some(agrees));
        }
    }

    #[test]
    fn incomplete_directory_only_reports_what_its_known_prefix_establishes() {
        // The suffix extends beyond the directory solver's supported sector.
        let mut slots: Vec<u16> = (0..520).map(|i| 1100 + 2 * i).collect();
        for (vacancy, stored, want) in [
            (None, 301, None),
            (None, 242, None),
            (None, 240, Some(false)),
            (Some(100), 100, Some(true)),
            (Some(100), 240, Some(false)),
        ] {
            if let Some(index) = vacancy {
                slots[index] = 0;
            }
            let h = recover(&store_sector(&make_sector(&slots), 37, 23, 73, stored)).unwrap();
            assert!(h.complete_slot_starts().is_none());
            assert_eq!(h.directory_prefix_count(), stored);
            assert_eq!(h.directory_prefix_matches(), want);
        }
    }

    #[test]
    fn physical_rows_keep_original_slot_numbers_and_verify_sector_zero_lengths() {
        let mut s = make_sector(&[472, 0, 120, 60]);
        s[88..90].copy_from_slice(&60u16.to_le_bytes());
        // Starts 148 and 500 delimit a 352-byte row. Deliberately store a
        // different length to ensure callers can distinguish damaged rows.
        s[148..150].copy_from_slice(&351u16.to_le_bytes());
        let h = recover(&store_sector(&s, 511, 210, 87, 2)).unwrap();
        let rows = h.physical_rows().unwrap();
        assert_eq!(rows.iter().map(|r| r.slot()).collect::<Vec<_>>(), [3, 2, 0]);
        assert_eq!(rows[0].sector0_bytes().unwrap(), Some(&s[88..148]));
        let error = rows[1].sector0_bytes().unwrap_err();
        assert_eq!(
            (error.slot, error.expected, error.stored),
            (2, 352, Some(351))
        );
        assert_eq!((rows[2].start(), rows[2].end()), (500, 4092));
        assert!(rows[2].sector0_bytes().unwrap().is_none());
    }

    #[test]
    fn invalid_directory_candidates_are_rejected() {
        for slots in [&[12u16, 2][..], &[1000, 1000], &[4063], &[u16::MAX]] {
            let raw = store_sector(&make_sector(slots), 37, 23, 73, 1);
            assert!(matches!(recover(&raw), Err(RowHeaderError::NoMatch { .. })));
        }
        let mut s = make_sector(&[900, 700]);
        s[20..22].copy_from_slice(&900u16.to_le_bytes());
        assert!(matches!(
            recover(&store_sector(&s, 37, 23, 73, 2)),
            Err(RowHeaderError::NoMatch { .. })
        ));
        let s = make_sector(&[0, 900]);
        assert!(matches!(
            recover(&store_sector(&s, 37, 23, 73, 2)),
            Err(RowHeaderError::NoMatch { .. })
        ));
    }

    #[test]
    fn duplicate_page_number_is_ambiguous_even_at_a_nonheader_offset() {
        let mut s = make_sector(&[1000]);
        s[126..130].copy_from_slice(&PN.to_le_bytes());
        assert!(matches!(
            recover(&store_sector(&s, 37, 23, 73, 1)),
            Err(RowHeaderError::Ambiguous { .. })
        ));
    }

    #[test]
    fn repeated_lob_header_needs_an_independent_owner_and_present_bounded_slot() {
        let mut sector = make_sector(&[0, 1000, 1500]);
        sector[17] = 0x14;
        sector[126..130].copy_from_slice(&PN.to_le_bytes());
        let raw = store_sector(&sector, 37, 23, 73, 0);
        let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
        assert!(matches!(
            RowPageHeader::recover(page),
            Err(RowHeaderError::Ambiguous { .. })
        ));
        let recovered = RowPageHeader::sole_repeated_lob(page, 7, 1)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.sector0(), &sector);
        for (owner, slot) in [(8, 1), (7, 0), (7, 3)] {
            assert!(
                RowPageHeader::sole_repeated_lob(page, owner, slot)
                    .unwrap()
                    .is_none()
            );
        }
        let mut ordinary = sector;
        ordinary[17] = 3;
        let raw = store_sector(&ordinary, 37, 23, 73, 0);
        assert!(
            RowPageHeader::sole_repeated_lob(Page::from_bytes(u64::from(PN), &raw).unwrap(), 7, 1)
                .unwrap()
                .is_none()
        );
        let raw = store_sector(&sector, 37, 23, 73, 1);
        assert!(
            RowPageHeader::sole_repeated_lob(Page::from_bytes(u64::from(PN), &raw).unwrap(), 7, 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn repeated_lob_reference_cannot_choose_between_keys_or_ignore_source_integrity() {
        let mut sector = make_sector(&[1000]);
        sector[17] = 0x14;
        sector[126..130].copy_from_slice(&PN.to_le_bytes());
        let mut raw = store_sector(&sector, 37, 23, 73, 1);
        let mut other = sector;
        other[24..28].copy_from_slice(&8u32.to_le_bytes());
        let alternative = store_sector(&other, 161, 209, 121, 1);
        raw[161..191].copy_from_slice(&alternative[161..191]);
        seal(&mut raw);
        let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
        assert!(RowPageHeader::structural_candidates(page).unwrap().count() > 1);
        assert!(
            RowPageHeader::sole_repeated_lob(page, 7, 0)
                .unwrap()
                .is_none()
        );
        let mut raw = store_sector(&sector, 37, 23, 73, 1);
        raw[512] ^= 1;
        assert!(matches!(
            RowPageHeader::sole_repeated_lob(Page::from_bytes(u64::from(PN), &raw).unwrap(), 7, 0),
            Err(RowHeaderError::Integrity(Error::BadCrc { .. }))
        ));
    }

    #[test]
    fn mapped_owner_records_extra_numbers_without_electing_another_key() {
        let mut sector = make_sector(&[1000]);
        sector[24..28].copy_from_slice(&PN.to_le_bytes());
        let raw = store_sector(&sector, 511, 238, 253, 1);
        let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
        assert!(matches!(
            RowPageHeader::recover(page),
            Err(RowHeaderError::Ambiguous { .. })
        ));
        let header = RowPageHeader::recover_for_owner(page, PN).unwrap();
        assert_eq!(header.sector0(), &sector);
        assert!(header.uses_owner_anchor());
        assert_eq!(header.mapped_number_offsets(), [24]);
        assert!(matches!(
            RowPageHeader::recover_for_owner(page, PN + 1),
            Err(RowHeaderError::Ambiguous { .. })
        ));
        assert!(
            !recover(&store_sector(&make_sector(&[1000]), 37, 23, 73, 1))
                .unwrap()
                .uses_owner_anchor()
        );
        for at in [6, 126, 400] {
            let mut extra = sector;
            extra[at..at + 4].copy_from_slice(&PN.to_le_bytes());
            let stored = store_sector(&extra, 37, 23, 73, 1);
            let page = Page::from_bytes(u64::from(PN), &stored).unwrap();
            assert!(matches!(
                RowPageHeader::recover(page),
                Err(RowHeaderError::Ambiguous { .. })
            ));
            let header = RowPageHeader::recover_for_owner(page, PN).unwrap();
            assert!(!header.uses_owner_anchor());
            let mut expected = vec![24, at as u16];
            expected.sort_unstable();
            assert_eq!(header.mapped_number_offsets(), expected);
        }
    }

    #[test]
    fn mapped_owner_must_come_from_outside_the_repeated_number() {
        let mut sector = make_sector(&[1000]);
        sector[126..130].copy_from_slice(&PN.to_le_bytes());
        let raw = store_sector(&sector, 37, 23, 73, 1);
        let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
        assert!(matches!(
            RowPageHeader::recover(page),
            Err(RowHeaderError::Ambiguous { .. })
        ));
        let header = RowPageHeader::recover_for_owner(page, 7).unwrap();
        assert_eq!(header.owner_id(), 7);
        assert_eq!(header.mapped_number_offsets(), [126]);
        assert!(!header.uses_owner_anchor());
        assert!(matches!(
            RowPageHeader::recover_for_owner(page, 8),
            Err(RowHeaderError::Ambiguous { .. })
        ));
    }

    #[test]
    fn owner_anchor_requires_complete_agreeing_directory_and_ordinary_kind() {
        for (slots, kind, prefix) in [
            (vec![1000, 1500], 3, 1),
            (vec![1000], 0x12, 1),
            ((0..520).map(|i| 1100 + 2 * i).collect(), 3, 301),
        ] {
            let mut sector = make_sector(&slots);
            sector[24..28].copy_from_slice(&PN.to_le_bytes());
            sector[17] = kind;
            let raw = store_sector(&sector, 37, 23, 73, prefix);
            let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
            assert!(RowPageHeader::recover_for_owner(page, PN).is_err());
        }
    }

    #[test]
    fn owner_anchor_cannot_select_between_structural_keys_or_bypass_integrity() {
        let mut sector = make_sector(&[1000]);
        sector[24..28].copy_from_slice(&PN.to_le_bytes());
        let mut raw = store_sector(&sector, 37, 23, 73, 1);
        let alt = store_sector(&sector, 161, 209, 121, 1);
        raw[161..191].copy_from_slice(&alt[161..191]);
        seal(&mut raw);
        let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
        assert!(RowPageHeader::structural_candidates(page).unwrap().count() > 1);
        assert!(matches!(
            RowPageHeader::recover_for_owner(page, PN),
            Err(RowHeaderError::Ambiguous { .. })
        ));
        let mut raw = store_sector(&sector, 37, 23, 73, 1);
        raw[512] ^= 1;
        assert!(matches!(
            RowPageHeader::recover_for_owner(Page::from_bytes(u64::from(PN), &raw).unwrap(), PN),
            Err(RowHeaderError::Integrity(Error::BadCrc { .. }))
        ));
        raw[4083] = 1;
        seal(&mut raw);
        assert!(matches!(
            RowPageHeader::recover_for_owner(Page::from_bytes(u64::from(PN), &raw).unwrap(), PN),
            Err(RowHeaderError::Integrity(Error::BadTrailer { .. }))
        ));
    }

    #[test]
    fn two_different_valid_keys_are_ambiguous() {
        let s = make_sector(&[1000]);
        let mut raw = store_sector(&s, 37, 23, 73, 1);
        let alt = store_sector(&s, 161, 209, 121, 1);
        raw[161..191].copy_from_slice(&alt[161..191]);
        seal(&mut raw);
        assert!(matches!(
            recover(&raw),
            Err(RowHeaderError::Ambiguous { .. })
        ));
    }

    #[test]
    fn validates_physical_identity_integrity_and_type_before_reporting_a_header() {
        let mut raw = store_sector(&make_sector(&[1000]), 37, 23, 73, 1);
        let page = |index, raw| Page::from_bytes(index, raw).unwrap();
        assert!(matches!(
            RowPageHeader::recover(page(u64::from(PN) + 1, &raw)),
            Err(RowHeaderError::NoMatch { .. })
        ));
        assert!(matches!(
            RowPageHeader::recover(page(u64::from(u32::MAX) + 1, &raw)),
            Err(RowHeaderError::UnsupportedPageNumber { .. })
        ));
        raw[512] ^= 1;
        assert!(matches!(
            recover(&raw),
            Err(RowHeaderError::Integrity(Error::BadCrc { .. }))
        ));
        raw[4083] = 1;
        seal(&mut raw);
        assert!(matches!(
            recover(&raw),
            Err(RowHeaderError::Integrity(Error::BadTrailer { .. }))
        ));
        raw[4082] = b'I';
        seal(&mut raw);
        assert!(matches!(
            recover(&raw),
            Err(RowHeaderError::NotRowPage { .. })
        ));
    }

    #[test]
    fn recognizes_structural_row_pages_across_trailer_families() {
        let mut raw = store_sector(&make_sector(&[1000]), 37, 23, 73, 1);
        for kind in b"AaEeGg" {
            raw[4082] = *kind;
            seal(&mut raw);
            assert_eq!(recover(&raw).unwrap().slot_count(), 1);
        }
        raw[..512].fill(0);
        seal(&mut raw);
        assert!(matches!(recover(&raw), Err(RowHeaderError::NoMatch { .. })));
    }
}
