//! Complete the slot directory when it ends in sector one. Directory bounds
//! select a proposed suffix, independently recovered length words check it.

use crate::row::sector::{RowSectorRecovery, match_sector, visit_sector_candidates};
use crate::{Page, RowPageHeader, SECTOR_SIZE};

const SLOT_ARRAY: usize = 28;
const ROW_END: usize = 4092;

struct Proposed {
    slots: Vec<Option<u16>>,
    // Available only if structural checks agree on the entire sector before
    // using any row lengths. This enables an independent length check.
    sector: Option<[u8; SECTOR_SIZE]>,
}

pub(crate) fn complete(page: Page<'_>, header: &RowPageHeader) -> Option<Vec<Option<u16>>> {
    let count = usize::from(header.slot_count());
    let directory_end = SLOT_ARRAY + 2 * count;
    if !(SECTOR_SIZE + 1..=2 * SECTOR_SIZE).contains(&directory_end) {
        return None;
    }
    let mut proposed: Option<Proposed> = None;
    visit_sector_candidates(page, header, 1, |decode| {
        let Some(slots) = candidate_slots(header, directory_end, decode) else {
            return Ok(());
        };
        match &mut proposed {
            None => {
                proposed = Some(Proposed {
                    slots,
                    sector: Some(std::array::from_fn(decode)),
                })
            }
            Some(previous) if previous.slots != slots => return Err(()),
            Some(previous) => {
                if previous
                    .sector
                    .as_ref()
                    .is_some_and(|s| (0..SECTOR_SIZE).any(|i| s[i] != decode(i)))
                {
                    previous.sector = None;
                }
            }
        }
        Ok(())
    })
    .ok()?;
    let proposed = proposed?;
    corroborated(page, header, &proposed).then_some(proposed.slots)
}

fn candidate_slots(
    header: &RowPageHeader,
    directory_end: usize,
    decode: impl Fn(usize) -> u8,
) -> Option<Vec<Option<u16>>> {
    let mut slots = header.sector0_slot_starts().to_vec();
    for off in (0..directory_end - SECTOR_SIZE).step_by(2) {
        let word = u16::from_le_bytes([decode(off), decode(off + 1)]);
        if word == 0 {
            slots.push(None);
        } else {
            let start = SLOT_ARRAY + usize::from(word);
            if !(directory_end..=ROW_END - 2).contains(&start) {
                return None;
            }
            slots.push(Some(start as u16));
        }
    }
    let mut starts: Vec<_> = slots.iter().flatten().copied().collect();
    starts.sort_unstable();
    let header_min = u16::from_le_bytes([header.sector0()[20], header.sector0()[21]]);
    if starts.first().copied().map(usize::from) != Some(SLOT_ARRAY + usize::from(header_min))
        || starts.len() < usize::from(header.live_count())
        || starts.windows(2).any(|pair| pair[1] - pair[0] < 2)
    {
        return None;
    }
    Some(slots)
}

fn corroborated(page: Page<'_>, header: &RowPageHeader, proposed: &Proposed) -> bool {
    let prefix_len = header.sector0_slot_starts().len();
    let mut ordered: Vec<_> = proposed
        .slots
        .iter()
        .enumerate()
        .filter_map(|(slot, start)| start.map(|at| (usize::from(at), slot)))
        .collect();
    ordered.sort_unstable();
    let mut prefix_spans = Vec::new();
    let mut held_out = Vec::new();
    let mut structural_checks = 0;
    for (i, &(start, slot)) in ordered.iter().enumerate() {
        let (end, next_slot) = ordered.get(i + 1).copied().unwrap_or((ROW_END, 0));
        let length = (end - start) as u16;
        if let Some(bytes) = &proposed.sector {
            for (j, expected) in length.to_le_bytes().into_iter().enumerate() {
                let pos = start + j;
                if (SECTOR_SIZE..2 * SECTOR_SIZE).contains(&pos)
                    && bytes[pos - SECTOR_SIZE] != expected
                {
                    return false;
                }
            }
            if (SECTOR_SIZE..2 * SECTOR_SIZE - 1).contains(&start) {
                structural_checks += 1;
            }
        }
        // Anchors with both endpoints in the old prefix are kept separate
        // from words whose start or end was supplied by the proposed suffix.
        if slot < prefix_len && next_slot < prefix_len {
            prefix_spans.push((start, length));
        } else {
            held_out.push((start, length));
        }
    }
    let increment = header.step().wrapping_mul(header.rotation() as u8);
    let mut directly_confirmed = false;
    let mut confirmed_words = 0;
    for sector in 1..=6 {
        let from = sector * SECTOR_SIZE;
        let to = from + SECTOR_SIZE;
        let raw = &page.bytes()[from..to];
        let bytes = match match_sector(raw, from, header.base(), increment, &prefix_spans) {
            RowSectorRecovery::Unique(c) => c.candidate_bytes(),
            RowSectorRecovery::Equivalent { bytes, .. } => *bytes,
            RowSectorRecovery::NoMatch { .. } | RowSectorRecovery::Unmodeled { .. } => {
                return false;
            }
            _ => continue,
        };
        if sector == 1 {
            for (i, slot) in proposed.slots[prefix_len..].iter().enumerate() {
                let word = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
                if usize::from(word) != slot.map_or(0, |at| usize::from(at) - SLOT_ARRAY) {
                    return false;
                }
            }
            directly_confirmed = true;
        }
        for &(start, length) in &held_out {
            for (j, expected) in length.to_le_bytes().into_iter().enumerate() {
                let pos = start + j;
                if (from..to).contains(&pos) && bytes[pos - from] != expected {
                    return false;
                }
            }
            if (from..to - 1).contains(&start) {
                confirmed_words += 1;
            }
        }
    }
    directly_confirmed || structural_checks >= 2 || confirmed_words >= 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::row::sector::inverse_odd;
    use crate::{PAGE_SIZE, RowSectorReader, RowSlotRecovery};

    const PN: u32 = 0x102_0304;
    const R0: usize = 55;
    const B0: u8 = 41;
    const STEP: u8 = 47;

    fn word(data: &mut [u8], at: usize, number: usize) {
        data[at..at + 2].copy_from_slice(&(number as u16).to_le_bytes());
    }

    fn directory() -> Vec<Option<u16>> {
        let mut slots = vec![None; 260];
        for (i, offset) in [620, 680, 710, 850, 921, 1044, 1201, 1281, 1401, 1521]
            .into_iter()
            .enumerate()
        {
            slots[i] = Some(offset);
        }
        // Suffix order is intentionally unrelated to physical offset order.
        for (i, offset) in [
            1903, 770, 1630, 1130, 1740, 2180, 2010, 2455, 2310, 2540, 2660, 2700, 2850, 2800,
            3000, 3180, 3310, 3440,
        ]
        .into_iter()
        .enumerate()
        {
            slots[242 + i] = Some(offset);
        }
        slots
    }

    fn fixture(slots: &[Option<u16>], bad_length: Option<usize>, rival: bool) -> [u8; PAGE_SIZE] {
        let mut logical =
            std::array::from_fn::<_, PAGE_SIZE, _>(|i| ((i * i * 3 + 19 * i + 29) / 7) as u8);
        logical[..4].copy_from_slice(&PN.to_le_bytes());
        logical[16] = 4;
        logical[17] = 3;
        let mut sorted: Vec<_> = slots.iter().flatten().map(|&v| usize::from(v)).collect();
        sorted.sort_unstable();
        word(&mut logical, 20, sorted[0] - SLOT_ARRAY);
        word(&mut logical, 22, slots.len());
        logical[24..28].copy_from_slice(&93u32.to_le_bytes());
        for (i, s) in slots.iter().enumerate() {
            word(
                &mut logical,
                SLOT_ARRAY + i * 2,
                s.map_or(0, |v| usize::from(v) - SLOT_ARRAY),
            );
        }
        for (i, &start) in sorted.iter().enumerate() {
            let length = sorted.get(i + 1).copied().unwrap_or(ROW_END) - start;
            word(
                &mut logical,
                start,
                length + usize::from(bad_length == Some(start)),
            );
        }
        let mut raw = [0u8; PAGE_SIZE];
        let d = STEP.wrapping_mul(R0 as u8);
        for sector in 0..7 {
            let r = if sector == 0 { R0 } else { 51 + sector * 8 };
            let step = d.wrapping_mul(inverse_odd(r as u8));
            for j in 0..SECTOR_SIZE {
                let i = (r + j) % SECTOR_SIZE;
                raw[sector * SECTOR_SIZE + i] = logical[sector * SECTOR_SIZE + j]
                    .wrapping_add(B0 + sector as u8)
                    .wrapping_add((i as u8).wrapping_mul(step));
            }
        }
        if rival {
            // Install another structurally valid directory at disjoint stored
            // positions under a second modeled key. Row lengths must not choose
            // between conflicting directory starts.
            let r = 359usize;
            let step = d.wrapping_mul(inverse_odd(r as u8));
            for (n, s) in slots[242..].iter().enumerate() {
                let v = s.map_or(0, |v| v + 2 - SLOT_ARRAY as u16);
                for (j, b) in v.to_le_bytes().into_iter().enumerate() {
                    let i = (r + 2 * n + j) % SECTOR_SIZE;
                    raw[SECTOR_SIZE + i] = b
                        .wrapping_add(B0 + 1)
                        .wrapping_add((i as u8).wrapping_mul(step));
                }
            }
        }
        word(&mut raw, 4080, sorted.len());
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    #[test]
    fn appends_corroborated_slots_without_changing_the_first_sector_view() {
        let expected = directory();
        let raw = fixture(&expected, None, false);
        let page = Page::from_bytes(u64::from(PN), &raw).unwrap();
        let reader = RowSectorReader::new(page).unwrap();
        let h = reader.header();
        assert!(!h.directory_complete());
        assert_eq!(h.sector0_slot_starts(), &expected[..242]);
        assert_eq!(h.complete_slot_starts(), Some(&expected[..]));
        let row = h
            .physical_rows()
            .unwrap()
            .into_iter()
            .find(|r| r.slot() == 243)
            .unwrap();
        assert_eq!((row.start(), row.end()), (770, 850));
        assert!(matches!(
            reader.read_slot(243),
            Some(RowSlotRecovery::Candidate { start: 770, .. })
        ));
    }

    #[test]
    fn disagreed_length_or_competing_suffix_leaves_the_directory_partial() {
        let slots = directory();
        for raw in [
            fixture(&slots, Some(770), false),
            fixture(&slots, None, true),
        ] {
            let h = RowPageHeader::recover(Page::from_bytes(u64::from(PN), &raw).unwrap()).unwrap();
            assert_eq!(h.sector0_slot_starts(), &slots[..242]);
            assert!(h.complete_slot_starts().is_none());
            assert!(h.physical_rows().is_none());
        }
    }

    #[test]
    fn beyond_supported_directory_or_absent_independent_checks_never_extends_prefix() {
        let mut long = vec![None; 499];
        long[0] = Some(3200);
        long[498] = Some(3500);
        let mut unwitnessed = vec![None; 260];
        for (i, off) in (3800..3980).step_by(10).enumerate() {
            unwitnessed[242 + i] = Some(off);
        }
        for slots in [long, unwitnessed] {
            let raw = fixture(&slots, None, false);
            let h = RowPageHeader::recover(Page::from_bytes(u64::from(PN), &raw).unwrap()).unwrap();
            assert!(!h.directory_complete());
            assert!(h.complete_slot_starts().is_none());
        }
    }
}
