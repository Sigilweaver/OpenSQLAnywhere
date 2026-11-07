//! Bitmap-specific recovery for zero-word sectors of an exact terminal
//! ISYSTAB chunk. Select by bounded exhaustive bitmap decoding first. Check
//! row lengths and physical page owners only after the payload is unique.

use std::collections::BTreeMap;
use std::ops::Range;

use super::{PageBitmapError, TableMapRead, TablePageBitmap, words};
use crate::record::long_value::check_reference;
use crate::row::sector::{LocalEvidence, visit_sector_candidates};
use crate::row::tail::STASH_START;
use crate::{
    CalibratedPage, CalibratedStore, LongDescriptor, Page, PageStore, PhysicalRow, RowPageHeader,
    RowSectorReader, RowSectorRecovery, RowTail, RowTailError, SECTOR_SIZE,
};

/// A complete bitmap literal directly governed by a length-unanchored sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapLiteralWitness {
    /// Byte offset in the logical bitmap payload of the 32-bit literal.
    pub payload_offset: usize,
    /// A set bit whose physical row page verifies the expected owner.
    pub member_page: u32,
    /// A supported alternative for those same four bytes would set this bit.
    /// Independent evidence excludes that page from this row map: either a
    /// recovered foreign row owner, a supported foreign overflow header, or
    /// a CRC- and trailer-checked stored I-page type outside the row families.
    pub alternative_page: u32,
}

/// Two distinct member pages used to corroborate one recovered sector's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapSectorWitness {
    /// Physical sector number, from 1 through 7.
    pub sector: u8,
    /// Independent positive/negative physical membership evidence.
    pub literals: [BitmapLiteralWitness; 2],
}

const MAX_PREFIXES: usize = 32;
const MAX_TRIALS: usize = 200_000;

/// For each distinct slice of the bitmap payload, remember whether *every*
/// generating key matched the available physical length bytes. This flag
/// must never select between different payloads.
struct Region {
    sector: u8,
    payload: Range<usize>,
    unanchored: bool,
    calibrated: bool,
    choices: BTreeMap<Vec<u8>, bool>,
}

pub(super) fn recover(
    store: &CalibratedStore<'_>,
    descriptor: &LongDescriptor<'_>,
    declared_pages: u32,
    owner: u32,
    previous: PageBitmapError,
    claims: Option<&super::CatalogPageClaims<'_, '_>>,
) -> Result<TableMapRead, PageBitmapError> {
    if declared_pages == 0 || descriptor.domain != 31 {
        return Err(previous);
    }
    check_reference(store.store(), descriptor)?;
    let raw = store.store().page(u64::from(descriptor.first_page))?;
    let calibrated =
        store
            .page(descriptor.first_page)
            .map_err(|source| PageBitmapError::Header {
                page: descriptor.first_page,
                source,
            })?;
    let header = calibrated.header();
    if header.owner_id() != 1 || !(0x11..=0x14).contains(&header.page_kind()) {
        return Err(previous);
    }
    let rows = header
        .physical_rows()
        .ok_or(PageBitmapError::SparseBounds)?;
    let row = rows
        .iter()
        .find(|r| r.slot() == descriptor.slot)
        .ok_or(PageBitmapError::SparseBounds)?;
    let length = descriptor.total_len as usize;
    if row.length().checked_sub(3) != Some(length)
        || length == 0
        || !length.is_multiple_of(4)
        || descriptor.prefix.len() > length
        || rows.iter().any(|r| r.length() < 2)
    {
        return Err(previous);
    }
    let ordinary = RowSectorReader::from_header(raw, header.clone());
    let span = row.start()..row.end();
    let mut parts = Vec::new();
    for sector in span.start / SECTOR_SIZE..=(span.end - 1) / SECTOR_SIZE {
        let base = sector * SECTOR_SIZE;
        let end = span.end.min(base + SECTOR_SIZE).min(STASH_START);
        let range = span.start.max(base)..end;
        if !range.is_empty() {
            let region = match sector {
                0 => known_region(sector, &span, range, &rows, header.sector0(), false),
                7 => match RowTail::recover_from_header(raw, header) {
                    Ok(tail) => {
                        known_region(sector, &span, range, &rows, &tail.bytes()[..496], false)
                    }
                    Err(RowTailError::InsufficientAnchors { count: 0, .. }) => {
                        unanchored_region(raw, header, sector, &span, range, &rows)?
                    }
                    Err(RowTailError::InsufficientAnchors { count, .. }) => calibrated_region(
                        &calibrated,
                        sector,
                        LocalEvidence::Sparse(count),
                        &span,
                        range,
                        &rows,
                    )?,
                    Err(RowTailError::Ambiguous { .. }) => calibrated_region(
                        &calibrated,
                        sector,
                        LocalEvidence::Ambiguous,
                        &span,
                        range,
                        &rows,
                    )?,
                    Err(_) => return Err(previous),
                },
                _ => match ordinary.recover(sector) {
                    Some(RowSectorRecovery::Unique(key)) => {
                        known_region(sector, &span, range, &rows, &key.candidate_bytes(), false)
                    }
                    Some(RowSectorRecovery::Equivalent { bytes, .. }) => {
                        known_region(sector, &span, range, &rows, bytes.as_ref(), false)
                    }
                    Some(RowSectorRecovery::InsufficientLengths { words: 0 }) => {
                        unanchored_region(raw, header, sector, &span, range, &rows)?
                    }
                    Some(RowSectorRecovery::InsufficientLengths { words }) => calibrated_region(
                        &calibrated,
                        sector,
                        LocalEvidence::Sparse(words),
                        &span,
                        range,
                        &rows,
                    )?,
                    Some(RowSectorRecovery::Ambiguous { .. }) => calibrated_region(
                        &calibrated,
                        sector,
                        LocalEvidence::Ambiguous,
                        &span,
                        range,
                        &rows,
                    )?,
                    _ => return Err(previous),
                },
            };
            parts.push(region);
        }
    }
    if span.end > STASH_START {
        let range = span.start.max(STASH_START)..span.end;
        parts.push(known_region(
            8,
            &span,
            range,
            &rows,
            &header.row_tail_stash(),
            false,
        ));
    }
    if !parts.iter().any(|part| part.unanchored) {
        return Err(previous);
    }
    let physical = store.store().page_count();
    let mut candidates =
        payload_candidates(&parts, length, physical, declared_pages, descriptor.prefix)?;
    let (payload, conflict_witnesses) = if candidates.len() == 1 {
        (candidates.pop().expect("one complete payload"), Vec::new())
    } else {
        let registry = claims.ok_or(PageBitmapError::AmbiguousSparseMap)?;
        registry.select(candidates, descriptor, declared_pages, owner)?
    };
    // Stored lengths and the positive/negative literal witnesses were held
    // out of both the initial search and any conflict-based elimination.
    for part in &parts {
        if part.choices.get(&payload[part.payload.clone()]) != Some(&true) {
            return Err(PageBitmapError::NoBitmapWitness);
        }
    }
    let bitmap = TablePageBitmap::decode(&payload, physical, declared_pages)?;
    let counts = bitmap.verify_owner(store.store(), owner)?;
    let literal_witnesses =
        confirm_literals(&payload, &parts, store.store(), owner, &conflict_witnesses)?;
    Ok(TableMapRead {
        empty_allocation: None,
        linked_map: None,
        bitmap,
        counts,
        calibrated_sector_uses: parts.iter().filter(|p| p.calibrated).count(),
        repeated_map_header: false,
        literal_witnesses,
        conflict_witnesses,
    })
}

fn region_base(sector: usize) -> usize {
    (sector * SECTOR_SIZE).min(STASH_START)
}

fn region_end(sector: usize) -> usize {
    if sector == 8 {
        4092
    } else {
        ((sector + 1) * SECTOR_SIZE).min(STASH_START)
    }
}

fn region(
    sector: usize,
    span: &Range<usize>,
    range: &Range<usize>,
    unanchored: bool,
    calibrated: bool,
) -> Region {
    let payload_start = span.start + 3;
    Region {
        sector: sector as u8,
        payload: range.start.saturating_sub(payload_start)..range.end.saturating_sub(payload_start),
        unanchored,
        calibrated,
        choices: BTreeMap::new(),
    }
}

fn lengths(sector: usize, rows: &[PhysicalRow<'_>]) -> Vec<(usize, u8)> {
    let base = region_base(sector);
    let end = region_end(sector);
    let mut result = Vec::new();
    for row in rows {
        for (j, value) in (row.length() as u16).to_le_bytes().into_iter().enumerate() {
            let pos = row.start() + j;
            if (base..end).contains(&pos) {
                result.push((pos - base, value));
            }
        }
    }
    result
}

fn add_choice(
    part: &mut Region,
    span: &Range<usize>,
    range: &Range<usize>,
    constraints: &[(usize, u8)],
    decode: &dyn Fn(usize) -> u8,
) {
    let base = region_base(usize::from(part.sector));
    if range.contains(&(span.start + 2)) && decode(span.start + 2 - base) != 0 {
        return;
    }
    let bytes = (range.start.max(span.start + 3)..range.end)
        .map(|p| decode(p - base))
        .collect();
    let matches = constraints
        .iter()
        .all(|&(at, expected)| decode(at) == expected);
    part.choices
        .entry(bytes)
        .and_modify(|ok| *ok &= matches)
        .or_insert(matches);
}

fn known_region(
    sector: usize,
    span: &Range<usize>,
    range: Range<usize>,
    rows: &[PhysicalRow<'_>],
    bytes: &[u8],
    calibrated: bool,
) -> Region {
    let mut part = region(sector, span, &range, false, calibrated);
    add_choice(&mut part, span, &range, &lengths(sector, rows), &|i| {
        bytes[i]
    });
    part
}

fn calibrated_region(
    cal: &CalibratedPage<'_, '_>,
    sector: usize,
    local: LocalEvidence,
    span: &Range<usize>,
    range: Range<usize>,
    rows: &[PhysicalRow<'_>],
) -> Result<Region, PageBitmapError> {
    let bytes = cal
        .anchored_region(sector, local)
        .map_err(|_| PageBitmapError::SparseBounds)?;
    Ok(known_region(sector, span, range, rows, bytes, true))
}

fn unanchored_region(
    page: Page<'_>,
    h: &RowPageHeader,
    sector: usize,
    span: &Range<usize>,
    range: Range<usize>,
    rows: &[PhysicalRow<'_>],
) -> Result<Region, PageBitmapError> {
    let mut part = region(sector, span, &range, true, false);
    let constraints = lengths(sector, rows);
    visit_sector_candidates::<PageBitmapError>(page, h, sector, |decode| {
        add_choice(&mut part, span, &range, &constraints, decode);
        Ok(())
    })?;
    Ok(part)
}

fn payload_candidates(
    parts: &[Region],
    length: usize,
    physical: u64,
    declared: u32,
    prefix: &[u8],
) -> Result<Vec<Vec<u8>>, PageBitmapError> {
    let mut frontier = vec![Vec::new()];
    let mut trials = 0;
    for part in parts {
        let mut next = Vec::new();
        for mut data in frontier {
            let start = data.len();
            for bytes in part.choices.keys() {
                trials += 1;
                if trials > MAX_TRIALS {
                    return Err(PageBitmapError::SparseSearchLimit);
                }
                data.extend_from_slice(bytes);
                let overlap = prefix.len().min(data.len());
                let valid = data[..overlap] == prefix[..overlap]
                    && words::walk(&data, length, physical, |_, _| Ok(())).is_ok_and(|bits| {
                        bits <= declared && (data.len() < length || bits == declared)
                    });
                if valid {
                    if next.len() >= MAX_PREFIXES {
                        return Err(PageBitmapError::SparseSearchLimit);
                    }
                    next.push(data.clone());
                }
                data.truncate(start);
            }
        }
        if next.is_empty() {
            return Err(PageBitmapError::NoSparseMap);
        }
        frontier = next;
    }
    Ok(frontier)
}

// This evidence is withheld until the complete payload is already unique.
// A checked I-page cannot be a positive row-map member. Other stored types
// still need a recovered foreign row owner; absence of a header proves nothing.
fn excluded_member(
    store: &PageStore,
    owner: u32,
    page: u32,
    cache: &mut BTreeMap<u32, bool>,
) -> bool {
    // Page zero is a superblock, so its bytes at the trailer offsets do not
    // declare a page type even if they happen to contain an ASCII I.
    if page == 0 {
        return false;
    }
    *cache.entry(page).or_insert_with(|| {
        let Ok(stored) = store.page(u64::from(page)) else {
            return false;
        };
        if matches!(stored.trailer().page_type(), crate::PageType::Index) {
            return stored.verify_crc().is_ok() && stored.verify_trailer().is_ok();
        }
        RowPageHeader::recover(stored)
            .ok()
            .is_some_and(|h| h.page_kind() <= 4 && h.owner_id() != owner)
    })
}

fn confirm_literals(
    payload: &[u8],
    parts: &[Region],
    store: &PageStore,
    owner: u32,
    conflicts: &[super::BitmapConflictWitness],
) -> Result<Vec<BitmapSectorWitness>, PageBitmapError> {
    let mut found: Vec<_> = parts
        .iter()
        .filter(|p| p.unanchored)
        .map(|p| (p, Vec::<BitmapLiteralWitness>::new()))
        .collect();
    let mut cache = BTreeMap::new();
    words::walk(
        payload,
        payload.len(),
        store.page_count(),
        |offset, word| {
            if !word.literal || word.bits == 0 {
                return Ok(());
            }
            let Some((part, witnesses)) = found.iter_mut().find(|(p, v)| {
                v.len() < 2 && p.payload.start <= offset && offset + 4 <= p.payload.end
            }) else {
                return Ok(());
            };
            let local = offset - part.payload.start;
            let mut wrong_bits = 0;
            for choice in part.choices.keys() {
                let slice = &choice[local..local + 4];
                wrong_bits |=
                    u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) & !word.bits;
            }
            let base = word.start as u32;
            let negative = (0..32).find(|b| {
                wrong_bits & (1 << b) != 0
                    && !conflicts.iter().any(|w| w.page == base + b)
                    && excluded_member(store, owner, base + b, &mut cache)
            });
            if let Some(bit) = negative {
                for positive in (0..32)
                    .filter(|b| word.bits & (1 << b) != 0)
                    .take(2 - witnesses.len())
                {
                    witnesses.push(BitmapLiteralWitness {
                        payload_offset: offset,
                        member_page: base + positive,
                        alternative_page: base + bit,
                    });
                }
            }
            Ok(())
        },
    )?;
    found
        .into_iter()
        .map(|(part, literals)| {
            let literals = literals
                .try_into()
                .map_err(|_| PageBitmapError::NoBitmapWitness)?;
            Ok(BitmapSectorWitness {
                sector: part.sector,
                literals,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PAGE_SIZE, PhysicalValue};

    fn unique_payload(
        parts: &[Region],
        length: usize,
        physical: u64,
        declared: u32,
        prefix: &[u8],
    ) -> Result<Vec<u8>, PageBitmapError> {
        let mut payloads = payload_candidates(parts, length, physical, declared, prefix)?;
        if payloads.len() != 1 {
            return Err(PageBitmapError::AmbiguousSparseMap);
        }
        Ok(payloads.pop().unwrap())
    }

    fn encoded(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn region_options(start: usize, choices: Vec<Vec<u8>>) -> Region {
        Region {
            sector: 1,
            payload: start..start + choices[0].len(),
            unanchored: true,
            calibrated: false,
            choices: choices.into_iter().map(|bytes| (bytes, true)).collect(),
        }
    }

    #[test]
    fn distinct_encodings_of_the_same_set_remain_ambiguous_before_any_owner_check() {
        // Both representations name only page 1. The second word of zero
        // bits is literal in one representation and a fill in the other.
        let literal = encoded(&[64, 2, 2, 0]);
        let fill = encoded(&[64, 1, 2, 128]);
        assert_eq!(
            TablePageBitmap::decode(&literal, 64, 1).unwrap(),
            TablePageBitmap::decode(&fill, 64, 1).unwrap()
        );
        let alternatives = region_options(0, vec![literal, fill]);
        assert!(matches!(
            unique_payload(&[alternatives], 16, 64, 1, &[]),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
        // Membership and stored length must never eliminate a rival here.
        let mut part = region_options(0, vec![encoded(&[32, 1, 2]), encoded(&[32, 1, 4])]);
        part.choices.insert(encoded(&[32, 1, 4]), false);
        assert!(matches!(
            unique_payload(&[part], 12, 32, 1, &[]),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
    }

    #[test]
    fn excess_live_prefixes_abstain_without_selecting_a_partial_search() {
        let first = region_options(
            0,
            (1..=MAX_PREFIXES + 1)
                .map(|n| encoded(&[(n * 32) as u32]))
                .collect(),
        );
        let second = region_options(4, vec![encoded(&[1, 2])]);
        assert!(matches!(
            unique_payload(&[first, second], 12, 128, 1, &[]),
            Err(PageBitmapError::SparseSearchLimit)
        ));
    }

    #[test]
    fn a_partial_control_or_literal_at_every_byte_boundary_preserves_the_real_payload() {
        let expected = encoded(&[128, 129, 2, 1, 8, 128]); // one empty fill, two literal runs, one empty fill
        for split in 1..expected.len() {
            let first = region_options(0, vec![expected[..split].to_vec()]);
            let second = region_options(split, vec![expected[split..].to_vec()]);
            assert_eq!(
                unique_payload(&[first, second], expected.len(), 128, 2, &[]).unwrap(),
                expected
            );
        }
    }

    fn seal(raw: &mut [u8]) {
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
    }

    fn encode_sector(raw: &mut [u8], logical: &[u8], rotation: usize, base: u8, step: u8) {
        for (i, &byte) in logical.iter().enumerate() {
            let pos = (i + rotation) % SECTOR_SIZE;
            raw[pos] = byte
                .wrapping_add(base)
                .wrapping_add(step.wrapping_mul(pos as u8));
        }
    }

    fn empty_data_page(raw: &mut [u8], number: u32, owner: u32, repeated: bool) {
        let mut header = [0x53; 512];
        header[..4].copy_from_slice(&number.to_le_bytes());
        header[16] = 4;
        header[17] = 3;
        header[20..24].fill(0);
        header[24..28].copy_from_slice(&owner.to_le_bytes());
        if repeated {
            header[390..394].copy_from_slice(&number.to_le_bytes());
        }
        encode_sector(&mut raw[..512], &header, 55, 41, 47);
        raw[4082] = b'E';
        seal(raw);
    }

    fn fixture(bad_body: bool, uncertain_rival: bool) -> (PageStore, Vec<u8>) {
        // Each of the two missing sectors has a literal naming two same-owner
        // pages and another bit with a demonstrably different row owner.
        let mut words = vec![4096];
        for index in 0..127 {
            words.push(1);
            words.push(if index == 0 || index == 64 { 0x30 } else { 0 });
        }
        words.push(128);
        let payload = encoded(&words);
        assert_eq!(payload.len(), 1024);
        let mut all = vec![0; 2056 * PAGE_SIZE];
        let raw = &mut all[2 * PAGE_SIZE..3 * PAGE_SIZE];
        let mut h = [0x53; 512];
        h[..4].copy_from_slice(&2u32.to_le_bytes());
        h[16] = 4;
        h[17] = 0x11;
        h[24..28].copy_from_slice(&1u32.to_le_bytes());
        for (at, n) in [
            (20, 509u16 - 28),
            (22, 2),
            (28, 509 - 28),
            (30, 1536 - 28),
            (509, 1027),
        ] {
            h[at..at + 2].copy_from_slice(&n.to_le_bytes());
        }
        h[511] = 0;
        encode_sector(&mut raw[..512], &h, 55, 41, 47);
        let delta = 55u8.wrapping_mul(47);
        for (sector, rotation) in [(1usize, 73usize), (2, 151)] {
            let step = (0u8..=255)
                .find(|s| s.wrapping_mul(rotation as u8) == delta)
                .unwrap();
            encode_sector(
                &mut raw[sector * 512..(sector + 1) * 512],
                &payload[(sector - 1) * 512..sector * 512],
                rotation,
                41 + sector as u8,
                step,
            );
        }
        if bad_body {
            for byte in &mut raw[512..1024] {
                *byte = byte.wrapping_add(1);
            }
        }
        raw[4080] = 2;
        raw[4082] = b'E';
        seal(raw);
        for (pn, owner) in [
            (4u32, 77),
            (5, 77),
            (6, 91),
            (2052, 77),
            (2053, 77),
            (2054, 92),
        ] {
            let data = &mut all[pn as usize * PAGE_SIZE..][..PAGE_SIZE];
            empty_data_page(data, pn, owner, uncertain_rival && owner != 77);
        }
        (PageStore::from_bytes_unchecked(all).unwrap(), payload)
    }

    fn descriptor(prefix: &[u8]) -> PhysicalValue<'_> {
        PhysicalValue::OutOfRow(LongDescriptor {
            domain: 31,
            tag: 0,
            prefix,
            total_len: 1024,
            first_page: 2,
            unknown: 0,
            slot: 0,
        })
    }

    #[test]
    fn two_zero_word_sectors_require_unique_bytes_and_direct_cross_owner_evidence() {
        let (store, expected) = fixture(false, false);
        let reader = CalibratedStore::new(&store);
        assert!(matches!(
            TablePageBitmap::from_catalog_value_for_owner(&store, &descriptor(&[]), 4, 77),
            Err(PageBitmapError::SparseBounds)
        ));
        let raw = store.page(2).unwrap();
        let h = RowPageHeader::recover(raw).unwrap();
        let rows = h.physical_rows().unwrap();
        let span = 509..1536;
        let parts: Vec<_> = (1..=2)
            .map(|sector| {
                unanchored_region(
                    raw,
                    &h,
                    sector,
                    &span,
                    sector * 512..(sector + 1) * 512,
                    &rows,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            unique_payload(&parts, expected.len(), store.page_count(), 4, &[]).unwrap(),
            expected
        );
        let result = reader.table_page_map(&descriptor(&[]), 4, 77).unwrap();
        assert_eq!(
            result.bitmap,
            TablePageBitmap::decode(&expected, store.page_count(), 4).unwrap()
        );
        assert_eq!(
            result.bitmap.pages().collect::<Vec<_>>(),
            [4, 5, 2052, 2053]
        );
        assert_eq!(result.literal_witnesses.len(), 2);
        for (index, w) in result.literal_witnesses.iter().enumerate() {
            assert_eq!(w.sector as usize, index + 1);
            let expected_base = if index == 0 { 0 } else { 2048 };
            assert_eq!(
                w.literals.map(|x| x.member_page),
                [expected_base + 4, expected_base + 5]
            );
            for literal in w.literals {
                assert_eq!(literal.alternative_page, expected_base + 6);
                assert!(
                    literal.payload_offset >= index * 512
                        && literal.payload_offset + 4 <= (index + 1) * 512
                );
            }
        }
        assert!(reader.table_page_map(&descriptor(&[]), 4, 91).is_err());
        assert!(reader.table_page_map(&descriptor(&[]), 3, 77).is_err());
        assert!(reader.table_page_map(&descriptor(&[32]), 4, 77).is_err());
        let PhysicalValue::OutOfRow(mut swapped) = descriptor(&[]) else {
            unreachable!()
        };
        swapped.slot = 1;
        assert!(
            reader
                .table_page_map(&PhysicalValue::OutOfRow(swapped), 4, 77)
                .is_err()
        );
        let (invalid, _) = fixture(true, false);
        assert!(
            CalibratedStore::new(&invalid)
                .table_page_map(&descriptor(&[]), 4, 77)
                .is_err()
        );
        let (unknown, _) = fixture(false, true);
        assert!(matches!(
            CalibratedStore::new(&unknown).table_page_map(&descriptor(&[]), 4, 77),
            Err(PageBitmapError::NoBitmapWitness)
        ));
    }

    fn with_negative_type(kind: u8, corrupt_crc: bool, bad_trailer: bool) -> PageStore {
        let (source, _) = fixture(false, false);
        let mut bytes: Vec<_> = source
            .pages()
            .flat_map(|p| p.unwrap().bytes().to_vec())
            .collect();
        for pn in [0, 6, 2054] {
            let page = &mut bytes[pn * PAGE_SIZE..(pn + 1) * PAGE_SIZE];
            page.fill(0x5a);
            page[4080..4092].fill(0);
            page[4082] = kind;
            page[4083] = u8::from(bad_trailer);
            seal(page);
            if corrupt_crc {
                page[1000] ^= 1;
            }
        }
        PageStore::from_bytes_unchecked(bytes).unwrap()
    }

    #[test]
    fn checked_i_pages_supply_exclusion_evidence_after_unique_bitmap_selection() {
        for kind in *b"Ii" {
            let store = with_negative_type(kind, false, false);
            let reader = CalibratedStore::new(&store);
            let result = reader.table_page_map(&descriptor(&[]), 4, 77).unwrap();
            assert_eq!(
                result.bitmap.pages().collect::<Vec<_>>(),
                [4, 5, 2052, 2053]
            );
            assert_eq!(result.literal_witnesses.len(), 2);
            for (i, sector) in result.literal_witnesses.iter().enumerate() {
                let base = if i == 0 { 0 } else { 2048 };
                assert_eq!(sector.literals.map(|w| w.member_page), [base + 4, base + 5]);
                assert!(
                    sector
                        .literals
                        .iter()
                        .all(|w| w.alternative_page == base + 6)
                );
            }
            let index_member =
                TablePageBitmap::decode(&encoded(&[32, 1, 1 << 6]), 2056, 1).unwrap();
            assert!(matches!(
                index_member.verify_owner(&store, 77),
                Err(PageBitmapError::Header {
                    source: crate::RowHeaderError::NotRowPage { .. },
                    ..
                })
            ));
            assert!(!excluded_member(&store, 77, 0, &mut BTreeMap::new()));
        }
    }

    #[test]
    fn corrupt_or_unclassified_nonrow_pages_do_not_supply_exclusion_evidence() {
        for (kind, corrupt_crc, bad_trailer) in [
            (b'I', true, false),
            (b'I', false, true),
            (b'Z', false, false),
            (b'A', false, false),
        ] {
            let store = with_negative_type(kind, corrupt_crc, bad_trailer);
            assert!(!excluded_member(&store, 77, 6, &mut BTreeMap::new()));
            assert!(matches!(
                CalibratedStore::new(&store).table_page_map(&descriptor(&[]), 4, 77),
                Err(PageBitmapError::NoBitmapWitness)
            ));
        }
    }
    // Rotations 73 and 329 have the same physical byte step. On this
    // complete sector, they exchange its two halves. Both encodings have
    // exactly two members and a valid 2,048-bit universe.
    fn tie_fixture(uncertain: bool) -> (PageStore, Vec<u8>, Vec<u8>) {
        let mut all = vec![0; 1032 * PAGE_SIZE];
        let positive_bits = 0x30;
        let mut words = vec![2048];
        for w in 0..64 {
            words.extend([1, if w == 0 { positive_bits } else { 0 }]);
        }
        let first = encoded(&words);
        let mut second = first.clone();
        second[4..].rotate_left(256);
        for (pn, start, end, payload) in [
            (2u32, 505usize, 1024usize, first.clone()),
            (3, 160, 175, encoded(&[1056, 4097, positive_bits])),
        ] {
            let raw = &mut all[pn as usize * PAGE_SIZE..][..PAGE_SIZE];
            let mut header = [0x53; 512];
            header[..4].copy_from_slice(&pn.to_le_bytes());
            header[16] = 4;
            header[17] = 0x11;
            header[24..28].copy_from_slice(&1u32.to_le_bytes());
            for (at, n) in [
                (20, start - 28),
                (22, 2),
                (28, start - 28),
                (30, end - 28),
                (start, end - start),
            ] {
                header[at..at + 2].copy_from_slice(&(n as u16).to_le_bytes());
            }
            header[start + 2] = 0;
            let prefix = (512 - start - 3).min(payload.len());
            header[start + 3..start + 3 + prefix].copy_from_slice(&payload[..prefix]);
            encode_sector(&mut raw[..512], &header, 55, 41, 47);
            if pn == 2 {
                let delta = 55u8.wrapping_mul(47);
                let step = (0u8..=255).find(|k| k.wrapping_mul(73) == delta).unwrap();
                encode_sector(&mut raw[512..1024], &payload[prefix..], 73, 42, step);
            }
            raw[4080] = 2;
            raw[4082] = b'E';
            seal(raw);
        }
        for (pn, owner) in [(4u32, 77), (5, 77), (6, 91), (1028, 88), (1029, 88)] {
            empty_data_page(
                &mut all[pn as usize * PAGE_SIZE..][..PAGE_SIZE],
                pn,
                owner,
                uncertain && pn == 1028,
            );
        }
        if uncertain {
            // A second complete structural key remains disqualifying even
            // when its owner disagrees with the independently expected one.
            let raw = &mut all[1028 * PAGE_SIZE..][..PAGE_SIZE];
            let mut header = [0x53; 512];
            header[..4].copy_from_slice(&1028u32.to_le_bytes());
            header[16] = 4;
            header[17] = 3;
            header[20..24].fill(0);
            header[24..28].copy_from_slice(&999u32.to_le_bytes());
            let mut alternate = [0; 512];
            encode_sector(&mut alternate, &header, 161, 209, 121);
            raw[161..189].copy_from_slice(&alternate[161..189]);
            seal(raw);
        }
        (PageStore::from_bytes_unchecked(all).unwrap(), first, second)
    }

    fn tie_descriptor(page: u32, length: u32) -> LongDescriptor<'static> {
        LongDescriptor {
            domain: 31,
            tag: 0,
            prefix: &[],
            total_len: length,
            first_page: page,
            unknown: 0,
            slot: 0,
        }
    }

    #[test]
    fn independently_verified_other_map_must_rule_out_every_rival_before_reading_members() {
        let (store, exact, rival) = tie_fixture(false);
        let calibrated = CalibratedStore::new(&store);
        let mut claims = crate::CatalogPageClaims::new(&calibrated);
        let target = PhysicalValue::OutOfRow(tie_descriptor(2, 516));
        let source = PhysicalValue::OutOfRow(tie_descriptor(3, 12));
        assert!(matches!(
            calibrated.table_page_map(&target, 2, 77),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
        assert!(matches!(
            claims.table_page_map(&target, 2, 77),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
        assert!(claims.observe_positive_map(&source, 2, 999).is_err());
        assert!(matches!(
            claims.table_page_map(&target, 2, 77),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
        claims.observe_positive_map(&source, 2, 88).unwrap();
        let read = claims.table_page_map(&target, 2, 77).unwrap();
        assert_eq!(read.bitmap.pages().collect::<Vec<_>>(), [4, 5]);
        assert_eq!(read.conflict_witnesses.len(), 1);
        assert_eq!(
            read.conflict_witnesses[0],
            crate::BitmapConflictWitness {
                page: 1028,
                owner: 88,
                source_page: 3,
                source_slot: 0
            }
        );
        assert_eq!(read.literal_witnesses.len(), 1);
        assert!(
            read.literal_witnesses[0]
                .literals
                .iter()
                .all(|l| l.alternative_page == 6)
        );
        let (actual, _) = claims
            .select(
                vec![rival.clone(), exact.clone()],
                &tie_descriptor(2, 516),
                2,
                77,
            )
            .unwrap();
        assert_eq!(actual, exact);
        // Changing only the descriptor to identify the witness's own slot
        // must disable that source even though its physical map was checked.
        assert!(matches!(
            claims.select(vec![rival, exact], &tie_descriptor(3, 516), 2, 77),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
        let same_set = [encoded(&[64, 2, 0x30, 0]), encoded(&[64, 1, 0x30, 128])];
        assert!(matches!(
            claims.select(same_set.to_vec(), &tie_descriptor(2, 16), 2, 77),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
        assert!(claims.table_page_map(&target, 2, 999).is_err());
        assert!(matches!(
            claims.observe_positive_map(&target, 2, 77),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
    }

    #[test]
    fn a_map_with_competing_member_keys_cannot_supply_any_conflict_evidence() {
        let (store, _, _) = tie_fixture(true);
        let calibrated = CalibratedStore::new(&store);
        let mut claims = crate::CatalogPageClaims::new(&calibrated);
        let source = PhysicalValue::OutOfRow(tie_descriptor(3, 12));
        assert!(matches!(
            claims.observe_positive_map(&source, 2, 88),
            Err(PageBitmapError::Header {
                source: crate::RowHeaderError::Ambiguous { .. },
                ..
            })
        ));
        let target = PhysicalValue::OutOfRow(tie_descriptor(2, 516));
        assert!(matches!(
            claims.table_page_map(&target, 2, 77),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
    }
}
