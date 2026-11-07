//! Linked, high-tag domain-31 ISYSTAB page maps. A 0x04 chunk stores one
//! address followed by bitmap bytes. A 0x00 chunk ends the chain. The slot
//! length covers the physical frame; the descriptor length covers the
//! concatenated logical bitmap. Those lengths need separate checks.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Range;

use super::{BitmapLiteralWitness, PageBitmapError, TableMapRead, TablePageBitmap, words};
use crate::row::sector::visit_sector_candidates;
use crate::row::tail::STASH_START;
use crate::{
    CalibratedPage, CalibratedStore, LongValueError, PAGE_SIZE, PageStore, PhysicalValue,
    RowPageHeader, SECTOR_SIZE,
};

const MAX_CHUNKS: usize = 64;

mod search;

/// A unique complete bitmap across all supported zero-anchor sector choices.
#[derive(Debug)]
pub struct LinkedBitmapSearch {
    /// Number of independently enumerated logical regions.
    pub regions: usize,
    /// Candidate prefix extensions actually considered.
    pub trials: usize,
    /// Greatest number of distinct surviving prefixes (bounded by 32).
    pub peak_prefixes: usize,
    /// Independently CRC/trailer-checked non-row I-pages used as exclusions.
    pub index_pages: Vec<(u32, Box<[u8; PAGE_SIZE]>)>,
}

/// Two independent literal membership checks on a bitmap-bearing sector whose
/// stream key was selected by the store model without a local length word.
#[derive(Debug)]
pub struct LinkedBitmapSector {
    /// Physical sector index in this chunk page, from 1 to 7.
    pub sector: u8,
    /// Half-open byte range in the complete logical bitmap.
    pub bitmap_range: Range<usize>,
    /// Two different members; exclusions can coincide only after a complete
    /// joint grammar proof has independently established the unique payload.
    pub literals: [BitmapLiteralWitness; 2],
}

/// Original physical slot and its contribution to a checked linked map.
pub struct LinkedMapChunk {
    /// Referenced physical page number.
    pub page: u32,
    /// Exact zero-based slot from the descriptor or preceding chunk.
    pub slot: u16,
    /// Physical chunk page kind, independently recovered from its row header.
    pub page_kind: u8,
    /// Logical start of the slot within its page.
    pub start: usize,
    /// Physical slot length, checked against its stored word.
    pub frame_len: usize,
    /// Stored chunk flags: 0x04 for a link or 0x00 for the terminal.
    pub flags: u8,
    /// Stored target address of a nonterminal chunk.
    pub next: Option<(u32, u16)>,
    /// This chunk's half-open byte range in the complete logical bitmap.
    pub bitmap_range: Range<usize>,
    /// Terminal surplus in logical page coordinates. Recovering or interpreting
    /// these bytes is outside the map proof. Their stored representation is
    /// retained in the original page, including the sector permutation and stash.
    pub opaque_surplus: Range<usize>,
    /// Complete original encoded page including its header, trailer and CRC.
    pub stored_page: Box<[u8; PAGE_SIZE]>,
    /// Membership witnesses for each length-unanchored bitmap sector in this chunk.
    pub sectors: Vec<LinkedBitmapSector>,
}

/// Physical source chain and exact logical payload of a verified catalog page map.
pub struct LinkedMapEvidence {
    /// Additional joint grammar proof when local exclusions were insufficient.
    pub global_grammar: Option<LinkedBitmapSearch>,
    /// The complete serialized bitmap of the descriptor's advertised byte length.
    pub bytes: Vec<u8>,
    /// Chunks in order, following only their stored addresses.
    pub chunks: Vec<LinkedMapChunk>,
}

impl fmt::Debug for LinkedMapEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkedMapEvidence")
            .field("byte_length", &self.bytes.len())
            .field("chunk_count", &self.chunks.len())
            .finish_non_exhaustive()
    }
}

// Coordinates are kept separate: a sector's byte zero belongs to the source
// page, while a literal may begin mid-chunk and is indexed in the logical map.
struct ModeledRegion {
    sector: u8,
    bitmap: Range<usize>,
    sector_offset: usize,
}

impl CalibratedStore<'_> {
    /// Read a positive ISYSTAB.tab_page_list after the caller corroborates the
    /// catalog record's identity, page count and row count. This entry point is
    /// specific to the high-tag linked descriptor. It preserves the physical
    /// chain while returning only logical bytes checked as the table's bitmap.
    pub fn linked_table_page_map(
        &self,
        value: &PhysicalValue<'_>,
        declared_pages: u32,
        declared_rows: u64,
        owner_id: u32,
    ) -> Result<TableMapRead, PageBitmapError> {
        let PhysicalValue::OutOfRow(d) = value else {
            return Err(PageBitmapError::UnsupportedField);
        };
        if declared_pages == 0
            || declared_rows == 0
            || d.domain != 31
            || d.tag != 0x80
            || d.unknown != 0
            || !d.prefix.is_empty()
        {
            return Err(PageBitmapError::UnsupportedField);
        }
        let length = d.total_len as usize;
        if !(8..=MAX_CHUNKS * PAGE_SIZE).contains(&length) || !length.is_multiple_of(4) {
            return Err(PageBitmapError::LinkedFrame);
        }
        let mut bytes = Vec::with_capacity(length);
        let mut chunks = Vec::new();
        let mut regions = Vec::new();
        let mut visited = BTreeSet::new();
        let mut address = (d.first_page, d.slot);
        let mut calibrated_sector_uses = 0;
        loop {
            if chunks.len() >= MAX_CHUNKS || !visited.insert(address) {
                return Err(PageBitmapError::LinkedLimit);
            }
            let (page, slot) = address;
            if page == 0 || u64::from(page) >= self.store().page_count() {
                return Err(PageBitmapError::LinkedFrame);
            }
            let reader = self
                .page(page)
                .map_err(|source| PageBitmapError::Header { page, source })?;
            let header = reader.header();
            if header.owner_id() != 1
                || !(0x11..=0x14).contains(&header.page_kind())
                || header.directory_prefix_matches() != Some(true)
            {
                return Err(PageBitmapError::LinkedFrame);
            }
            let rows = header.physical_rows().ok_or(PageBitmapError::LinkedFrame)?;
            let row = rows
                .iter()
                .find(|r| r.slot() == slot)
                .ok_or(PageBitmapError::LinkedFrame)?;
            let span = row.start()..row.end();
            let Frame {
                flags,
                next,
                data_start,
            } = frame(header, &span)?;
            let remaining = length - bytes.len();
            let available = span.end - data_start;
            // The link itself and its framing must be ordinary, independent
            // bytes. Each link contributes data and is needed to reach the
            // advertised length. Only the terminal can contain unused space.
            if remaining == 0
                || (next.is_some() && (available == 0 || available >= remaining))
                || (next.is_none() && (chunks.is_empty() || available < remaining))
            {
                return Err(PageBitmapError::LinkedFrame);
            }
            let before = bytes.len();
            let end = data_start + remaining.min(available);
            let (used, chunk_regions) = append_payload(&reader, data_start..end, &mut bytes)?;
            calibrated_sector_uses += used;
            let raw = self.store().page(u64::from(page))?;
            chunks.push(LinkedMapChunk {
                page,
                slot,
                page_kind: header.page_kind(),
                start: span.start,
                frame_len: span.len(),
                flags,
                next,
                bitmap_range: before..bytes.len(),
                opaque_surplus: end..span.end,
                stored_page: Box::new(raw.bytes().try_into().expect("store pages have fixed size")),
                sectors: Vec::new(),
            });
            regions.push(chunk_regions);
            let Some(target) = next else { break };
            address = target;
        }
        // The frozen fit supplies one payload. The optional joint grammar
        // proof below must reproduce it uniquely; it cannot replace this
        // prediction or change any link, chunk or logical padding boundary.
        let bitmap = TablePageBitmap::decode(&bytes, self.store().page_count(), declared_pages)?;
        let counts = bitmap.verified_counts(self.store(), owner_id, true)?;
        if counts.occupied_slots != Some(declared_rows) {
            return Err(PageBitmapError::LinkedMemberCounts);
        }
        let literals = literal_words(&bytes, self.store().page_count())?;
        let mut owner_cache = BTreeMap::new();
        let mut needs_global = false;
        for (chunk, modeled) in chunks.iter().zip(&regions) {
            let page = self.store().page(u64::from(chunk.page))?;
            let header =
                RowPageHeader::recover(page).map_err(|source| PageBitmapError::Header {
                    page: chunk.page,
                    source,
                })?;
            for region in modeled {
                match check_region(
                    self.store(),
                    page,
                    &header,
                    owner_id,
                    &bytes,
                    region,
                    &literals,
                    &mut owner_cache,
                    false,
                ) {
                    Ok(_) => {}
                    Err(PageBitmapError::LinkedWitness) => {
                        needs_global = true;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            if needs_global {
                break;
            }
        }
        let mut global_grammar = needs_global
            .then(|| search::verify(self.store(), &bytes, declared_pages, &chunks, &regions))
            .transpose()?;
        let mut retained_indexes = BTreeSet::new();
        for (chunk, modeled) in chunks.iter_mut().zip(regions) {
            let page = self.store().page(u64::from(chunk.page))?;
            let header =
                RowPageHeader::recover(page).map_err(|source| PageBitmapError::Header {
                    page: chunk.page,
                    source,
                })?;
            for region in modeled {
                let witnesses = check_region(
                    self.store(),
                    page,
                    &header,
                    owner_id,
                    &bytes,
                    &region,
                    &literals,
                    &mut owner_cache,
                    global_grammar.is_some(),
                )?;
                if let Some(proof) = &mut global_grammar {
                    for witness in &witnesses {
                        let number = witness.alternative_page;
                        let page = self.store().page(u64::from(number))?;
                        if checked_index(self.store(), number) && retained_indexes.insert(number) {
                            proof.index_pages.push((
                                number,
                                Box::new(page.bytes().try_into().expect("fixed page size")),
                            ));
                        }
                    }
                }
                chunk.sectors.push(LinkedBitmapSector {
                    sector: region.sector,
                    bitmap_range: region.bitmap,
                    literals: witnesses,
                });
            }
        }
        Ok(TableMapRead {
            empty_allocation: None,
            bitmap,
            counts,
            calibrated_sector_uses,
            repeated_map_header: false,
            literal_witnesses: Vec::new(),
            conflict_witnesses: Vec::new(),
            linked_map: Some(LinkedMapEvidence {
                global_grammar,
                bytes,
                chunks,
            }),
        })
    }
}

// The observed link address is in the corroborated first sector. Its six
// bytes use a different frame from an ordinary nine-byte forwarded data row.
struct Frame {
    flags: u8,
    next: Option<(u32, u16)>,
    data_start: usize,
}

fn frame(header: &RowPageHeader, span: &Range<usize>) -> Result<Frame, PageBitmapError> {
    let sector = header.sector0();
    let first = sector
        .get(span.start..span.end.min(SECTOR_SIZE))
        .ok_or(PageBitmapError::LinkedFrame)?;
    let (&[lo, hi, flags], rest) = first
        .split_first_chunk::<3>()
        .ok_or(PageBitmapError::LinkedFrame)?;
    if usize::from(u16::from_le_bytes([lo, hi])) != span.len() {
        return Err(PageBitmapError::LinkedFrame);
    }
    match flags {
        0 => Ok(Frame {
            flags,
            next: None,
            data_start: span.start + 3,
        }),
        4 => {
            let &[a, b, c, d, e, f] = rest
                .first_chunk::<6>()
                .ok_or(PageBitmapError::LinkedFrame)?;
            Ok(Frame {
                flags,
                next: Some((u32::from_le_bytes([a, b, c, d]), u16::from_le_bytes([e, f]))),
                data_start: span.start + 9,
            })
        }
        _ => Err(PageBitmapError::LinkedFrame),
    }
}

fn append_payload(
    reader: &CalibratedPage<'_, '_>,
    range: Range<usize>,
    bytes: &mut Vec<u8>,
) -> Result<(usize, Vec<ModeledRegion>), PageBitmapError> {
    let mut modeled = Vec::new();
    let mut uses = 0;
    let mut at = range.start;
    while at < range.end {
        let sector = at / SECTOR_SIZE;
        let end = range.end.min(if at >= STASH_START {
            4092
        } else {
            ((sector + 1) * SECTOR_SIZE).min(STASH_START)
        });
        if sector == 0 {
            bytes.extend_from_slice(&reader.header().sector0()[at..end]);
        } else if at >= STASH_START {
            bytes.extend_from_slice(
                &reader.header().row_tail_stash()[at - STASH_START..end - STASH_START],
            );
        } else {
            let (part, anchors) = reader
                .linked_bitmap_sector(sector)
                .map_err(LongValueError::Calibration)?;
            let local = at - sector * SECTOR_SIZE;
            let offset = bytes.len();
            bytes.extend_from_slice(&part[local..local + end - at]);
            if anchors.is_some() {
                uses += 1;
            }
            if anchors == Some(0) {
                modeled.push(ModeledRegion {
                    sector: sector as u8,
                    bitmap: offset..bytes.len(),
                    sector_offset: local,
                });
            }
        }
        at = end;
    }
    Ok((uses, modeled))
}

struct Literal {
    offset: usize,
    base: u32,
    bits: u32,
}

fn literal_words(bytes: &[u8], pages: u64) -> Result<Vec<Literal>, PageBitmapError> {
    let mut out = Vec::new();
    words::walk(bytes, bytes.len(), pages, |offset, word| {
        if word.literal && word.bits != 0 {
            out.push(Literal {
                offset,
                base: word.start as u32,
                bits: word.bits,
            });
        }
        Ok(())
    })?;
    Ok(out)
}

// A fully corroborated foreign overflow page is exclusion evidence too. Its
// independent header identifies another owner even though it cannot be a
// positive table-row member. Keep unsupported kinds and ambiguous headers out.
fn negative_witness_owner(store: &PageStore, page: u32) -> Option<u32> {
    store
        .page(u64::from(page))
        .ok()
        .and_then(|p| RowPageHeader::recover(p).ok())
        .filter(|h| matches!(h.page_kind(), 0..=4 | 0x11..=0x14))
        .map(|h| h.owner_id())
}

fn checked_index(store: &PageStore, page: u32) -> bool {
    page != 0
        && store.page(u64::from(page)).is_ok_and(|p| {
            matches!(p.trailer().page_type(), crate::PageType::Index)
                && p.verify_crc().is_ok()
                && p.verify_trailer().is_ok()
        })
}

// Require two distinct physical members and exclusions that a competing local
// key would set. Exclusions must be distinct unless the separate joint search
// already proved the whole bitmap unique. The store model and logical length
// were frozen before these checks.
#[allow(clippy::too_many_arguments)]
fn check_region(
    store: &PageStore,
    page: crate::Page<'_>,
    header: &RowPageHeader,
    owner: u32,
    bytes: &[u8],
    region: &ModeledRegion,
    literals: &[Literal],
    cache: &mut BTreeMap<u32, Option<u32>>,
    global_unique: bool,
) -> Result<[BitmapLiteralWitness; 2], PageBitmapError> {
    let predicted = &bytes[region.bitmap.clone()];
    let (matched, union) = alternative_bits(page, header, region, predicted)?;
    if !matched {
        return Err(PageBitmapError::LinkedWitness);
    }
    let mut first: Option<BitmapLiteralWitness> = None;
    let mut other_positive = None;
    let mut other_negative = None;
    for word in literals
        .iter()
        .skip_while(|w| w.offset < region.bitmap.start)
        .take_while(|w| w.offset + 4 <= region.bitmap.end)
    {
        let local = word.offset - region.bitmap.start;
        let wrong = u32::from_le_bytes(union[local..local + 4].try_into().unwrap()) & !word.bits;
        if wrong == 0 {
            continue;
        }
        // verify_owner already corroborated every set bit. Negative evidence
        // requires a separately recovered supported header of a different
        // owner, including independently recognized overflow frames.
        for bit in 0..32 {
            if wrong & (1 << bit) == 0 {
                continue;
            }
            let negative = word.base + bit;
            let observed = cache
                .entry(negative)
                .or_insert_with(|| negative_witness_owner(store, negative));
            if !(observed.is_some_and(|actual| actual != owner)
                || global_unique && checked_index(store, negative))
            {
                continue;
            }
            for positive in 0..32 {
                if word.bits & (1 << positive) == 0 {
                    continue;
                }
                let witness = BitmapLiteralWitness {
                    payload_offset: word.offset,
                    member_page: word.base + positive,
                    alternative_page: negative,
                };
                let Some(one) = first else {
                    first = Some(witness);
                    continue;
                };
                if global_unique && one.member_page != witness.member_page {
                    return Ok([one, witness]);
                }
                match (
                    one.member_page == witness.member_page,
                    one.alternative_page == witness.alternative_page,
                ) {
                    (false, false) => return Ok([one, witness]),
                    (false, true) => other_positive = Some(witness),
                    (true, false) => other_negative = Some(witness),
                    _ => {}
                }
                if let (Some(a), Some(b)) = (other_positive, other_negative) {
                    return Ok([a, b]);
                }
            }
        }
    }
    Err(PageBitmapError::LinkedWitness)
}

fn alternative_bits(
    page: crate::Page<'_>,
    header: &RowPageHeader,
    region: &ModeledRegion,
    predicted: &[u8],
) -> Result<(bool, Vec<u8>), PageBitmapError> {
    let k = usize::from(region.sector);
    let start = k * SECTOR_SIZE;
    let end = (start + SECTOR_SIZE).min(STASH_START);
    let mut constraints = Vec::new();
    for row in header.physical_rows().ok_or(PageBitmapError::LinkedFrame)? {
        for (i, b) in (row.length() as u16).to_le_bytes().into_iter().enumerate() {
            let at = row.start() + i;
            if (start..end).contains(&at) {
                constraints.push((at - start, b));
            }
        }
    }
    let mut matched = false;
    let mut union = vec![0; predicted.len()];
    visit_sector_candidates(page, header, k, |decode| {
        if constraints.iter().any(|&(at, b)| decode(at) != b) {
            return Ok::<(), PageBitmapError>(());
        }
        let mut same = true;
        for (i, v) in predicted.iter().enumerate() {
            let b = decode(region.sector_offset + i);
            same &= b == *v;
            union[i] |= b;
        }
        matched |= same;
        Ok(())
    })?;
    Ok((matched, union))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LongDescriptor;
    use crate::page_bitmap::tests::stored_page;

    fn bitmap() -> Vec<u8> {
        [32u32, 1, 1 << 4]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect()
    }

    fn descriptor(length: u32) -> PhysicalValue<'static> {
        PhysicalValue::OutOfRow(LongDescriptor {
            domain: 31,
            tag: 0x80,
            prefix: &[],
            total_len: length,
            first_page: 2,
            unknown: 0,
            slot: 0,
        })
    }

    fn chunk(number: u32, owner: u32, kind: u8, flags: u8, data: &[u8]) -> [u8; PAGE_SIZE] {
        let mut page = stored_page(number, owner, kind, 2, 2, Some(data));
        // The shared fixture stores its first record at 160 and uses rotation 55.
        let offset = (162 + 55) % SECTOR_SIZE;
        page[offset] = page[offset].wrapping_add(flags);
        let crc = crc32fast::hash(&page[..4092]);
        page[4092..].copy_from_slice(&crc.to_le_bytes());
        page
    }

    fn pointer(page: u32, slot: u16, data: &[u8]) -> Vec<u8> {
        let mut frame = page.to_le_bytes().to_vec();
        frame.extend_from_slice(&slot.to_le_bytes());
        frame.extend_from_slice(data);
        frame
    }

    fn fixture(head: [u8; PAGE_SIZE], tail: [u8; PAGE_SIZE]) -> PageStore {
        let mut bytes = vec![0; 5 * PAGE_SIZE];
        for (n, p) in [(2, head), (3, tail), (4, stored_page(4, 27, 3, 2, 1, None))] {
            bytes[n * PAGE_SIZE..(n + 1) * PAGE_SIZE].copy_from_slice(&p);
        }
        PageStore::from_bytes_unchecked(bytes).unwrap()
    }

    fn normal() -> ([u8; PAGE_SIZE], [u8; PAGE_SIZE]) {
        let data = bitmap();
        let mut tail = data[5..].to_vec();
        // Opaque physical bytes can be arbitrary, including a nonzero byte.
        tail.extend_from_slice(&[0xff, 0x80, 0]);
        (
            chunk(2, 1, 0x11, 4, &pointer(3, 0, &data[..5])),
            chunk(3, 1, 0x12, 0, &tail),
        )
    }

    #[test]
    fn joins_a_split_word_and_retains_the_encoded_pages_and_opaque_extent() {
        let (head, tail) = normal();
        let db = fixture(head, tail);
        let result = CalibratedStore::new(&db)
            .linked_table_page_map(&descriptor(12), 1, 1, 27)
            .unwrap();
        assert_eq!(result.bitmap.pages().collect::<Vec<_>>(), [4]);
        assert_eq!(result.counts.occupied_slots, Some(1));
        let proof = result.linked_map.unwrap();
        assert_eq!(proof.bytes, bitmap());
        assert_eq!(proof.chunks.len(), 2);
        let first = &proof.chunks[0];
        assert_eq!(
            (
                first.page,
                first.slot,
                first.page_kind,
                first.flags,
                first.next
            ),
            (2, 0, 0x11, 4, Some((3, 0)))
        );
        assert_eq!(first.bitmap_range, 0..5);
        assert_eq!(first.opaque_surplus, 174..174);
        assert_eq!(*first.stored_page, head);
        let last = &proof.chunks[1];
        assert_eq!(
            (last.page, last.slot, last.page_kind, last.flags, last.next),
            (3, 0, 0x12, 0, None)
        );
        assert_eq!(last.bitmap_range, 5..12);
        assert_eq!(last.opaque_surplus, 170..173);
        assert_eq!(*last.stored_page, tail);
        assert!(proof.chunks.iter().all(|c| c.sectors.is_empty()));
    }

    #[test]
    fn rejects_invalid_links_and_never_substitutes_another_address_or_owner() {
        let (head, tail) = normal();
        let data = bitmap();
        let read = |a, b| {
            CalibratedStore::new(&fixture(a, b))
                .linked_table_page_map(&descriptor(12), 1, 1, 27)
                .unwrap_err()
        };
        assert!(matches!(
            read(head, chunk(3, 1, 0x12, 4, &pointer(2, 0, &[0]))),
            PageBitmapError::LinkedLimit
        ));
        for (pn, slot) in [(0, 0), (40, 0), (3, 3)] {
            assert!(matches!(
                read(chunk(2, 1, 0x11, 4, &pointer(pn, slot, &data[..5])), tail),
                PageBitmapError::LinkedFrame
            ));
        }
        for (owner, kind, flag) in [(18, 0x12, 0), (1, 3, 0), (1, 0x12, 2)] {
            assert!(matches!(
                read(head, chunk(3, owner, kind, flag, &data[5..])),
                PageBitmapError::LinkedFrame
            ));
        }
        assert!(matches!(
            read(head, chunk(3, 1, 0x12, 0, &data[5..11])),
            PageBitmapError::LinkedFrame
        ));
        assert!(matches!(
            read(chunk(2, 1, 0x11, 4, &pointer(3, 0, &data)), tail),
            PageBitmapError::LinkedFrame
        ));
        let mut bad_word = tail;
        bad_word[160 + 55] = bad_word[160 + 55].wrapping_add(1);
        let crc = crc32fast::hash(&bad_word[..4092]);
        bad_word[4092..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(read(head, bad_word), PageBitmapError::LinkedFrame));
        let mut corrupt = tail;
        corrupt[2000] ^= 1;
        assert!(matches!(
            read(head, corrupt),
            PageBitmapError::Header {
                source: crate::RowHeaderError::Integrity(_),
                ..
            }
        ));
    }

    #[test]
    fn positive_descriptor_and_exact_catalog_counts_are_required() {
        let (head, tail) = normal();
        let db = fixture(head, tail);
        let s = CalibratedStore::new(&db);
        let value = descriptor(12);
        assert!(matches!(
            s.linked_table_page_map(&value, 1, 0, 27),
            Err(PageBitmapError::UnsupportedField)
        ));
        assert!(matches!(
            s.linked_table_page_map(&value, 0, 1, 27),
            Err(PageBitmapError::UnsupportedField)
        ));
        assert!(matches!(
            s.linked_table_page_map(&value, 2, 1, 27),
            Err(PageBitmapError::Count { .. })
        ));
        assert!(matches!(
            s.linked_table_page_map(&value, 1, 2, 27),
            Err(PageBitmapError::LinkedMemberCounts)
        ));
        assert!(matches!(
            s.linked_table_page_map(&value, 1, 1, 28),
            Err(PageBitmapError::Owner { .. })
        ));
        assert!(matches!(
            s.linked_table_page_map(&descriptor(11), 1, 1, 27),
            Err(PageBitmapError::LinkedFrame)
        ));
        let PhysicalValue::OutOfRow(d) = &value else {
            unreachable!()
        };
        for bad in [
            LongDescriptor { domain: 12, ..*d },
            LongDescriptor { tag: 0, ..*d },
            LongDescriptor { unknown: 1, ..*d },
            LongDescriptor {
                prefix: &[32],
                ..*d
            },
        ] {
            assert!(matches!(
                s.linked_table_page_map(&PhysicalValue::OutOfRow(bad), 1, 1, 27),
                Err(PageBitmapError::UnsupportedField)
            ));
        }
    }

    #[test]
    fn foreign_overflow_headers_can_exclude_literal_bits_without_becoming_members() {
        let (head, _) = normal();
        for kind in 0x11..=0x14 {
            let db = fixture(head, chunk(3, 1, kind, 0, &[0]));
            assert_eq!(negative_witness_owner(&db, 3), Some(1));
            assert_ne!(negative_witness_owner(&db, 3), Some(27));
            // The same overflow page remains invalid as a positive table-row
            // member, even when its owner matches the requested table owner.
            let map = TablePageBitmap::decode(
                &[32u32, 1, 1 << 3]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>(),
                db.page_count(),
                1,
            )
            .unwrap();
            assert!(matches!(
                map.verify_owner(&db, 1),
                Err(PageBitmapError::NotTableRow { .. })
            ));
        }
        let same_owner = fixture(head, chunk(3, 27, 0x12, 0, &[0]));
        assert!(negative_witness_owner(&same_owner, 3).is_none_or(|o| o == 27));
        let unsupported = fixture(head, chunk(3, 1, 0x10, 0, &[0]));
        assert_eq!(negative_witness_owner(&unsupported, 3), None);
        let mut corrupt = chunk(3, 1, 0x12, 0, &[0]);
        corrupt[2000] ^= 1;
        assert_eq!(negative_witness_owner(&fixture(head, corrupt), 3), None);
        assert_eq!(negative_witness_owner(&same_owner, 100), None);
    }

    #[test]
    fn global_search_index_exclusions_require_crc_type_and_reserved_trailer_bytes() {
        let (head, _) = normal();
        let mut index = chunk(3, 1, 0x12, 0, &[0]);
        index[4082] = b'I';
        let crc = crc32fast::hash(&index[..4092]);
        index[4092..].copy_from_slice(&crc.to_le_bytes());
        let db = fixture(head, index);
        assert!(checked_index(&db, 3));
        assert!(!checked_index(&db, 0));
        let mut corrupt = index;
        corrupt[2000] ^= 1;
        assert!(!checked_index(&fixture(head, corrupt), 3));
        let mut reserved = index;
        reserved[4083] = 1;
        let crc = crc32fast::hash(&reserved[..4092]);
        reserved[4092..].copy_from_slice(&crc.to_le_bytes());
        assert!(!checked_index(&fixture(head, reserved), 3));
        assert!(!checked_index(
            &fixture(head, chunk(3, 1, 0x12, 0, &[0])),
            3
        ));
    }

    #[test]
    fn depth_limit_applies_even_to_unique_bounded_nonterminal_slots() {
        let mut bytes = vec![0; (MAX_CHUNKS + 4) * PAGE_SIZE];
        for i in 0..=MAX_CHUNKS {
            let pn = 2 + i;
            let page = chunk(pn as u32, 1, 0x11, 4, &pointer(pn as u32 + 1, 0, &[0]));
            bytes[pn * PAGE_SIZE..(pn + 1) * PAGE_SIZE].copy_from_slice(&page);
        }
        let db = PageStore::from_bytes_unchecked(bytes).unwrap();
        assert!(matches!(
            CalibratedStore::new(&db).linked_table_page_map(&descriptor(128), 1, 1, 27),
            Err(PageBitmapError::LinkedLimit)
        ));
    }
}
