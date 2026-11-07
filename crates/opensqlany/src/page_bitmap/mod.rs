//! Candidate table-page membership from the `ISYSTAB.tab_page_list` catalog
//! field. A little-endian bit limit is followed by controls and literal words.
//! A control describes a run of 32-bit words (zero or all ones), then 0..63
//! literal words. The least significant bit of each word is its first page.
//!
//! Membership belongs to one physical catalog record. It does not identify
//! which copy of that record is current, or which slots on a named page are
//! live. The separate `ext_page_list` field is not a table-row page list.

pub(crate) mod bitset;
mod calibrated;
mod claims;
mod linked;
mod recovery;
mod regions;
pub(crate) mod words;

use crate::record::long_value::resolve_byte_counted_chunk;
use crate::{
    CalibratedPage, CalibratedStore, Error, LongValueError, PageStore, PhysicalValue,
    RowHeaderError, RowPageHeader,
};

pub use calibrated::TableMapRead;
pub use claims::{BitmapConflictWitness, CatalogPageClaims};
pub use linked::{LinkedBitmapSearch, LinkedBitmapSector, LinkedMapChunk, LinkedMapEvidence};
pub use regions::{BitmapLiteralWitness, BitmapSectorWitness};

/// Validated set physical page numbers. At most one compressed segment is
/// stored per control or literal word, including for large all-one fills.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TablePageBitmap {
    segments: Vec<BitSegment>,
    count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BitSegment {
    start: u32,
    end: u32,
    bits: u32,
}

impl BitSegment {
    fn has_bit(&self, page: u32) -> bool {
        self.bits & (1 << (page % 32)) != 0
    }
}

/// Physical counts across all the owner-checked pages in one catalog map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TablePageCounts {
    /// Legacy field name for the sum of the raw directory prefix counts.
    /// Each trailer word describes the leading occupied slots on its page.
    /// Occupied slots may also occur after the first vacant slot.
    pub live_slots: u64,
    /// Sum of nonzero directory entries, or `None` if any directory is partial.
    pub occupied_slots: Option<u64>,
}

/// A four-byte serialized empty map in a verified nine-byte terminal frame.
/// The final two bytes belong to the physical allocation, not its logical value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyMapAllocation {
    /// Physical catalog chunk page.
    pub page: u32,
    /// Zero-based chunk slot named by the catalog descriptor.
    pub slot: u16,
    /// Complete six-byte physical payload, including the two opaque surplus bytes.
    pub payload: [u8; 6],
}

impl TablePageBitmap {
    /// Decode a complete serialized catalog map. The limit is word-aligned
    /// and can include padding beyond the physical end of the store; all set
    /// bits must identify existing data pages, and their total must equal the
    /// catalog-declared table-page count. Empty field bytes are accepted only
    /// for a declared zero-page table.
    ///
    /// # Errors
    ///
    /// Returns [`PageBitmapError`] for incomplete or invalid RLE words,
    /// out-of-store members, or a population different from `declared_pages`.
    pub fn decode(
        bytes: &[u8],
        physical_pages: u64,
        declared_pages: u32,
    ) -> Result<Self, PageBitmapError> {
        let mut result = Self {
            segments: Vec::new(),
            count: 0,
        };
        if bytes.is_empty() {
            return if declared_pages == 0 {
                Ok(result)
            } else {
                Err(PageBitmapError::Count {
                    declared: declared_pages,
                    actual: 0,
                })
            };
        }
        result.count = words::walk(bytes, bytes.len(), physical_pages, |_, word| {
            if word.bits != 0 {
                result.add_segment(word.start as u32, word.end as u32, word.bits)?;
            }
            Ok(())
        })?;
        if result.count != declared_pages {
            return Err(PageBitmapError::Count {
                declared: declared_pages,
                actual: result.count,
            });
        }
        Ok(result)
    }

    fn add_segment(&mut self, start: u32, end: u32, bits: u32) -> Result<(), PageBitmapError> {
        if let Some(previous) = self
            .segments
            .last_mut()
            .filter(|s| s.end == start && s.bits == bits)
        {
            previous.end = end;
        } else {
            self.segments
                .try_reserve(1)
                .map_err(|_| PageBitmapError::Allocation)?;
            self.segments.push(BitSegment { start, end, bits });
        }
        Ok(())
    }

    /// Decode a caller-identified `tab_page_list` field from an ISYSTAB row.
    /// A nonempty field must be the observed domain-31, tag-zero, terminal
    /// single-chunk form: the descriptor's reported length must exactly match
    /// the retrieved payload in bytes, and its prefix and owner must agree.
    /// A four-byte zero universe can occupy a nine-byte terminal allocation
    /// when the catalog declares no pages. The two physical surplus bytes
    /// are outside that logical value and retained by the richer map reader.
    pub fn from_catalog_value(
        store: &PageStore,
        value: &PhysicalValue<'_>,
        declared_pages: u32,
    ) -> Result<Self, PageBitmapError> {
        match value {
            PhysicalValue::Null
            | PhysicalValue::InlineBytes {
                domain: 31,
                bytes: [],
            } => Self::decode(&[], store.page_count(), declared_pages),
            PhysicalValue::OutOfRow(descriptor) if descriptor.domain == 31 => {
                Self::read_terminal_map(descriptor, store.page_count(), declared_pages, |frame| {
                    resolve_byte_counted_chunk(store, 1, frame)
                })
                .map(|(map, _, _)| map)
            }
            _ => Err(PageBitmapError::UnsupportedField),
        }
    }

    // Both ordinary and separately witnessed readers use exactly the same
    // terminal framing, declared logical length and map validation.
    pub(crate) fn read_terminal_map<'a>(
        descriptor: &crate::LongDescriptor<'_>,
        physical_pages: u64,
        declared_pages: u32,
        mut read: impl FnMut(
            &crate::LongDescriptor<'_>,
        ) -> Result<crate::LongValueCandidate<'a>, LongValueError>,
    ) -> Result<(Self, usize, Option<EmptyMapAllocation>), PageBitmapError> {
        let mut allocation = None;
        let (chunk, payload_len) = match read(descriptor) {
            Ok(chunk) => {
                let length = chunk.bytes.len();
                (chunk, length)
            }
            Err(
                error @ LongValueError::Length {
                    expected: 4,
                    actual: 6,
                },
            ) if declared_pages == 0 && descriptor.prefix.is_empty() => {
                // Read the entire minimum allocation through the same exact
                // reference and frame checks. Only the advertised four-byte
                // universe is logical map data; preserve any nonzero surplus.
                let frame = crate::LongDescriptor {
                    total_len: 6,
                    ..*descriptor
                };
                let chunk = read(&frame)?;
                if chunk.bytes.len() != 6
                    || chunk.physical_frame_len() != 9
                    || chunk.bytes[..4] != [0; 4]
                {
                    return Err(error.into());
                }
                if chunk.bytes[4..].iter().any(|&byte| byte != 0) {
                    allocation = Some(EmptyMapAllocation {
                        page: chunk.page,
                        slot: chunk.slot,
                        payload: chunk.bytes.as_slice().try_into().expect("six-byte payload"),
                    });
                }
                (chunk, 4)
            }
            Err(error) => return Err(error.into()),
        };
        let uses = chunk
            .sectors
            .iter()
            .filter(|s| matches!(s, crate::RowSlotSector::Calibrated { .. }))
            .count();
        let map = Self::decode(&chunk.bytes[..payload_len], physical_pages, declared_pages)?;
        Ok((map, uses, allocation))
    }

    /// Read a catalog value with a known table identity. The ordinary path
    /// still requires exact byte-counted chunk framing. Only a positive map
    /// with exactly one sector missing for lack of length anchors can also
    /// be recovered from its unique complete bitmap, every set page's owner
    /// and an independent held-out length word in that same missing sector.
    /// Every returned map names only corroborated row pages of this owner.
    pub fn from_catalog_value_for_owner(
        store: &PageStore,
        value: &PhysicalValue<'_>,
        declared_pages: u32,
        owner_id: u32,
    ) -> Result<Self, PageBitmapError> {
        match (
            Self::from_catalog_value(store, value, declared_pages),
            value,
        ) {
            (
                Err(PageBitmapError::Chunk(LongValueError::Unavailable)),
                PhysicalValue::OutOfRow(d),
            ) if declared_pages > 0 && d.domain == 31 => {
                recovery::recover(store, d, declared_pages, owner_id)
            }
            (Ok(bitmap), _) => {
                bitmap.verify_owner(store, owner_id)?;
                Ok(bitmap)
            }
            (Err(error), _) => Err(error),
        }
    }

    /// Set physical page numbers, in ascending order.
    pub fn pages(&self) -> impl Iterator<Item = u32> + '_ {
        self.segments
            .iter()
            .flat_map(|s| (s.start..s.end).filter(move |&page| s.has_bit(page)))
    }

    /// Whether a specific physical page is named in this catalog record.
    pub fn contains(&self, page: u32) -> bool {
        let i = self.segments.partition_point(|s| s.end <= page);
        self.segments
            .get(i)
            .is_some_and(|s| s.start <= page && s.has_bit(page))
    }

    /// Number of pages, checked against the catalog's declared count.
    pub fn len(&self) -> u32 {
        self.count
    }
    /// Whether the catalog declares and names zero table pages.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Verify the stored CRC, physical page identity, logical row-page kind
    /// and owner of every set page against this store. This can establish the
    /// table membership named by this record, not its time or liveness.
    pub fn verify_owner(
        &self,
        store: &PageStore,
        owner_id: u32,
    ) -> Result<TablePageCounts, PageBitmapError> {
        self.verified_counts(store, owner_id, false)
    }

    /// Open a named row member and check its physical identity, owner and kind.
    /// Ordinary header checks take precedence. A sole repeated-number header
    /// may use the independently expected catalog owner when there is exactly
    /// one structural key and the complete directory and trailer prefix agree.
    /// A repeated number in a field or directory never elects a competing key.
    /// Slot bytes still need their normal length, sector and typed-record checks.
    pub fn page<'r, 's>(
        &self,
        store: &'r CalibratedStore<'s>,
        owner_id: u32,
        page: u32,
    ) -> Result<CalibratedPage<'r, 's>, PageBitmapError> {
        if !self.contains(page) {
            return Err(PageBitmapError::NotMember { page });
        }
        let header = member_header(store.store(), page, owner_id)?;
        let stored = store.store().page(u64::from(page))?;
        Ok(store.page_with_header(stored, header))
    }

    /// Resolve a forward from a source independently selected by this bitmap.
    /// Ordinary target headers take precedence. Only a sole repeated-number
    /// LOB header may also use the verified source owner and exact target slot;
    /// complete directory/prefix, frame, flag and value checks still apply.
    /// The ordinary unbound forward resolver keeps its stricter header policy.
    pub fn resolve_forwarded_row<'s>(
        &self,
        store: &CalibratedStore<'s>,
        owner_id: u32,
        page: u32,
        slot: u16,
    ) -> Result<crate::ForwardedRow<'s>, crate::ForwardedRowError> {
        let source = self.page(store, owner_id, page)?;
        crate::row::forwarded::from_mapped_page(store, &source, slot)
    }

    fn verified_counts(
        &self,
        store: &PageStore,
        owner_id: u32,
        require_complete_prefix: bool,
    ) -> Result<TablePageCounts, PageBitmapError> {
        let mut counts = TablePageCounts {
            live_slots: 0,
            occupied_slots: Some(0),
        };
        for page in self.pages() {
            let header = member_header(store, page, owner_id)?;
            if require_complete_prefix
                && (header.directory_prefix_matches() != Some(true)
                    || (header.page_kind() == 0
                        && header
                            .complete_slot_starts()
                            .is_none_or(|slots| slots.iter().any(Option::is_some))))
            {
                return Err(PageBitmapError::LinkedMemberCounts);
            }
            counts.live_slots += u64::from(header.directory_prefix_count());
            counts.occupied_slots = counts
                .occupied_slots
                .zip(header.complete_slot_starts())
                .map(|(n, slots)| n + slots.iter().flatten().count() as u64);
        }
        Ok(counts)
    }
}

pub(crate) fn member_header(
    store: &PageStore,
    page: u32,
    owner_id: u32,
) -> Result<RowPageHeader, PageBitmapError> {
    let stored = store.page(u64::from(page))?;
    let header = RowPageHeader::recover_for_owner(stored, owner_id)
        .map_err(|source| PageBitmapError::Header { page, source })?;
    if header.owner_id() != owner_id {
        return Err(PageBitmapError::Owner {
            page,
            expected: owner_id,
            actual: header.owner_id(),
        });
    }
    if header.page_kind() > 4 {
        return Err(PageBitmapError::NotTableRow {
            page,
            kind: header.page_kind(),
        });
    }
    Ok(header)
}

/// Why a candidate catalog table-page map could not be verified.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PageBitmapError {
    /// The requested page is absent from this exact bitmap.
    #[error("page {page}: not a member of this table bitmap")]
    NotMember {
        /// Requested physical page number.
        page: u32,
    },
    /// An ISYSTAB linked map has an invalid stored link, extent, flag, or terminal length.
    #[error("invalid linked catalog bitmap framing")]
    LinkedFrame,
    /// The stored chain repeats an address or exceeds the bounded chunk count.
    #[error("linked catalog bitmap contains a cycle or exceeds its size limit")]
    LinkedLimit,
    /// A bitmap-bearing sector lacks the two independent literal-page witnesses.
    #[error("linked bitmap sector lacks independent literal membership evidence")]
    LinkedWitness,
    /// Linked map members must have complete prefix-checked directories and the declared row count.
    #[error("linked bitmap member counts do not match the catalog")]
    LinkedMemberCounts,
    /// The declared terminal row could not be bounded with exactly one sparse sector.
    #[error("cannot delimit an exact single-gap terminal bitmap chunk")]
    SparseBounds,
    /// A sparse candidate has no independent varying stored length word that confirms it.
    #[error("no varying held-out row length confirms the sparse bitmap")]
    NoBitmapWitness,
    /// No sparse candidate met the complete bitmap, size and physical owner constraints.
    #[error("no sparse payload satisfies the catalog bitmap and page ownership checks")]
    NoSparseMap,
    /// Distinct sparse payloads satisfied those checks; their lengths cannot break the tie.
    #[error("multiple sparse bitmap payloads satisfy the catalog constraints")]
    AmbiguousSparseMap,
    /// The bounded sector enumeration reached its work or live-prefix limit.
    #[error("bitmap sector search exceeded its bounded work budget")]
    SparseSearchLimit,
    /// The compact segment index could not be allocated.
    #[error("cannot allocate a bitmap segment index")]
    Allocation,
    /// The value was not a null, empty or supported domain-31 descriptor.
    #[error("tab_page_list has an unsupported value form or domain")]
    UnsupportedField,
    /// A referenced chunk could not be independently recovered.
    #[error(transparent)]
    Chunk(#[from] LongValueError),
    /// The input is not a sequence of complete little-endian 32-bit words.
    #[error("bitmap data is not word aligned")]
    WordAlignment,
    /// Observed bit limits are multiples of 32 bits.
    #[error("bitmap universe {universe} is not word aligned")]
    UniverseAlignment {
        /// Declared bit limit.
        universe: u32,
    },
    /// A control would consume no bits.
    #[error("bitmap control makes no progress")]
    NoProgress,
    /// A control declares more literal words than remain.
    #[error("truncated bitmap literal run")]
    TruncatedLiteral,
    /// The runs exceed the limit or do not reach it at end of input.
    #[error("bitmap runs do not exactly span the declared universe {universe}")]
    UniverseCoverage {
        /// Declared bit limit.
        universe: u32,
    },
    /// Page zero and pages past the end of the store cannot be members.
    #[error("bitmap names page {page} outside the data pages of a {physical_pages}-page store")]
    OutOfStore {
        /// Invalid set page.
        page: u64,
        /// Physical store size in pages.
        physical_pages: u64,
    },
    /// The number of set bits did not match the catalog.
    #[error("catalog declares {declared} table pages but its bitmap names {actual}")]
    Count {
        /// Catalog count.
        declared: u32,
        /// Number of set pages.
        actual: u32,
    },
    /// A named page could not be read.
    #[error(transparent)]
    Page(#[from] Error),
    /// Column catalog member evidence was obtained from a different reader.
    #[error("column catalog map and reader belong to different calibrated stores")]
    DifferentMemberStore,
    /// The verified ISYSTABCOL map does not name the requested page.
    #[error("page {page} is outside the verified column catalog bitmap")]
    NotColumnCatalogMember {
        /// Requested physical page number.
        page: u32,
    },
    /// A named page did not yield a corroborated row header.
    #[error("table bitmap page {page}: {source}")]
    Header {
        /// Physical page number.
        page: u32,
        /// Integrity or header recovery failure.
        source: RowHeaderError,
    },
    /// A named page belongs to a different table.
    #[error("bitmap page {page} belongs to owner {actual}, expected {expected}")]
    Owner {
        /// Physical page number.
        page: u32,
        /// Catalog table identifier.
        expected: u32,
        /// Stored owner identifier.
        actual: u32,
    },
    /// The page is not one of the ordinary data-row kinds.
    #[error("table bitmap page {page} has unsupported row kind {kind:#04x}")]
    NotTableRow {
        /// Physical page number.
        page: u32,
        /// Stored page kind.
        kind: u8,
    },
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{LongDescriptor, PAGE_SIZE};

    fn encoded(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn reads_zero_and_one_fills_and_sparse_literals_in_little_endian_order() {
        // 0..32 empty, then literal bits 1/31, then 64 ones and one final
        // literal. The final zero fill pads the universe beyond the file.
        let bytes = encoded(&[
            192,
            (1 << 7) | 1,
            0x80000002,
            (2 << 7) | 0x40 | 1,
            2,
            1 << 7,
        ]);
        let bitmap = TablePageBitmap::decode(&bytes, 131, 67).unwrap();
        let mut expected = vec![33, 63];
        expected.extend(64..128);
        expected.push(129);
        assert_eq!(bitmap.pages().collect::<Vec<_>>(), expected);
        assert_eq!(bitmap.len(), 67);
        for p in 0..256 {
            assert_eq!(bitmap.contains(p), expected.contains(&p));
        }
        assert!(!bitmap.contains(u32::MAX));
    }

    #[test]
    fn large_fills_are_never_materialized_as_one_entry_per_page() {
        let words_to_set = 0x1ff_ffffu32; // maximum 25-bit run in a control
        let universe = (words_to_set + 1) * 32;
        let bytes = encoded(&[universe, 1 << 7, words_to_set << 7 | 0x40]);
        let bitmap = TablePageBitmap::decode(&bytes, u64::from(universe), universe - 32).unwrap();
        assert_eq!(bitmap.segments.len(), 1);
        assert!(bitmap.contains(32) && bitmap.contains(universe - 1));
        assert!(!bitmap.contains(31) && !bitmap.contains(universe));
    }

    #[test]
    fn rejects_incomplete_overlong_unaligned_or_out_of_store_maps() {
        assert!(matches!(
            TablePageBitmap::decode(&[1, 2, 3], 999, 0),
            Err(PageBitmapError::WordAlignment)
        ));
        let check = |words: &[u32], n: u32| TablePageBitmap::decode(&encoded(words), 34, n);
        assert!(matches!(
            check(&[31], 0),
            Err(PageBitmapError::UniverseAlignment { .. })
        ));
        for c in [0, 0x40] {
            assert!(matches!(
                check(&[32, c], 0),
                Err(PageBitmapError::NoProgress)
            ));
        }
        assert!(matches!(
            check(&[64, 2, 1], 1),
            Err(PageBitmapError::TruncatedLiteral)
        ));
        assert!(matches!(
            check(&[64, 128], 0),
            Err(PageBitmapError::UniverseCoverage { .. })
        ));
        assert!(matches!(
            check(&[32, 256], 0),
            Err(PageBitmapError::UniverseCoverage { .. })
        ));
        assert!(matches!(
            check(&[32, 1, 1], 1),
            Err(PageBitmapError::OutOfStore { page: 0, .. })
        ));
        assert!(matches!(
            check(&[64, 129, 4], 1),
            Err(PageBitmapError::OutOfStore { page: 34, .. })
        ));
        assert!(matches!(
            check(&[64, 128, 192], 32),
            Err(PageBitmapError::OutOfStore { .. })
        ));
        assert!(matches!(
            check(&[32, 1, 2], 2),
            Err(PageBitmapError::Count { actual: 1, .. })
        ));
        assert!(check(&[], 0).unwrap().is_empty());
        assert!(matches!(
            check(&[], 1),
            Err(PageBitmapError::Count { actual: 0, .. })
        ));
    }

    pub(crate) fn stored_page(
        number: u32,
        owner: u32,
        kind: u8,
        slot_count: u16,
        live: u8,
        payload: Option<&[u8]>,
    ) -> [u8; PAGE_SIZE] {
        let mut logical = [0x8bu8; 512];
        logical[..4].copy_from_slice(&number.to_le_bytes());
        logical[16] = 4;
        logical[17] = kind;
        logical[20..22].copy_from_slice(&132u16.to_le_bytes());
        logical[22..24].copy_from_slice(&slot_count.to_le_bytes());
        logical[24..28].copy_from_slice(&owner.to_le_bytes());
        logical[28..].fill(0);
        if let Some(data) = payload {
            let end = 163 + data.len();
            logical[28..30].copy_from_slice(&132u16.to_le_bytes());
            logical[30..32].copy_from_slice(&((end - 28) as u16).to_le_bytes());
            logical[160..162].copy_from_slice(&((end - 160) as u16).to_le_bytes());
            logical[162] = 0;
            logical[163..end].copy_from_slice(data);
        } else if slot_count <= 242 {
            logical[28..30].copy_from_slice(&132u16.to_le_bytes());
        } else {
            logical[20..22].copy_from_slice(&700u16.to_le_bytes());
        }
        let mut raw = [0u8; PAGE_SIZE];
        for (j, byte) in logical.iter().enumerate() {
            let i = (55 + j) % 512;
            raw[i] = byte
                .wrapping_add(41)
                .wrapping_add((i as u8).wrapping_mul(47));
        }
        raw[4080] = live;
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    #[test]
    fn mapped_owner_anchor_reopens_only_the_named_member_and_keeps_row_checks() {
        let mut bytes = vec![0; PAGE_SIZE * 5];
        let mut raw = stored_page(4, 4, 3, 2, 2, Some(&[91, 92]));
        // Damage a length word while preserving its page CRC. Header checks
        // cannot substitute for the per-record length check.
        raw[215] = raw[215].wrapping_add(1); // stored position of logical byte 160
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        bytes[4 * PAGE_SIZE..].copy_from_slice(&raw);
        let store = PageStore::from_bytes_unchecked(bytes).unwrap();
        let bitmap = TablePageBitmap::decode(&encoded(&[32, 1, 1 << 4]), 5, 1).unwrap();
        assert_eq!(
            bitmap.verify_owner(&store, 4).unwrap().occupied_slots,
            Some(2)
        );
        let calibrated = CalibratedStore::new(&store);
        assert!(matches!(
            calibrated.page(4),
            Err(RowHeaderError::Ambiguous { .. })
        ));
        let page = bitmap.page(&calibrated, 4, 4).unwrap();
        assert!(page.header().uses_owner_anchor());
        assert!(matches!(
            page.read_slot(0),
            Some(crate::RowSlotRecovery::LengthMismatch { .. })
        ));
        assert!(matches!(
            bitmap.page(&calibrated, 4, 3),
            Err(PageBitmapError::NotMember { page: 3 })
        ));
        assert!(matches!(
            bitmap.page(&calibrated, 7, 4),
            Err(PageBitmapError::Header {
                source: RowHeaderError::Ambiguous { .. },
                ..
            })
        ));
    }

    #[test]
    fn retrieves_only_a_matching_terminal_catalog_chunk_and_checks_all_named_owners() {
        let map = encoded(&[32, 1, 0b1_0000]);
        let mut all = vec![0u8; PAGE_SIZE * 5];
        // Keep the chunk's physical number distinct from its owner ID. An
        // equal header field can yield a genuinely ambiguous page anchor.
        all[PAGE_SIZE * 2..PAGE_SIZE * 3].copy_from_slice(&stored_page(
            2,
            1,
            0x12,
            2,
            2,
            Some(&map),
        ));
        all[PAGE_SIZE * 4..PAGE_SIZE * 5].copy_from_slice(&stored_page(4, 27, 3, 2, 1, None));
        let store = PageStore::from_bytes_unchecked(all).unwrap();
        let make = |tag, len| {
            PhysicalValue::OutOfRow(LongDescriptor {
                domain: 31,
                tag,
                prefix: &map[..2],
                total_len: len,
                first_page: 2,
                unknown: 0,
                slot: 0,
            })
        };
        let bitmap = TablePageBitmap::from_catalog_value(&store, &make(0, 12), 1).unwrap();
        assert_eq!(bitmap.pages().collect::<Vec<_>>(), [4]);
        let counts = bitmap.verify_owner(&store, 27).unwrap();
        assert_eq!(
            counts,
            TablePageCounts {
                live_slots: 1,
                occupied_slots: Some(1)
            }
        );
        assert!(matches!(
            bitmap.verify_owner(&store, 1),
            Err(PageBitmapError::Owner { page: 4, .. })
        ));
        assert!(matches!(
            TablePageBitmap::from_catalog_value(&store, &make(0x80, 12), 1),
            Err(PageBitmapError::Chunk(
                LongValueError::UnknownDescriptor { .. }
            ))
        ));
        assert!(matches!(
            TablePageBitmap::from_catalog_value(&store, &make(0, 96), 1),
            Err(PageBitmapError::Chunk(LongValueError::Length { .. }))
        ));
        let unknown = PhysicalValue::InlineBytes {
            domain: 31,
            bytes: &map,
        };
        assert!(matches!(
            TablePageBitmap::from_catalog_value(&store, &unknown, 1),
            Err(PageBitmapError::UnsupportedField)
        ));
        assert!(
            TablePageBitmap::from_catalog_value(&store, &PhysicalValue::Null, 0)
                .unwrap()
                .is_empty()
        );
        assert!(TablePageBitmap::from_catalog_value(&store, &PhysicalValue::Null, 1).is_err());
    }

    fn set_header_word(chunk: &mut [u8; PAGE_SIZE], at: usize, value: u16) {
        for (j, byte) in value.to_le_bytes().into_iter().enumerate() {
            let i = (55 + at + j) % 512;
            chunk[i] = byte
                .wrapping_add(41)
                .wrapping_add((i as u8).wrapping_mul(47));
        }
    }

    #[test]
    fn four_byte_empty_map_requires_the_entire_short_terminal_frame() {
        let value = PhysicalValue::OutOfRow(LongDescriptor {
            domain: 31,
            tag: 0,
            prefix: &[],
            total_len: 4,
            first_page: 2,
            unknown: 0,
            slot: 0,
        });
        let read = |bytes: &[u8], pages: u32, chunk_owner: u32| {
            let mut data = vec![0u8; 3 * PAGE_SIZE];
            data[2 * PAGE_SIZE..].copy_from_slice(&stored_page(
                2,
                chunk_owner,
                0x12,
                2,
                2,
                Some(bytes),
            ));
            let store = PageStore::from_bytes_unchecked(data).unwrap();
            TablePageBitmap::from_catalog_value_for_owner(&store, &value, pages, 9)
        };
        assert!(read(&[0; 6], 0, 1).unwrap().is_empty());
        assert!(read(&[0; 4], 0, 1).unwrap().is_empty());
        assert!(read(&[0, 0, 0, 0, 0xa9, 0xaa], 0, 1).unwrap().is_empty());
        for payload in [&[1, 0, 0, 0, 0, 0][..], &[0; 5], &[0; 7]] {
            assert!(read(payload, 0, 1).is_err());
        }
        assert!(read(&[0; 6], 1, 1).is_err());
        assert!(read(&[0; 6], 0, 2).is_err());
    }

    #[test]
    fn empty_map_retains_opaque_minimum_allocation_surplus() {
        let payload = [0, 0, 0, 0, 0xa9, 0xaa];
        let mut data = vec![0; 3 * PAGE_SIZE];
        data[2 * PAGE_SIZE..].copy_from_slice(&stored_page(2, 1, 0x12, 2, 2, Some(&payload)));
        let store = PageStore::from_bytes_unchecked(data).unwrap();
        let descriptor = LongDescriptor {
            domain: 31,
            tag: 0,
            prefix: &[],
            total_len: 4,
            first_page: 2,
            unknown: 0,
            slot: 0,
        };
        let value = PhysicalValue::OutOfRow(LongDescriptor { ..descriptor });
        let map = CalibratedStore::new(&store)
            .table_page_map(&value, 0, 99)
            .unwrap();
        assert!(map.bitmap.is_empty());
        assert_eq!(map.counts.occupied_slots, Some(0));
        assert_eq!(
            map.empty_allocation,
            Some(EmptyMapAllocation {
                page: 2,
                slot: 0,
                payload
            })
        );
        for bad in [
            LongDescriptor {
                total_len: 0,
                ..descriptor
            },
            LongDescriptor {
                total_len: 3,
                ..descriptor
            },
            LongDescriptor {
                tag: 0x80,
                ..descriptor
            },
            LongDescriptor {
                unknown: 1,
                ..descriptor
            },
            LongDescriptor {
                prefix: &[0],
                ..descriptor
            },
        ] {
            assert!(
                CalibratedStore::new(&store)
                    .table_page_map(&PhysicalValue::OutOfRow(bad), 0, 99)
                    .is_err()
            );
        }
    }

    #[test]
    fn positive_map_requires_a_sole_repeated_header_even_when_a_second_key_cannot_supply_the_chunk()
    {
        const CHUNK: usize = 2;
        let payload = encoded(&[32, 1, 1 << 4]);
        let mut raw = stored_page(CHUNK as u32, 1, 0x12, 2, 2, Some(&payload));
        set_header_word(&mut raw, 350, CHUNK as u16);
        set_header_word(&mut raw, 352, 0);
        let read_store = |mut raw: [u8; PAGE_SIZE]| {
            let crc = crc32fast::hash(&raw[..4092]);
            raw[4092..].copy_from_slice(&crc.to_le_bytes());
            let mut all = vec![0; 5 * PAGE_SIZE];
            all[CHUNK * PAGE_SIZE..(CHUNK + 1) * PAGE_SIZE].copy_from_slice(&raw);
            all[4 * PAGE_SIZE..5 * PAGE_SIZE].copy_from_slice(&stored_page(4, 27, 3, 2, 1, None));
            PageStore::from_bytes_unchecked(all).unwrap()
        };
        let store = read_store(raw);
        let reader = crate::CalibratedStore::new(&store);
        let field = |len, prefix| {
            PhysicalValue::OutOfRow(LongDescriptor {
                domain: 31,
                prefix,
                tag: 0,
                total_len: len,
                first_page: CHUNK as u32,
                unknown: 0,
                slot: 0,
            })
        };
        assert!(matches!(
            reader.page(CHUNK as u32),
            Err(RowHeaderError::Ambiguous { .. })
        ));
        let result = reader.table_page_map(&field(12, &[32]), 1, 27).unwrap();
        assert!(result.repeated_map_header);
        assert_eq!(result.calibrated_sector_uses, 0);
        assert_eq!(result.bitmap.pages().collect::<Vec<_>>(), [4]);
        assert!(matches!(
            reader.table_page_map(&field(12, &[]), 1, 28),
            Err(PageBitmapError::Owner { .. })
        ));
        assert!(matches!(
            reader.table_page_map(&field(12, &[]), 2, 27),
            Err(PageBitmapError::Count { .. })
        ));
        assert!(matches!(
            reader.table_page_map(&field(12, &[99]), 1, 27),
            Err(PageBitmapError::Chunk(LongValueError::Prefix))
        ));
        assert!(matches!(
            reader.table_page_map(&field(11, &[]), 1, 27),
            Err(PageBitmapError::Chunk(LongValueError::Length { .. }))
        ));
        assert!(matches!(
            reader.table_page_map(&field(12, &[]), 0, 27),
            Err(PageBitmapError::Chunk(LongValueError::Header(
                RowHeaderError::Ambiguous { .. }
            )))
        ));
        // Add a second genuine odd rotation by translating the same structural
        // bytes half a frame. Give this rival a wrong chunk owner. The map's
        // semantics must not be used to select the other structural key.
        for logical in 0..180 {
            let pos = (55 + logical) % 512;
            raw[(pos + 256) % 512] = raw[pos];
        }
        set_header_word(&mut raw, 256 + 24, 99);
        let competing = read_store(raw);
        let page = competing.page(CHUNK as u64).unwrap();
        assert_eq!(
            RowPageHeader::structural_candidates(page).unwrap().count(),
            2
        );
        assert!(matches!(
            crate::CalibratedStore::new(&competing).table_page_map(&field(12, &[]), 1, 27),
            Err(PageBitmapError::Chunk(LongValueError::Header(
                RowHeaderError::Ambiguous { .. }
            )))
        ));
    }

    fn sparse_fixture(alternate: bool, wrong_length: bool) -> PageStore {
        // One 15-byte chunk at 1009..1024 has just one complete word in
        // sector 1: its own length. The next row starts in sector 2.
        let mut chunk = stored_page(2, 1, 0x11, 2, 2, None);
        set_header_word(&mut chunk, 20, 1009 - 28);
        set_header_word(&mut chunk, 28, 1009 - 28);
        set_header_word(&mut chunk, 30, 1024 - 28);
        for i in 0..512 {
            chunk[512 + i] = ((i * i * 3 + 19 * i) / 7) as u8;
        }
        let mut add = |rotation: usize, set_page: u32, stored_len: u16| {
            let d = 55u8.wrapping_mul(47);
            let step = (0u8..=255)
                .find(|k| (rotation as u8).wrapping_mul(*k) == d)
                .unwrap();
            let mut row = stored_len.to_le_bytes().to_vec();
            row.push(0);
            row.extend(encoded(&[32, 1, 1 << set_page]));
            for (j, v) in row.into_iter().enumerate() {
                let i = (1009 - 512 + j + rotation) % 512;
                chunk[512 + i] = v
                    .wrapping_add(42)
                    .wrapping_add((i as u8).wrapping_mul(step));
            }
        };
        add(73, 4, if wrong_length { 14 } else { 15 });
        if alternate {
            add(173, 5, 14);
        }
        let crc = crc32fast::hash(&chunk[..4092]);
        chunk[4092..].copy_from_slice(&crc.to_le_bytes());
        let mut all = vec![0u8; 6 * PAGE_SIZE];
        all[2 * PAGE_SIZE..3 * PAGE_SIZE].copy_from_slice(&chunk);
        for pn in [4usize, 5] {
            all[pn * PAGE_SIZE..(pn + 1) * PAGE_SIZE]
                .copy_from_slice(&stored_page(pn as u32, 27, 3, 2, 1, None));
        }
        PageStore::from_bytes_unchecked(all).unwrap()
    }

    fn sparse_reference(prefix: &[u8]) -> PhysicalValue<'_> {
        PhysicalValue::OutOfRow(LongDescriptor {
            domain: 31,
            tag: 0,
            prefix,
            total_len: 12,
            first_page: 2,
            unknown: 0,
            slot: 0,
        })
    }

    #[test]
    fn sparse_bitmap_is_confirmed_by_size_owner_and_an_unused_length_word() {
        let store = sparse_fixture(false, false);
        let value = sparse_reference(&[32, 0]);
        assert!(matches!(
            TablePageBitmap::from_catalog_value(&store, &value, 1),
            Err(PageBitmapError::Chunk(LongValueError::Unavailable))
        ));
        let map = TablePageBitmap::from_catalog_value_for_owner(&store, &value, 1, 27).unwrap();
        assert_eq!(map.pages().collect::<Vec<_>>(), [4]);
        let read = crate::CalibratedStore::new(&store)
            .table_page_map(&value, 1, 27)
            .unwrap();
        assert_eq!(read.bitmap, map);
        assert_eq!(read.calibrated_sector_uses, 0);
        assert!(TablePageBitmap::from_catalog_value_for_owner(&store, &value, 1, 28).is_err());
        assert!(
            TablePageBitmap::from_catalog_value_for_owner(
                &store,
                &sparse_reference(&[31, 0]),
                1,
                27
            )
            .is_err()
        );
        assert!(TablePageBitmap::from_catalog_value_for_owner(&store, &value, 0, 27).is_err());
    }

    #[test]
    fn a_known_length_from_another_sector_cannot_confirm_a_sparse_map() {
        // The declared 512-byte payload occupies sector 1, but the length and
        // flags lie entirely in sector zero and the next slot starts in sector 2.
        let mut chunk = stored_page(2, 1, 0x11, 2, 2, None);
        for (off, value) in [(20, 509 - 28), (28, 509 - 28), (30, 1024 - 28), (509, 515)] {
            set_header_word(&mut chunk, off, value);
        }
        let crc = crc32fast::hash(&chunk[..4092]);
        chunk[4092..].copy_from_slice(&crc.to_le_bytes());
        let mut data = vec![0; PAGE_SIZE * 3];
        data[2 * PAGE_SIZE..].copy_from_slice(&chunk);
        let store = PageStore::from_bytes_unchecked(data).unwrap();
        let value = PhysicalValue::OutOfRow(LongDescriptor {
            domain: 31,
            tag: 0,
            prefix: &[],
            total_len: 512,
            first_page: 2,
            unknown: 0,
            slot: 0,
        });
        assert!(matches!(
            TablePageBitmap::from_catalog_value_for_owner(&store, &value, 1, 27),
            Err(PageBitmapError::NoBitmapWitness)
        ));
    }

    #[test]
    fn sparse_wrong_length_rejects_and_cannot_choose_between_different_maps() {
        let value = sparse_reference(&[32, 0]);
        let wrong = sparse_fixture(false, true);
        assert!(matches!(
            TablePageBitmap::from_catalog_value_for_owner(&wrong, &value, 1, 27),
            Err(PageBitmapError::NoBitmapWitness)
        ));
        // Two different bitmap payloads have the declared size and the right
        // owner. Only the first has the right held-out length; it must not win.
        let ambiguous = sparse_fixture(true, false);
        assert!(matches!(
            crate::CalibratedStore::new(&ambiguous).table_page_map(&value, 1, 27),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
        assert!(matches!(
            TablePageBitmap::from_catalog_value_for_owner(&ambiguous, &value, 1, 27),
            Err(PageBitmapError::AmbiguousSparseMap)
        ));
    }

    #[test]
    fn owner_verification_distinguishes_a_partial_directory_and_blob_pages() {
        let bytes = encoded(&[32, 1, 4]);
        let map = TablePageBitmap::decode(&bytes, 3, 1).unwrap();
        for kind in [3, 0x11] {
            let mut data = vec![0u8; PAGE_SIZE * 3];
            data[PAGE_SIZE * 2..].copy_from_slice(&stored_page(2, 27, kind, 243, 1, None));
            let store = PageStore::from_bytes_unchecked(data).unwrap();
            let result = map.verify_owner(&store, 27);
            if kind == 3 {
                assert_eq!(
                    result.unwrap(),
                    TablePageCounts {
                        live_slots: 1,
                        occupied_slots: None
                    }
                );
            } else {
                assert!(matches!(result, Err(PageBitmapError::NotTableRow { .. })));
            }
        }
    }
}
