//! Resolve the observed single-chunk form of byte-valued out-of-row fields.
//! The zero-based slot points to a record under the originating table owner.
//! The first bytes of that record's payload duplicate the in-row prefix in
//! the samples where both are recovered.

use crate::{
    CalibratedStore, CalibrationGap, LongDescriptor, PageStore, RowHeaderError, RowLengthMismatch,
    RowPageHeader, RowSectorReader, RowSlotRecovery, RowSlotSector,
};

/// Evidence for another occupied slot whose physical span could hold the
/// advertised domain-10 payload. Every such slot must be independently read.
#[derive(Debug)]
pub struct TextChunkPeer<'a> {
    /// Zero-based physical slot on the selected chunk page.
    pub slot: u16,
    /// True when this complete terminal payload equaled the selected bytes.
    /// Otherwise its checked prefix differed from the descriptor's prefix.
    pub identical_payload: bool,
    /// Regions used to check the rival's complete length and payload.
    pub sectors: Vec<RowSlotSector<'a>>,
}

/// Candidate bytes from one terminal chunk. The source page's sector evidence
/// remains attached; a physical slot can belong to an inactive record.
#[derive(Debug)]
pub struct LongValueCandidate<'a> {
    /// Complete descriptor-length value, including its in-row prefix once.
    pub bytes: Vec<u8>,
    /// Entire physical payload length after the terminal chunk's three-byte header.
    pub physical_payload_len: usize,
    /// All physical bytes beyond the descriptor length, in their original order.
    pub surplus: Vec<u8>,
    /// Physical chunk page from the descriptor.
    pub page: u32,
    /// Zero-based physical slot on that page.
    pub slot: u16,
    /// Evidence for the regions used to reconstruct the chunk record.
    pub sectors: Vec<RowSlotSector<'a>>,
    /// Other occupied slots with compatible spans tested for a domain-10
    /// value. Empty for domains that do not require this page-wide check.
    pub text_peers: Vec<TextChunkPeer<'a>>,
}

impl LongValueCandidate<'_> {
    /// Length of the full physical row, including its stored length and flags.
    /// The reader checks that length against the complete slot directory span.
    pub fn physical_frame_len(&self) -> usize {
        self.physical_payload_len + 3
    }
}

/// Resolve one out-of-row value using the table owner of the originating row.
/// Domain 10 requires at least four overlapping prefix bytes and a complete
/// check of every other occupied slot with a compatible physical span on the
/// referenced page. Only one distinct terminal payload may satisfy that
/// prefix and descriptor length. Domains 9, 12 and 28 use the direct reference. A
/// one- through five-byte domain-12 value can occupy a six-byte payload when
/// its descriptor prefix is empty. The nine-byte terminal allocation can retain
/// nonzero surplus after shrinking a value.
/// The result retains the physical payload length
/// and every byte beyond the descriptor length.
pub fn resolve_single_chunk<'a>(
    store: &'a PageStore,
    owner_id: u32,
    descriptor: &LongDescriptor<'_>,
) -> Result<LongValueCandidate<'a>, LongValueError> {
    require_byte_domain(descriptor)?;
    resolve_byte_counted_chunk(store, owner_id, descriptor)
}

impl<'a> CalibratedStore<'a> {
    /// Resolve one terminal byte-counted chunk under the same store calibration
    /// used for the referring row. Ordinary sector evidence takes precedence.
    /// Every calibrated region must have an independently matched whole length
    /// word, in addition to all owner, chunk, length and prefix checks.
    pub fn resolve_single_chunk(
        &self,
        owner_id: u32,
        descriptor: &LongDescriptor<'_>,
    ) -> Result<LongValueCandidate<'a>, LongValueError> {
        require_byte_domain(descriptor)?;
        self.resolve_byte_counted_chunk(owner_id, descriptor)
    }

    // Domain 31 gets this byte-framing interpretation only for a caller-identified
    // ISYSTAB page map, which must separately verify its count and named pages.
    pub(crate) fn resolve_byte_counted_chunk(
        &self,
        owner_id: u32,
        descriptor: &LongDescriptor<'_>,
    ) -> Result<LongValueCandidate<'a>, LongValueError> {
        check_reference(self.store(), descriptor)?;
        let reader = self.page(descriptor.first_page)?;
        read_chunk(owner_id, descriptor, reader.header(), |slot| {
            reader.read_slot(slot)
        })
    }
}

fn require_byte_domain(descriptor: &LongDescriptor<'_>) -> Result<(), LongValueError> {
    if matches!(descriptor.domain, 9 | 10 | 12 | 28) {
        Ok(())
    } else {
        Err(LongValueError::UnsupportedDomain(descriptor.domain))
    }
}

// Only call after determining that the selected field has byte-length
// framing; a domain-31 catalog bitmap is checked separately by its caller.
pub(crate) fn resolve_byte_counted_chunk<'a>(
    store: &'a PageStore,
    owner_id: u32,
    descriptor: &LongDescriptor<'_>,
) -> Result<LongValueCandidate<'a>, LongValueError> {
    check_reference(store, descriptor)?;
    let reader = RowSectorReader::new(store.page(u64::from(descriptor.first_page))?)?;
    read_chunk(owner_id, descriptor, reader.header(), |slot| {
        reader.read_slot(slot)
    })
}

pub(crate) fn check_reference(
    store: &PageStore,
    descriptor: &LongDescriptor<'_>,
) -> Result<(), LongValueError> {
    if descriptor.tag != 0 || descriptor.unknown != 0 {
        return Err(LongValueError::UnknownDescriptor {
            tag: descriptor.tag,
            word: descriptor.unknown,
        });
    }
    let page_number = u64::from(descriptor.first_page);
    if page_number == 0 || page_number >= store.page_count() {
        return Err(LongValueError::PageRange {
            page: descriptor.first_page,
            pages: store.page_count(),
        });
    }
    Ok(())
}

pub(crate) fn read_chunk<'a>(
    owner_id: u32,
    descriptor: &LongDescriptor<'_>,
    header: &RowPageHeader,
    mut read_slot: impl FnMut(u16) -> Option<RowSlotRecovery<'a>>,
) -> Result<LongValueCandidate<'a>, LongValueError> {
    if descriptor.domain == 10 {
        let prefix = descriptor.prefix.len();
        if prefix < 4 {
            return Err(LongValueError::ShortTextPrefix(prefix));
        }
        // 0x80..0xfe are indirect markers. 0xff denotes an extended inline length.
        if prefix > 126 || prefix > descriptor.total_len as usize {
            return Err(LongValueError::InvalidTextPrefix {
                prefix,
                length: descriptor.total_len,
            });
        }
    }
    if header.owner_id() != owner_id {
        return Err(LongValueError::Owner {
            expected: owner_id,
            actual: header.owner_id(),
        });
    }
    if !(0x11..=0x14).contains(&header.page_kind()) {
        return Err(LongValueError::PageKind(header.page_kind()));
    }
    let (bytes, sectors) = match read_slot(descriptor.slot) {
        None => return Err(LongValueError::SlotRange(descriptor.slot)),
        Some(RowSlotRecovery::Vacant) => return Err(LongValueError::Vacant(descriptor.slot)),
        Some(RowSlotRecovery::IncompleteDirectory) => return Err(LongValueError::PartialDirectory),
        Some(RowSlotRecovery::Unavailable { sectors, .. }) => {
            let mut reasons = sectors.into_iter().filter_map(|sector| match sector {
                RowSlotSector::CalibrationGap { reason, .. } => Some(reason),
                _ => None,
            });
            if let Some(first) = reasons.next() {
                let reason = if reasons.any(|reason| reason == CalibrationGap::NoAnchor) {
                    CalibrationGap::NoAnchor
                } else {
                    first
                };
                return Err(LongValueError::Calibration(reason));
            }
            return Err(LongValueError::Unavailable);
        }
        Some(RowSlotRecovery::LengthMismatch { error, .. }) => return Err(error.into()),
        Some(RowSlotRecovery::Candidate { bytes, sectors, .. }) => (bytes, sectors),
    };
    // read_slot has independently verified the stored u16 against this physical span.
    let Some((&[_, _, flags], payload)) = bytes.split_first_chunk::<3>() else {
        return Err(LongValueError::TruncatedChunk);
    };
    if flags & 4 != 0 {
        return Err(LongValueError::Continuation);
    }
    if flags != 0 {
        return Err(LongValueError::ChunkFlags(flags));
    }
    let length = descriptor.total_len as usize;
    if payload.len() != length {
        let short_binary = descriptor.domain == 12
            && descriptor.tag == 0
            && descriptor.unknown == 0
            && descriptor.prefix.is_empty()
            && payload.len() == 6
            && (1..=5).contains(&length);
        if !short_binary {
            return Err(LongValueError::Length {
                expected: descriptor.total_len,
                actual: payload.len(),
            });
        }
    }
    let (value, surplus) = payload.split_at(length);
    if !value.starts_with(descriptor.prefix) {
        return Err(LongValueError::Prefix);
    }
    let text_peers = if descriptor.domain == 10 {
        check_text_peers(header, descriptor, value, read_slot)?
    } else {
        Vec::new()
    };
    Ok(LongValueCandidate {
        bytes: value.to_vec(),
        physical_payload_len: payload.len(),
        surplus: surplus.to_vec(),
        page: descriptor.first_page,
        slot: descriptor.slot,
        sectors,
        text_peers,
    })
}

fn check_text_peers<'a>(
    header: &RowPageHeader,
    descriptor: &LongDescriptor<'_>,
    value: &[u8],
    mut read_slot: impl FnMut(u16) -> Option<RowSlotRecovery<'a>>,
) -> Result<Vec<TextChunkPeer<'a>>, LongValueError> {
    let rows = header
        .physical_rows()
        .ok_or(LongValueError::PartialDirectory)?;
    let mut peers = Vec::new();
    for row in rows {
        let slot = row.slot();
        if slot == descriptor.slot || row.length() != value.len() + 3 {
            continue;
        }
        let Some(RowSlotRecovery::Candidate { bytes, sectors, .. }) = read_slot(slot) else {
            return Err(LongValueError::IndeterminateTextPeer(slot));
        };
        let Some((&[_, _, 0], payload)) = bytes.split_first_chunk::<3>() else {
            return Err(LongValueError::IndeterminateTextPeer(slot));
        };
        // Stored length matches this physical span. Its exact terminal
        // payload can be excluded only by comparing actual prefix bytes.
        let identical_payload = value == payload;
        if !identical_payload && payload.starts_with(descriptor.prefix) {
            return Err(LongValueError::ConflictingTextPeer(slot));
        }
        peers.push(TextChunkPeer {
            slot,
            identical_payload,
            sectors,
        });
    }
    Ok(peers)
}

/// Why an out-of-row reference did not yield a complete single-chunk value.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LongValueError {
    /// The domain lacks confirmed single-chunk byte-length semantics.
    #[error("domain {0} has no supported byte-length chunk model")]
    UnsupportedDomain(u16),
    /// Domain 10 needs at least four independently overlapping prefix bytes.
    #[error("domain-10 chunk prefix has only {0} bytes")]
    ShortTextPrefix(usize),
    /// The prefix exceeds the indirect marker capacity or advertised byte length.
    #[error(
        "text prefix length {prefix} is incompatible with the indirect frame or length {length}"
    )]
    InvalidTextPrefix {
        /// Prefix byte count in the reference.
        prefix: usize,
        /// Logical length advertised by the reference.
        length: u32,
    },
    /// An occupied rival with compatible span could not be independently
    /// recovered as a complete terminal payload.
    #[error("compatible text chunk slot {0} is indeterminate")]
    IndeterminateTextPeer(u16),
    /// Another terminal payload at the advertised length has the same prefix
    /// but differs elsewhere.
    #[error("text chunk slot {0} shares the descriptor prefix and length but differs in payload")]
    ConflictingTextPeer(u16),
    /// The descriptor contains an unrecognized tag or unidentified-word value.
    #[error("unsupported descriptor tag {tag:#04x} or word {word:#06x}")]
    UnknownDescriptor {
        /// Descriptor tag.
        tag: u8,
        /// Unidentified stored word.
        word: u16,
    },
    /// The reference does not address a possible physical data page.
    #[error("chunk page {page} is outside data pages in a {pages}-page store")]
    PageRange {
        /// Referenced physical page.
        page: u32,
        /// Total pages, including the superblock.
        pages: u64,
    },
    /// Reading the page from the store failed.
    #[error(transparent)]
    Page(#[from] crate::Error),
    /// CRC, physical page identity, or the row header could not be verified.
    #[error(transparent)]
    Header(#[from] RowHeaderError),
    /// The page belongs to another physical table.
    #[error("chunk page owner is {actual}, referring row owner is {expected}")]
    Owner {
        /// Origination table owner.
        expected: u32,
        /// Chunk page owner.
        actual: u32,
    },
    /// The target is outside the observed chunk page kinds.
    #[error("unexpected chunk page kind {0:#04x}")]
    PageKind(u8),
    /// The physical slot is outside the page's slot count.
    #[error("chunk slot {0} is outside the slot directory")]
    SlotRange(u16),
    /// The target slot is empty.
    #[error("chunk slot {0} is vacant")]
    Vacant(u16),
    /// The end of the slot cannot be determined.
    #[error("chunk page has an incomplete slot directory")]
    PartialDirectory,
    /// At least one sector of the chunk row could not be reconstructed.
    #[error("chunk row has unresolved bytes")]
    Unavailable,
    /// The calibrated path could not corroborate a missing chunk region.
    #[error("chunk region unavailable: {0}")]
    Calibration(#[source] CalibrationGap),
    /// The stored length disagrees with the slot span.
    #[error(transparent)]
    RowLength(#[from] RowLengthMismatch),
    /// The entire row is too short to contain length and flags.
    #[error("chunk row is too short for length and flags")]
    TruncatedChunk,
    /// The chunk indicates another page; single-chunk recovery stops here.
    #[error("chunk declares a continuation")]
    Continuation,
    /// The terminal chunk flags do not match the observed form.
    #[error("unrecognized terminal chunk flags {0:#04x}")]
    ChunkFlags(u8),
    /// The payload and reference lengths differ outside the supported short binary form.
    #[error("expected {expected} payload bytes, chunk contains {actual}")]
    Length {
        /// Advertised byte length in the descriptor.
        expected: u32,
        /// Available bytes after the chunk header.
        actual: usize,
    },
    /// An overlapping prefix differs from the referring record.
    #[error("chunk payload disagrees with the descriptor's in-row prefix")]
    Prefix,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PAGE_SIZE;

    // Put the target in physical slot one and in logical sector zero. An
    // adjacent occupied slot delimits the target independently of its u16.
    fn fixture(kind: u8, flags: u8, payload: &[u8]) -> PageStore {
        owned_fixture(111, kind, flags, payload)
    }

    fn owned_fixture(owner: u32, kind: u8, flags: u8, payload: &[u8]) -> PageStore {
        let mut all = vec![0; PAGE_SIZE * 2];
        let mut plain = [0x9bu8; 512];
        let end = 160 + 3 + payload.len();
        plain[..4].copy_from_slice(&1u32.to_le_bytes());
        plain[16] = 4;
        plain[17] = kind;
        plain[20..22].copy_from_slice(&(160u16 - 28).to_le_bytes());
        plain[22..24].copy_from_slice(&3u16.to_le_bytes());
        plain[24..28].copy_from_slice(&owner.to_le_bytes());
        plain[28..30].copy_from_slice(&0u16.to_le_bytes());
        plain[30..32].copy_from_slice(&(160u16 - 28).to_le_bytes());
        plain[32..34].copy_from_slice(&((end - 28) as u16).to_le_bytes());
        plain[160..162].copy_from_slice(&((end - 160) as u16).to_le_bytes());
        plain[162] = flags;
        plain[163..end].copy_from_slice(payload);
        let raw = &mut all[PAGE_SIZE..];
        for (offset, &byte) in plain.iter().enumerate() {
            let i = (offset + 63) % 512;
            raw[i] = byte
                .wrapping_add(97)
                .wrapping_add((i as u8).wrapping_mul(11));
        }
        raw[4080] = 2;
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        PageStore::from_bytes_unchecked(all).unwrap()
    }

    fn reference<'a>(domain: u16, prefix: &'a [u8], len: u32) -> LongDescriptor<'a> {
        LongDescriptor {
            domain,
            prefix,
            tag: 0,
            total_len: len,
            first_page: 1,
            unknown: 0,
            slot: 1,
        }
    }

    #[test]
    fn returns_exact_binary_bytes_and_prefix_once() {
        let payload = [0, 0xff, 0x80, 3, 5];
        let store = fixture(0x11, 0, &payload);
        let d = reference(12, &payload[..3], 5);
        let value = resolve_single_chunk(&store, 111, &d).unwrap();
        assert_eq!(value.bytes, payload);
        assert_eq!((value.page, value.slot), (1, 1));
        assert!(matches!(value.sectors.as_slice(), [RowSlotSector::Header]));
        let empty = fixture(0x14, 0, &[]);
        assert!(
            resolve_single_chunk(&empty, 111, &reference(9, &[], 0))
                .unwrap()
                .bytes
                .is_empty()
        );
    }

    #[test]
    fn short_domain12_retains_value_and_surplus_from_the_exact_physical_slot() {
        // The same four logical bytes can occupy slots with different physical tails.
        // Include trailing zeros inside each logical length and zeros inside the surplus.
        for (length, payload) in [
            (1usize, [0, 0xab, 0x92, 0, 0xab, 0xcd]),
            (2, [0xff, 0, 0x92, 0, 0xab, 0xcd]),
            (3, [0xff, 0, 0x92, 0, 0xab, 0xcd]),
            (4usize, [0xff, 0, 0x92, 0, 0, 0]),
            (4, [0xff, 0, 0x92, 0, 0xab, 0]),
            (4, [0xff, 0, 0x92, 0, 0, 0xcd]),
            (4, [0xff, 0, 0x92, 0, 0xab, 0xcd]),
            (5, [0xff, 0, 0x92, 0xab, 0, 0]),
            (5, [0xff, 0, 0x92, 0xab, 0, 0xcd]),
        ] {
            let store = fixture(0x12, 0, &payload);
            let d = reference(12, &[], length as u32);
            let calibrated = CalibratedStore::new(&store);
            for candidate in [
                resolve_single_chunk(&store, 111, &d).unwrap(),
                calibrated.resolve_single_chunk(111, &d).unwrap(),
            ] {
                assert_eq!(candidate.bytes, payload[..length]);
                assert_eq!(candidate.surplus, payload[length..]);
                assert_eq!(candidate.physical_payload_len, 6);
                assert_eq!(candidate.physical_frame_len(), 9);
                assert_eq!((candidate.page, candidate.slot), (1, 1));
                assert!(matches!(
                    candidate.sectors.as_slice(),
                    [RowSlotSector::Header]
                ));
            }
        }
        let exact = fixture(0x12, 0, &[1, 2, 0, 0]);
        let value = resolve_single_chunk(&exact, 111, &reference(12, &[1, 2], 4)).unwrap();
        assert_eq!(value.bytes, [1, 2, 0, 0]);
        assert!(value.surplus.is_empty());
        assert_eq!(value.physical_payload_len, 4);
        assert_eq!(value.physical_frame_len(), 7);
    }

    #[test]
    fn one_and_two_byte_column_catalog_values_keep_the_entire_terminal() {
        for (length, payload) in [(1, [0, 0, 0, 0, 0, 0]), (2, [0xa7, 0, 0, 0, 0, 0])] {
            let store = owned_fixture(2, 0x12, 0, &payload);
            let d = reference(12, &[], length);
            let calibrated = CalibratedStore::new(&store);
            for value in [
                resolve_single_chunk(&store, 2, &d).unwrap(),
                calibrated.resolve_single_chunk(2, &d).unwrap(),
            ] {
                assert_eq!(value.bytes, payload[..length as usize]);
                assert_eq!(value.surplus, payload[length as usize..]);
                assert_eq!(value.physical_frame_len(), 9);
                assert_eq!((value.page, value.slot), (1, 1));
                assert!(matches!(value.sectors.as_slice(), [RowSlotSector::Header]));
            }
        }
    }

    #[test]
    fn minimum_binary_allocation_keeps_descriptor_owner_and_framing_checks() {
        let zeros = [0; 6];
        let store = owned_fixture(2, 0x12, 0, &zeros);
        for d in [
            reference(12, &[], 0),
            reference(12, &[], 7),
            reference(12, &[0], 2),
            reference(9, &[], 2),
            reference(28, &[], 1),
        ] {
            assert!(matches!(
                resolve_single_chunk(&store, 2, &d),
                Err(LongValueError::Length { .. })
            ));
        }
        for (length, surplus_at) in [(1, 1), (1, 5), (2, 2), (2, 5)] {
            let mut payload = zeros;
            payload[surplus_at] = 0x80;
            let bad = owned_fixture(2, 0x12, 0, &payload);
            let value = resolve_single_chunk(&bad, 2, &reference(12, &[], length)).unwrap();
            assert_eq!(value.bytes, payload[..length as usize]);
            assert_eq!(value.surplus, payload[length as usize..]);
        }
        let other = owned_fixture(3, 0x12, 0, &zeros);
        let d = reference(12, &[], 2);
        assert_eq!(resolve_single_chunk(&other, 3, &d).unwrap().bytes, [0; 2]);
        assert!(matches!(
            resolve_single_chunk(&other, 2, &d),
            Err(LongValueError::Owner { .. })
        ));
        for size in [5, 7] {
            let bad = owned_fixture(2, 0x12, 0, &[0; 7][..size]);
            assert!(
                matches!(resolve_single_chunk(&bad, 2, &d), Err(LongValueError::Length { actual, .. }) if actual == size)
            );
        }
        for (tag, unknown) in [(0x80, 0), (0, 1)] {
            let bad = LongDescriptor {
                tag,
                unknown,
                ..reference(12, &[], 1)
            };
            assert!(matches!(
                resolve_single_chunk(&store, 2, &bad),
                Err(LongValueError::UnknownDescriptor { .. })
            ));
        }
        let vacant = LongDescriptor {
            slot: 0,
            ..reference(12, &[], 1)
        };
        assert!(matches!(
            resolve_single_chunk(&store, 2, &vacant),
            Err(LongValueError::Vacant(0))
        ));
        let continued = owned_fixture(2, 0x12, 4, &zeros);
        assert!(matches!(
            resolve_single_chunk(&continued, 2, &d),
            Err(LongValueError::Continuation)
        ));
        let nonterminal = owned_fixture(2, 0x12, 0x80, &zeros);
        assert!(matches!(
            resolve_single_chunk(&nonterminal, 2, &d),
            Err(LongValueError::ChunkFlags(0x80))
        ));
    }

    #[test]
    fn short_binary_allocation_requires_the_exact_descriptor_and_terminal_slot() {
        let payload = [0x80, 0x23, 0, 0x56, 0, 0xab];
        let store = fixture(0x11, 0, &payload);
        for (domain, prefix, length) in [
            (9, &[][..], 4),
            (28, &[][..], 5),
            (12, &[0x80][..], 4),
            (12, &[][..], 0),
            (12, &[][..], 7),
        ] {
            assert!(matches!(
                resolve_single_chunk(&store, 111, &reference(domain, prefix, length)),
                Err(LongValueError::Length { .. })
            ));
        }
        let wrong_slot = LongDescriptor {
            slot: 0,
            ..reference(12, &[], 4)
        };
        assert!(matches!(
            resolve_single_chunk(&store, 111, &wrong_slot),
            Err(LongValueError::Vacant(0))
        ));
        assert!(matches!(
            resolve_single_chunk(&store, 112, &reference(12, &[], 4)),
            Err(LongValueError::Owner { .. })
        ));
        let over = fixture(0x12, 0, &[0; 7]);
        assert!(matches!(
            resolve_single_chunk(&over, 111, &reference(12, &[], 5)),
            Err(LongValueError::Length { actual: 7, .. })
        ));
        let continuation = fixture(0x12, 4, &payload);
        let flags = fixture(0x12, 0x80, &payload);
        let d = reference(12, &[], 4);
        assert!(matches!(
            resolve_single_chunk(&continuation, 111, &d),
            Err(LongValueError::Continuation)
        ));
        assert!(matches!(
            resolve_single_chunk(&flags, 111, &d),
            Err(LongValueError::ChunkFlags(0x80))
        ));
        for (tag, unknown) in [(0x80, 0), (0, 1)] {
            let d = LongDescriptor {
                tag,
                unknown,
                ..reference(12, &[], 4)
            };
            assert!(matches!(
                resolve_single_chunk(&store, 111, &d),
                Err(LongValueError::UnknownDescriptor { .. })
            ));
        }
        // Domain 31 is available only to the catalog reader, with its own
        // independently checked empty-map exception. Even all-zero padding
        // cannot enter that path through the binary-value reader.
        let zero = fixture(0x12, 0, &[0; 6]);
        let bitmap = reference(31, &[], 4);
        assert!(matches!(
            resolve_single_chunk(&zero, 111, &bitmap),
            Err(LongValueError::UnsupportedDomain(31))
        ));
        assert!(matches!(
            resolve_byte_counted_chunk(&zero, 111, &bitmap),
            Err(LongValueError::Length {
                expected: 4,
                actual: 6
            })
        ));
        assert!(matches!(
            CalibratedStore::new(&zero).resolve_byte_counted_chunk(111, &bitmap),
            Err(LongValueError::Length {
                expected: 4,
                actual: 6
            })
        ));
    }

    #[test]
    fn refuses_wrong_owner_kind_page_slot_or_unverified_units() {
        let store = fixture(0x12, 0, &[7, 8, 9]);
        let mut d = reference(28, &[], 3);
        assert!(matches!(
            resolve_single_chunk(&store, 112, &d),
            Err(LongValueError::Owner { .. })
        ));
        let wrong = fixture(3, 0, &[7, 8, 9]);
        assert!(matches!(
            resolve_single_chunk(&wrong, 111, &d),
            Err(LongValueError::PageKind(3))
        ));
        d.slot = 0;
        assert!(matches!(
            resolve_single_chunk(&store, 111, &d),
            Err(LongValueError::Vacant(0))
        ));
        d.slot = 5;
        assert!(matches!(
            resolve_single_chunk(&store, 111, &d),
            Err(LongValueError::SlotRange(5))
        ));
        d.first_page = 2;
        assert!(matches!(
            resolve_single_chunk(&store, 111, &d),
            Err(LongValueError::PageRange { .. })
        ));
        d.first_page = 0;
        assert!(matches!(
            resolve_single_chunk(&store, 111, &d),
            Err(LongValueError::PageRange { .. })
        ));
        d.domain = 31;
        assert!(matches!(
            resolve_single_chunk(&store, 111, &d),
            Err(LongValueError::UnsupportedDomain(31))
        ));
    }

    #[test]
    fn refuses_truncation_continuations_and_false_prefixes() {
        let store = fixture(0x13, 0, &[4, 5, 6]);
        for len in [2, 4] {
            assert!(matches!(
                resolve_single_chunk(&store, 111, &reference(12, &[], len)),
                Err(LongValueError::Length { .. })
            ));
        }
        assert!(matches!(
            resolve_single_chunk(&store, 111, &reference(9, &[4, 9], 3)),
            Err(LongValueError::Prefix)
        ));
        let chained = fixture(0x13, 4, &[3, 0, 0, 0]);
        assert!(matches!(
            resolve_single_chunk(&chained, 111, &reference(12, &[], 4)),
            Err(LongValueError::Continuation)
        ));
        let unknown = fixture(0x13, 0x10, &[0, 0]);
        assert!(matches!(
            resolve_single_chunk(&unknown, 111, &reference(12, &[], 2)),
            Err(LongValueError::ChunkFlags(0x10))
        ));
        let mut d = reference(12, &[], 3);
        d.unknown = 8;
        assert!(matches!(
            resolve_single_chunk(&store, 111, &d),
            Err(LongValueError::UnknownDescriptor { word: 8, .. })
        ));
    }

    #[test]
    fn rejected_stored_length_remains_an_error_even_with_matching_descriptor() {
        let original = fixture(0x11, 0, &[0xde, 0xad]);
        let mut raw = original.page(1).unwrap().bytes().to_vec();
        // Stored sector zero places logical position 160 at position 223.
        // Change the stored row length while keeping this a CRC-valid page.
        raw[223] = raw[223].wrapping_add(1);
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        let mut pages = vec![0; PAGE_SIZE];
        pages.extend(raw);
        let store = PageStore::from_bytes_unchecked(pages).unwrap();
        assert!(matches!(
            resolve_single_chunk(&store, 111, &reference(12, &[], 2)),
            Err(LongValueError::RowLength(RowLengthMismatch {
                expected: 5,
                stored: Some(6),
                ..
            }))
        ));
    }
    fn frame(flags: u8, body: &[u8]) -> Vec<u8> {
        let mut row = ((body.len() + 3) as u16).to_le_bytes().to_vec();
        row.push(flags);
        row.extend(body);
        row
    }

    fn text_page(records: &[Vec<u8>]) -> PageStore {
        let mut all = vec![0; PAGE_SIZE * 2];
        let mut plain = [0x9bu8; 512];
        plain[..4].copy_from_slice(&1u32.to_le_bytes());
        plain[16] = 4;
        plain[17] = 0x11;
        plain[20..22].copy_from_slice(&132u16.to_le_bytes());
        plain[22..24].copy_from_slice(&((records.len() + 1) as u16).to_le_bytes());
        plain[24..28].copy_from_slice(&111u32.to_le_bytes());
        let mut start = 160;
        for i in 0..=records.len() {
            plain[28 + i * 2..30 + i * 2].copy_from_slice(&((start - 28) as u16).to_le_bytes());
            if let Some(row) = records.get(i) {
                plain[start..start + row.len()].copy_from_slice(row);
                start += row.len();
            }
        }
        let raw = &mut all[PAGE_SIZE..];
        for (logical, value) in plain.into_iter().enumerate() {
            let pos = (logical + 63) % 512;
            raw[pos] = value
                .wrapping_add(97)
                .wrapping_add((pos as u8).wrapping_mul(11));
        }
        raw[4080] = (records.len() + 1) as u8;
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        PageStore::from_bytes_unchecked(all).unwrap()
    }

    #[test]
    fn text_reference_keeps_named_slot_and_checks_all_compatible_peer_slots() {
        let bytes = [0xe1, 0x00, 0x9b, 0x45, 0xff, 0];
        let target = frame(0, &bytes);
        let different_prefix = frame(0, &[0xe1, 0x00, 0x9b, 0x99, 0xff, 0]);
        let different_span = frame(4, &[0xe1, 0x00, 0x9b, 0x45]);
        let store = text_page(&[
            target.clone(),
            target.clone(),
            different_prefix,
            different_span,
            target,
        ]);
        let descriptor = reference(10, &bytes[..4], bytes.len() as u32);
        let calibrated = CalibratedStore::new(&store);
        for value in [
            resolve_single_chunk(&store, 111, &descriptor).unwrap(),
            calibrated.resolve_single_chunk(111, &descriptor).unwrap(),
        ] {
            assert_eq!((value.page, value.slot), (1, 1));
            assert_eq!(value.bytes, bytes);
            assert_eq!(value.physical_payload_len, bytes.len());
            assert!(value.surplus.is_empty());
            let peers: Vec<_> = value
                .text_peers
                .iter()
                .map(|p| (p.slot, p.identical_payload))
                .collect();
            assert_eq!(peers, [(0, true), (2, false), (4, true)]);
            assert!(
                value
                    .text_peers
                    .iter()
                    .all(|peer| matches!(peer.sectors.as_slice(), [RowSlotSector::Header]))
            );
        }
    }

    #[test]
    fn text_with_another_matching_prefix_and_length_cannot_choose_between_payloads() {
        let target = frame(0, b"ABCDxy");
        let rival = frame(0, b"ABCDxz");
        for slot in [0usize, 2] {
            let mut rows = vec![target.clone(); 3];
            rows[slot] = rival.clone();
            let store = text_page(&rows);
            let d = reference(10, b"ABCD", 6);
            assert!(matches!(resolve_single_chunk(&store, 111, &d),
                Err(LongValueError::ConflictingTextPeer(s)) if usize::from(s) == slot));
            assert!(
                matches!(CalibratedStore::new(&store).resolve_single_chunk(111, &d),
                Err(LongValueError::ConflictingTextPeer(s)) if usize::from(s) == slot)
            );
            // The full descriptor prefix participates in the comparison.
            // With six overlapping bytes, the rival's last byte no longer matches.
            let longer = resolve_single_chunk(&store, 111, &reference(10, b"ABCDxy", 6)).unwrap();
            assert_eq!(longer.bytes, b"ABCDxy");
            assert!(
                longer
                    .text_peers
                    .iter()
                    .any(|peer| peer.slot == slot as u16 && !peer.identical_payload)
            );
            let exact = resolve_single_chunk(&store, 111, &reference(9, b"ABCD", 6)).unwrap();
            assert_eq!(exact.bytes, b"ABCDxy");
            assert!(exact.text_peers.is_empty());
        }
    }

    #[test]
    fn text_refuses_indeterminate_rivals_or_an_unverified_prefix_and_never_uses_binary_padding() {
        let target = frame(0, b"ABCDxy");
        for rival in [frame(4, b"ABCDzz"), frame(0x80, b"ABCDxy"), {
            let mut wrong = target.clone();
            wrong[0] ^= 1;
            wrong
        }] {
            let store = text_page(&[rival, target.clone()]);
            assert!(matches!(
                resolve_single_chunk(&store, 111, &reference(10, b"ABCD", 6)),
                Err(LongValueError::IndeterminateTextPeer(0))
            ));
        }
        let store = fixture(0x12, 0, b"ABCDxy");
        for p in [&b""[..], &b"ABC"[..]] {
            assert!(matches!(
                resolve_single_chunk(&store, 111, &reference(10, p, 6)),
                Err(LongValueError::ShortTextPrefix(_))
            ));
        }
        assert!(matches!(
            resolve_single_chunk(&store, 111, &reference(10, &[0; 127], 127)),
            Err(LongValueError::InvalidTextPrefix { .. })
        ));
        assert!(matches!(
            resolve_single_chunk(&store, 111, &reference(10, b"ABCDxyz", 6)),
            Err(LongValueError::InvalidTextPrefix { .. })
        ));
        assert!(matches!(
            resolve_single_chunk(&store, 111, &reference(10, b"ABCX", 6)),
            Err(LongValueError::Prefix)
        ));
        let padded = fixture(0x12, 0, b"ABCD\0\0");
        assert!(matches!(
            resolve_single_chunk(&padded, 111, &reference(10, b"ABCD", 4)),
            Err(LongValueError::Length {
                expected: 4,
                actual: 6
            })
        ));
    }
}
