//! Resolve the supported raw VARCHAR/LONG BINARY LOB chain family.
//!
//! A descriptor names the first physical slot and its logical byte length.
//! Each frame is checked against its directory allocation before its next
//! address is followed. The result keeps original frames and terminal surplus
//! separately from the concatenated logical value.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::{
    CalibratedStore, CalibrationGap, LongDescriptor, PAGE_SIZE, RowHeaderError, RowPageHeader,
    WholePageRecovery,
};

#[derive(Clone, Copy)]
enum ChainFamily {
    Original,
    Stored,
    Bitset,
}

/// Exact stored record and its independently bounded directory allocation.
#[derive(Debug, Clone)]
pub struct ByteChainChunk {
    /// Physical source page.
    pub page: u32,
    /// Zero-based source slot.
    pub slot: u16,
    /// Table owner corroborated by the source header.
    pub owner: u32,
    /// Overflow page kind, in 0x11..=0x14.
    pub page_kind: u8,
    /// Logical start within the page.
    pub start: usize,
    /// End of the directory allocation; may exceed the stored kind-20 frame.
    pub allocation_end: usize,
    /// Complete frame, including its length, flags and optional next locator.
    pub record: Vec<u8>,
}

/// A descriptor-length value plus all framing and unused terminal bytes.
#[derive(Debug)]
pub struct ByteChainCandidate {
    /// Logical value, including the overlapping in-row prefix once.
    pub bytes: Vec<u8>,
    /// Exact physical records in pointer order.
    pub chunks: Vec<ByteChainChunk>,
    /// Terminal payload bytes beyond the descriptor's logical length.
    pub surplus: Vec<u8>,
    /// Complete-page key and framing evidence used to read these frames.
    pub pages: Vec<Arc<WholePageRecovery>>,
}

/// An unsupported descriptor or a failed chain proof.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ByteChainError {
    /// Only verified raw domains, tag 0/0x80 and auxiliary word zero are supported.
    #[error("unsupported byte-chain descriptor")]
    Descriptor,
    /// Physical input could not be read or checked.
    #[error(transparent)]
    Page(#[from] crate::Error),
    /// No unique source-bound header was recovered.
    #[error(transparent)]
    Header(#[from] RowHeaderError),
    /// The independent complete-page equation failed.
    #[error(transparent)]
    Calibration(#[from] CalibrationGap),
    /// Source owner differs from the referring table.
    #[error("byte-chain page has a different owner")]
    Owner,
    /// Referenced page has an unsupported physical kind.
    #[error("byte-chain page is outside the overflow family")]
    Kind,
    /// Complete slot geometry is unavailable.
    #[error("byte-chain directory is incomplete")]
    Directory,
    /// Referenced slot is absent.
    #[error("byte-chain slot is absent")]
    Slot,
    /// Record boundaries or the callback address contradict the source.
    #[error("byte-chain frame contradicts its allocation")]
    Frame,
    /// Frame flags or tag/termination combination are unsupported.
    #[error("byte-chain flags contradict its descriptor")]
    Flags,
    /// Stored pointer revisits a source record.
    #[error("byte-chain contains a cycle")]
    Cycle,
    /// Physical payload does not cover the advertised logical bytes.
    #[error("byte-chain length is inconsistent")]
    Length,
    /// Logical bytes do not overlap the in-row prefix exactly.
    #[error("byte-chain prefix differs")]
    Prefix,
}

impl CalibratedStore<'_> {
    /// Resolve a raw VARCHAR/LONG BINARY reference using exact page-and-slot
    /// links. Stored lengths bound kind-20 records within their allocations.
    /// All physical frames, complete-page evidence and nonzero terminal
    /// surplus remain available to the caller. This does not establish which
    /// referring table rows are transactionally visible.
    pub fn resolve_byte_chain(
        &self,
        owner: u32,
        descriptor: &LongDescriptor<'_>,
    ) -> Result<ByteChainCandidate, ByteChainError> {
        self.resolve_selected_chain(owner, descriptor, ChainFamily::Original)
    }

    /// Explicit raw stream resolution for supported CHAR, VARCHAR, LONG
    /// VARCHAR, BINARY, LONG BINARY and VARBINARY descriptors. CHAR and BINARY
    /// currently require the terminal tag-zero form. The exact named slot
    /// and every subsequent link remain source-bound; the complete value must
    /// match its descriptor length and overlapping logical prefix.
    pub fn resolve_stored_byte_chain(
        &self,
        owner: u32,
        descriptor: &LongDescriptor<'_>,
    ) -> Result<ByteChainCandidate, ByteChainError> {
        self.resolve_selected_chain(owner, descriptor, ChainFamily::Stored)
    }

    pub(crate) fn resolve_bitset_storage(
        &self,
        owner: u32,
        descriptor: &LongDescriptor<'_>,
    ) -> Result<ByteChainCandidate, ByteChainError> {
        self.resolve_selected_chain(owner, descriptor, ChainFamily::Bitset)
    }

    fn resolve_selected_chain(
        &self,
        owner: u32,
        descriptor: &LongDescriptor<'_>,
        family: ChainFamily,
    ) -> Result<ByteChainCandidate, ByteChainError> {
        let mut cache = BTreeMap::new();
        let read = |page, slot| {
            if let std::collections::btree_map::Entry::Vacant(entry) = cache.entry(page) {
                let stored = self.store().page(u64::from(page))?;
                let header = match RowPageHeader::recover(stored) {
                    Ok(header) => header,
                    Err(prior @ RowHeaderError::Ambiguous { .. }) => {
                        RowPageHeader::sole_repeated_lob(stored, owner, slot)?.ok_or(prior)?
                    }
                    Err(error) => return Err(error.into()),
                };
                if header.owner_id() != owner {
                    return Err(ByteChainError::Owner);
                }
                if !(0x11..=0x14).contains(&header.page_kind()) {
                    return Err(ByteChainError::Kind);
                }
                let evidence = Arc::new(self.whole_lob_page(stored, &header)?);
                let header = if header.complete_slot_starts().is_some() {
                    header
                } else {
                    header
                        .lob_directory_from_materialized(&evidence.bytes[..])
                        .ok_or(ByteChainError::Directory)?
                };
                entry.insert((header, evidence));
            }
            let (header, evidence) = cache.get(&page).ok_or(ByteChainError::Directory)?;
            let rows = header.physical_rows().ok_or(ByteChainError::Directory)?;
            let row = rows
                .iter()
                .find(|r| r.slot() == slot)
                .ok_or(ByteChainError::Slot)?;
            if row.length() < 3 {
                return Err(ByteChainError::Frame);
            }
            let bytes = &evidence.bytes[row.start()..row.end()];
            let stored_length = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            if !(3..=bytes.len()).contains(&stored_length) {
                return Err(ByteChainError::Frame);
            }
            Ok(ByteChainChunk {
                page,
                slot,
                owner: header.owner_id(),
                page_kind: header.page_kind(),
                start: row.start(),
                allocation_end: row.end(),
                record: bytes[..stored_length].to_vec(),
            })
        };
        let mut candidate = match family {
            ChainFamily::Original => walk(owner, descriptor, self.store().page_count(), read)?,
            ChainFamily::Stored => walk_stored(owner, descriptor, self.store().page_count(), read)?,
            ChainFamily::Bitset => walk_bitset(owner, descriptor, self.store().page_count(), read)?,
        };
        candidate.pages = cache.into_values().map(|(_, evidence)| evidence).collect();
        Ok(candidate)
    }
}

fn walk(
    owner: u32,
    descriptor: &LongDescriptor<'_>,
    physical_pages: u64,
    read: impl FnMut(u32, u16) -> Result<ByteChainChunk, ByteChainError>,
) -> Result<ByteChainCandidate, ByteChainError> {
    if !matches!(descriptor.domain, 9 | 12) {
        return Err(ByteChainError::Descriptor);
    }
    walk_frames(owner, descriptor, physical_pages, read)
}

fn walk_stored(
    owner: u32,
    descriptor: &LongDescriptor<'_>,
    physical_pages: u64,
    read: impl FnMut(u32, u16) -> Result<ByteChainChunk, ByteChainError>,
) -> Result<ByteChainCandidate, ByteChainError> {
    if !matches!(descriptor.domain, 8 | 9 | 10 | 11 | 12 | 28)
        || matches!(descriptor.domain, 8 | 11) && descriptor.tag != 0
    {
        return Err(ByteChainError::Descriptor);
    }
    walk_frames(owner, descriptor, physical_pages, read)
}

fn walk_bitset(
    owner: u32,
    descriptor: &LongDescriptor<'_>,
    physical_pages: u64,
    read: impl FnMut(u32, u16) -> Result<ByteChainChunk, ByteChainError>,
) -> Result<ByteChainCandidate, ByteChainError> {
    if descriptor.domain != 31 {
        return Err(ByteChainError::Descriptor);
    }
    walk_frames(owner, descriptor, physical_pages, read)
}

fn walk_frames(
    owner: u32,
    descriptor: &LongDescriptor<'_>,
    physical_pages: u64,
    mut read: impl FnMut(u32, u16) -> Result<ByteChainChunk, ByteChainError>,
) -> Result<ByteChainCandidate, ByteChainError> {
    if !matches!(descriptor.tag, 0 | 0x80) || descriptor.unknown != 0 {
        return Err(ByteChainError::Descriptor);
    }
    let length = descriptor.total_len as usize;
    if length == 0
        || u64::from(descriptor.total_len) > physical_pages.saturating_mul(PAGE_SIZE as u64)
        || descriptor.prefix.len() > length
    {
        return Err(ByteChainError::Length);
    }
    let mut address = (descriptor.first_page, descriptor.slot);
    let mut visited = BTreeSet::new();
    let mut bytes = Vec::with_capacity(length.min(PAGE_SIZE));
    let mut chunks = Vec::new();
    loop {
        if address.0 == 0 || u64::from(address.0) >= physical_pages {
            return Err(ByteChainError::Frame);
        }
        if !visited.insert(address) {
            return Err(ByteChainError::Cycle);
        }
        let chunk = read(address.0, address.1)?;
        if (chunk.page, chunk.slot) != address
            || chunk.start < 28
            || chunk.start > 4092
            || chunk.allocation_end > 4092
            || chunk.allocation_end <= chunk.start
            || chunk.record.len() < 3
            || chunk.record.len() > chunk.allocation_end - chunk.start
            || usize::from(u16::from_le_bytes([chunk.record[0], chunk.record[1]]))
                != chunk.record.len()
            || chunk.page_kind != 0x14 && chunk.record.len() != chunk.allocation_end - chunk.start
        {
            return Err(ByteChainError::Frame);
        }
        if chunk.owner != owner {
            return Err(ByteChainError::Owner);
        }
        if !(0x11..=0x14).contains(&chunk.page_kind) {
            return Err(ByteChainError::Kind);
        }
        let flags = chunk.record[2];
        if !matches!(flags, 0 | 4)
            || descriptor.tag == 0 && flags != 0
            || descriptor.tag == 0x80 && chunks.is_empty() && flags != 4
        {
            return Err(ByteChainError::Flags);
        }
        let remaining = length - bytes.len();
        if flags == 4 {
            let Some(link) = chunk.record.get(3..9) else {
                return Err(ByteChainError::Frame);
            };
            let payload = &chunk.record[9..];
            if payload.is_empty() || payload.len() >= remaining {
                return Err(ByteChainError::Length);
            }
            address = (
                u32::from_le_bytes(link[..4].try_into().map_err(|_| ByteChainError::Frame)?),
                u16::from_le_bytes([link[4], link[5]]),
            );
            bytes.extend_from_slice(payload);
            chunks.push(chunk);
        } else {
            let payload = &chunk.record[3..];
            if payload.len() < remaining {
                return Err(ByteChainError::Length);
            }
            bytes.extend_from_slice(&payload[..remaining]);
            let surplus = payload[remaining..].to_vec();
            chunks.push(chunk);
            if !bytes.starts_with(descriptor.prefix) {
                return Err(ByteChainError::Prefix);
            }
            return Ok(ByteChainCandidate {
                bytes,
                chunks,
                surplus,
                pages: Vec::new(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitset_storage_is_explicit_and_retains_serialized_bytes_and_surplus() {
        let mut d = descriptor(0x80, 12);
        d.domain = 31;
        d.prefix = &[32, 0, 0, 0];
        let encoded = [32, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0];
        let result = walk_bitset(42, &d, 3, |page, slot| {
            Ok(if page == 1 {
                chunk(page, slot, Some((2, 3)), &encoded[..4])
            } else {
                chunk(page, slot, None, &[1, 0, 0, 0, 1, 0, 0, 0, 0x7f, 0x82])
            })
        })
        .unwrap();
        assert_eq!(result.bytes, encoded);
        assert_eq!(result.surplus, [0x7f, 0x82]);
        assert_eq!(result.chunks[1].slot, 3);
        assert!(matches!(
            walk_stored(42, &d, 3, |_, _| panic!()),
            Err(ByteChainError::Descriptor)
        ));
        for (domain, tag, unknown) in [(12, 0, 0), (31, 0x40, 0), (31, 0x80, 1)] {
            d.domain = domain;
            d.tag = tag;
            d.unknown = unknown;
            assert!(matches!(
                walk_bitset(42, &d, 3, |_, _| panic!()),
                Err(ByteChainError::Descriptor)
            ));
        }
    }

    fn descriptor(tag: u8, length: u32) -> LongDescriptor<'static> {
        LongDescriptor {
            domain: 9,
            tag,
            prefix: b"ab",
            total_len: length,
            first_page: 1,
            unknown: 0,
            slot: 7,
        }
    }

    fn chunk(page: u32, slot: u16, next: Option<(u32, u16)>, payload: &[u8]) -> ByteChainChunk {
        let mut record = vec![0, 0, if next.is_some() { 4 } else { 0 }];
        if let Some((page, slot)) = next {
            record.extend(page.to_le_bytes());
            record.extend(slot.to_le_bytes());
        }
        record.extend(payload);
        let length = record.len() as u16;
        record[..2].copy_from_slice(&length.to_le_bytes());
        ByteChainChunk {
            page,
            slot,
            owner: 42,
            page_kind: 0x14,
            start: 36,
            allocation_end: 36 + record.len(),
            record,
        }
    }

    #[test]
    fn follows_nonzero_slots_and_retains_nonzero_surplus_and_allocation_gaps() {
        let first = chunk(1, 7, Some((2, 13)), b"abc");
        let mut last = chunk(2, 13, None, b"defSURPLUS");
        last.allocation_end += 19;
        let result = walk(42, &descriptor(0x80, 6), 3, |page, slot| {
            match (page, slot) {
                (1, 7) => Ok(first.clone()),
                (2, 13) => Ok(last.clone()),
                _ => panic!("the full page-and-slot address must be followed"),
            }
        })
        .unwrap();
        assert_eq!(result.bytes, b"abcdef");
        assert_eq!(result.surplus, b"SURPLUS");
        assert_eq!(result.chunks.len(), 2);
        assert_eq!(result.chunks[1].allocation_end, last.allocation_end);
        assert_eq!(result.chunks[1].record, last.record);
    }

    #[test]
    fn single_chunk_uses_declared_length_and_checks_prefix() {
        let result = walk(42, &descriptor(0, 3), 2, |page, slot| {
            Ok(chunk(page, slot, None, b"abcEXTRA"))
        })
        .unwrap();
        assert_eq!(result.bytes, b"abc");
        assert_eq!(result.surplus, b"EXTRA");
        assert!(matches!(
            walk(42, &descriptor(0, 3), 2, |page, slot| {
                Ok(chunk(page, slot, None, b"xyz"))
            }),
            Err(ByteChainError::Prefix)
        ));
    }

    #[test]
    fn unsupported_descriptor_families_are_rejected_before_reading() {
        for domain in [8, 10, 11, 28, 31] {
            let mut d = descriptor(0x80, 6);
            d.domain = domain;
            assert!(matches!(
                walk(42, &d, 2, |_, _| panic!()),
                Err(ByteChainError::Descriptor)
            ));
        }
        for tag in [1, 0x40, 0xc0] {
            assert!(matches!(
                walk(42, &descriptor(tag, 6), 2, |_, _| panic!()),
                Err(ByteChainError::Descriptor)
            ));
        }
        let mut d = descriptor(0x80, 6);
        d.unknown = 1;
        assert!(matches!(
            walk(42, &d, 2, |_, _| panic!()),
            Err(ByteChainError::Descriptor)
        ));
        for length in [0, 8193] {
            assert!(matches!(
                walk(42, &descriptor(0, length), 2, |_, _| panic!()),
                Err(ByteChainError::Length)
            ));
        }
    }

    #[test]
    fn extended_domains_require_explicit_stored_byte_resolution() {
        for domain in [8, 10, 11, 28] {
            let mut d = descriptor(0, 3);
            d.domain = domain;
            d.prefix = b"ab";
            assert!(matches!(
                walk(42, &d, 2, |_, _| panic!()),
                Err(ByteChainError::Descriptor)
            ));
            let result =
                walk_stored(42, &d, 2, |p, s| Ok(chunk(p, s, None, b"abcSURPLUS"))).unwrap();
            assert_eq!(result.bytes, b"abc");
            assert_eq!(result.surplus, b"SURPLUS");
            if matches!(domain, 8 | 11) {
                d.tag = 0x80;
                assert!(matches!(
                    walk_stored(42, &d, 2, |_, _| panic!()),
                    Err(ByteChainError::Descriptor)
                ));
            }
        }
        let mut d = descriptor(0, 3);
        d.domain = 31;
        assert!(matches!(
            walk_stored(42, &d, 2, |_, _| panic!()),
            Err(ByteChainError::Descriptor)
        ));
    }

    #[test]
    fn frame_flags_must_agree_with_the_descriptor() {
        assert!(matches!(
            walk(42, &descriptor(0, 6), 3, |p, s| {
                Ok(chunk(p, s, Some((2, 0)), b"abc"))
            }),
            Err(ByteChainError::Flags)
        ));
        assert!(matches!(
            walk(42, &descriptor(0x80, 6), 3, |p, s| {
                Ok(chunk(p, s, None, b"abcdef"))
            }),
            Err(ByteChainError::Flags)
        ));
        assert!(matches!(
            walk(42, &descriptor(0, 6), 3, |p, s| {
                let mut frame = chunk(p, s, None, b"abcdef");
                frame.record[2] = 8;
                Ok(frame)
            }),
            Err(ByteChainError::Flags)
        ));
    }

    #[test]
    fn every_frame_retains_owner_address_length_and_kind_constraints() {
        for alteration in 0..7 {
            let result = walk(42, &descriptor(0, 3), 2, |p, s| {
                let mut frame = chunk(p, s, None, b"abc");
                match alteration {
                    0 => frame.owner += 1,
                    1 => frame.page += 1,
                    2 => frame.slot += 1,
                    3 => frame.record[0] += 1,
                    4 => frame.allocation_end -= 1,
                    5 => frame.page_kind = 16,
                    _ => frame.start = usize::MAX,
                }
                Ok(frame)
            });
            assert!(result.is_err(), "alteration {alteration} must fail");
        }
        assert!(matches!(
            walk(42, &descriptor(0, 3), 2, |p, s| {
                let mut frame = chunk(p, s, None, b"abc");
                frame.page_kind = 0x11;
                frame.allocation_end += 1;
                Ok(frame)
            }),
            Err(ByteChainError::Frame)
        ));
    }

    #[test]
    fn cycles_invalid_addresses_and_short_payloads_fail() {
        assert!(matches!(
            walk(42, &descriptor(0x80, 8), 2, |p, s| {
                Ok(chunk(p, s, Some((p, s)), b"abc"))
            }),
            Err(ByteChainError::Cycle)
        ));
        for page in [0, 2] {
            assert!(matches!(
                walk(42, &descriptor(0x80, 8), 2, |p, s| {
                    Ok(chunk(p, s, Some((page, 0)), b"abc"))
                }),
                Err(ByteChainError::Frame)
            ));
        }
        assert!(matches!(
            walk(42, &descriptor(0, 8), 2, |p, s| {
                Ok(chunk(p, s, None, b"abc"))
            }),
            Err(ByteChainError::Length)
        ));
        assert!(matches!(
            walk(42, &descriptor(0x80, 3), 2, |p, s| {
                Ok(chunk(p, s, Some((1, 0)), b"abc"))
            }),
            Err(ByteChainError::Length)
        ));
        assert!(matches!(
            walk(42, &descriptor(0x80, 8), 2, |p, s| {
                let mut frame = chunk(p, s, None, b"ab");
                frame.record[2] = 4;
                Ok(frame)
            }),
            Err(ByteChainError::Frame)
        ));
    }
}
