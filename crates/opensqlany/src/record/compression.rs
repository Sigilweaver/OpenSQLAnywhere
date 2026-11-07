//! Bounded decoding of the supported SA17 compression envelope.

use crate::{
    ByteChainCandidate, ByteChainError, CalibratedStore, CompressedDescriptor, LongDescriptor,
};
use flate2::{Decompress, FlushDecompress, Status};

/// Decoded logical bytes and the complete encoded chain that supplied them.
#[derive(Debug)]
pub struct CompressedByteCandidate {
    /// Exact decoded logical bytes, with the in-row prefix included once.
    pub bytes: Vec<u8>,
    /// Encoded stream, original physical frames, terminal surplus and page proof.
    pub encoded: ByteChainCandidate,
}

/// A failed compressed descriptor, storage proof, decode or logical-prefix check.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoredByteError {
    /// The descriptor is outside the supported family.
    #[error("unsupported compressed byte descriptor")]
    Descriptor,
    /// Encoded storage did not pass its independent chain checks.
    #[error(transparent)]
    Chain(#[from] ByteChainError),
    /// Compression framing, checksum, length or resource check failed.
    #[error(transparent)]
    Compression(#[from] CompressionError),
    /// The original logical prefix differs from the complete decoded value.
    #[error("compressed byte prefix differs")]
    Prefix,
}

impl CalibratedStore<'_> {
    /// Resolve and decode the supported compressed byte-stream family.
    /// Encoded frames retain their ordinary raw segment layout; the original
    /// in-row prefix is checked against the decoded value. The caller must
    /// still establish the referring row's visibility and applicable layout.
    pub fn resolve_compressed_bytes(
        &self,
        owner: u32,
        descriptor: &CompressedDescriptor<'_>,
        max_output_bytes: usize,
    ) -> Result<CompressedByteCandidate, StoredByteError> {
        let d = &descriptor.storage;
        if !matches!(d.domain, 9 | 10 | 12 | 28)
            || !matches!(d.tag, 0x40 | 0xc0)
            || d.unknown != 0
            || descriptor.logical_len == 0
            || d.prefix.len() > descriptor.logical_len as usize
        {
            return Err(StoredByteError::Descriptor);
        }
        if descriptor.logical_len as usize > max_output_bytes {
            return Err(CompressionError::Limit.into());
        }
        // Its physical frame chain stores encoded bytes. The separate logical
        // prefix must not be imposed on that encoded envelope.
        let encoded_descriptor = LongDescriptor {
            domain: d.domain,
            tag: d.tag & 0x80,
            prefix: &[],
            total_len: d.total_len,
            first_page: d.first_page,
            unknown: d.unknown,
            slot: d.slot,
        };
        let encoded = self.resolve_stored_byte_chain(owner, &encoded_descriptor)?;
        let bytes =
            decode_compressed_stream(&encoded.bytes, descriptor.logical_len, max_output_bytes)?;
        if !bytes.starts_with(d.prefix) {
            return Err(StoredByteError::Prefix);
        }
        Ok(CompressedByteCandidate { bytes, encoded })
    }
}

/// A failed compression-envelope, payload, length or resource check.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressionError {
    /// The stream does not have the verified four-byte envelope header.
    #[error("unsupported compression envelope")]
    Header,
    /// A block is truncated, empty or has an unsupported type.
    #[error("unsupported or incomplete compression block")]
    Block,
    /// A block's recorded position differs from its actual stream position.
    #[error("compression block offset differs")]
    Offset,
    /// The compressed payload is invalid, incomplete or contains trailing input.
    #[error("compression block is not one complete zlib stream")]
    Inflate,
    /// Decoded bytes do not exactly fill the separately declared logical length.
    #[error("decoded compression length differs")]
    Length,
    /// The declared logical length exceeds the caller's explicit resource limit.
    #[error("compression output exceeds its resource limit")]
    Limit,
    /// The allocator could not reserve space for verified output bytes.
    #[error("compression output allocation failed")]
    Allocation,
}

/// Decode one verified SA17 compression envelope with an explicit output limit.
///
/// `encoded` must already be bounded by its descriptor and reconstructed from
/// independently verified source frames. The separate on-row length supplies
/// `logical_length`; it is not the encoded descriptor length. This function
/// checks all block types, self offsets, payload boundaries, zlib checksums,
/// complete input consumption and the exact final length. It supplies no page,
/// owner, prefix, column-layout or row-visibility evidence.
///
/// # Errors
///
/// Returns [`CompressionError`] for unsupported framing, truncated blocks,
/// invalid zlib data, mismatched lengths or exceeded output bounds.
pub fn decode_compressed_stream(
    encoded: &[u8],
    logical_length: u32,
    max_output_bytes: usize,
) -> Result<Vec<u8>, CompressionError> {
    let expected = logical_length as usize;
    if expected > max_output_bytes {
        return Err(CompressionError::Limit);
    }
    if expected == 0 {
        return Err(CompressionError::Length);
    }
    if encoded.get(..4) != Some(&[0, 4, 2, 0]) {
        return Err(CompressionError::Header);
    }
    let mut cursor = 4;
    let mut decoded = Vec::new();
    while cursor < encoded.len() {
        let header = encoded
            .get(cursor..cursor + 10)
            .ok_or(CompressionError::Block)?;
        let kind = u16::from_le_bytes([header[0], header[1]]);
        let size = u32::from_le_bytes(header[2..6].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(header[6..10].try_into().unwrap()) as usize;
        if offset != cursor {
            return Err(CompressionError::Offset);
        }
        if size == 0 || !matches!(kind, 0x0a01 | 0x0a02) {
            return Err(CompressionError::Block);
        }
        cursor += 10;
        let end = cursor.checked_add(size).ok_or(CompressionError::Block)?;
        let payload = encoded.get(cursor..end).ok_or(CompressionError::Block)?;
        cursor = end;
        if kind == 0x0a02 {
            append(&mut decoded, payload, expected)?;
            continue;
        }
        let mut inflater = Decompress::new(true);
        let mut scratch = [0; 8192];
        loop {
            let before_in = inflater.total_in();
            let before_out = inflater.total_out();
            let capacity = (expected - decoded.len()).min(scratch.len() - 1) + 1;
            let status = inflater
                .decompress(
                    &payload[before_in as usize..],
                    &mut scratch[..capacity],
                    FlushDecompress::None,
                )
                .map_err(|_| CompressionError::Inflate)?;
            let produced = (inflater.total_out() - before_out) as usize;
            append(&mut decoded, &scratch[..produced], expected)?;
            if status == Status::StreamEnd {
                if inflater.total_in() != payload.len() as u64 || inflater.total_out() == 0 {
                    return Err(CompressionError::Inflate);
                }
                break;
            }
            if inflater.total_in() == before_in && produced == 0 {
                return Err(CompressionError::Inflate);
            }
        }
    }
    if decoded.len() != expected {
        return Err(CompressionError::Length);
    }
    Ok(decoded)
}

fn append(out: &mut Vec<u8>, bytes: &[u8], expected: usize) -> Result<(), CompressionError> {
    if bytes.len() > expected - out.len() {
        return Err(CompressionError::Length);
    }
    out.try_reserve(bytes.len())
        .map_err(|_| CompressionError::Allocation)?;
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn block(stream: &mut Vec<u8>, kind: u16, payload: &[u8]) {
        let at = stream.len() as u32;
        stream.extend(kind.to_le_bytes());
        stream.extend((payload.len() as u32).to_le_bytes());
        stream.extend(at.to_le_bytes());
        stream.extend(payload);
    }

    fn fixture() -> (Vec<u8>, Vec<u8>) {
        let mut stream = vec![0, 4, 2, 0];
        let mut compressor =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        let value: Vec<_> = (0..40000).map(|i| (i % 251) as u8).collect();
        compressor.write_all(&value).unwrap();
        block(&mut stream, 0x0a01, &compressor.finish().unwrap());
        block(&mut stream, 0x0a02, b"raw\0tail");
        (stream, [value.as_slice(), b"raw\0tail"].concat())
    }

    #[test]
    fn compressed_reference_limits_and_shape_are_checked_before_storage() {
        let store = crate::PageStore::from_bytes_unchecked(vec![0; crate::PAGE_SIZE]).unwrap();
        let reader = CalibratedStore::new(&store);
        let mut descriptor = CompressedDescriptor {
            storage: LongDescriptor {
                domain: 28,
                tag: 0x40,
                prefix: b"a",
                total_len: 100,
                first_page: u32::MAX,
                unknown: 0,
                slot: 1,
            },
            logical_len: 10,
        };
        assert!(matches!(
            reader.resolve_compressed_bytes(1, &descriptor, 9),
            Err(StoredByteError::Compression(CompressionError::Limit))
        ));
        for tag in [0, 4, 0x80, 0x41, 0xc4] {
            descriptor.storage.tag = tag;
            assert!(matches!(
                reader.resolve_compressed_bytes(1, &descriptor, 10),
                Err(StoredByteError::Descriptor)
            ));
        }
        descriptor.storage.tag = 0x40;
        descriptor.storage.unknown = 1;
        assert!(matches!(
            reader.resolve_compressed_bytes(1, &descriptor, 10),
            Err(StoredByteError::Descriptor)
        ));
    }

    #[test]
    fn decodes_multiple_compressed_and_raw_blocks_with_bounded_buffers() {
        let (stream, expected) = fixture();
        assert_eq!(
            decode_compressed_stream(&stream, expected.len() as u32, expected.len()).unwrap(),
            expected
        );
        let mut stream = vec![0, 4, 2, 0];
        // A fixed zlib vector independently represents the ASCII word hello.
        block(
            &mut stream,
            0x0a01,
            &[
                0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15,
            ],
        );
        assert_eq!(decode_compressed_stream(&stream, 5, 5).unwrap(), b"hello");
    }

    #[test]
    fn rejects_incomplete_invalid_and_trailing_compressed_input() {
        let (stream, expected) = fixture();
        for end in 0..stream.len() {
            assert!(
                decode_compressed_stream(&stream[..end], expected.len() as u32, expected.len())
                    .is_err()
            );
        }
        for at in [0, 2, 4, 5, 6, 10, 14, stream.len() - 9] {
            let mut damaged = stream.clone();
            damaged[at] ^= 128;
            assert!(
                decode_compressed_stream(&damaged, expected.len() as u32, expected.len()).is_err()
            );
        }
        let mut trailing = vec![0, 4, 2, 0];
        block(
            &mut trailing,
            0x0a01,
            &[
                0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15, 0,
            ],
        );
        assert_eq!(
            decode_compressed_stream(&trailing, 5, 5),
            Err(CompressionError::Inflate)
        );
    }

    #[test]
    fn rejects_wrong_lengths_empty_blocks_and_output_above_the_limit() {
        let (stream, expected) = fixture();
        for size in [0, 1, expected.len() - 1, expected.len() + 1] {
            assert!(decode_compressed_stream(&stream, size as u32, size).is_err());
        }
        assert_eq!(
            decode_compressed_stream(&stream, expected.len() as u32, expected.len() - 1),
            Err(CompressionError::Limit)
        );
        let mut empty = vec![0, 4, 2, 0];
        block(&mut empty, 0x0a02, b"");
        assert_eq!(
            decode_compressed_stream(&empty, 1, 1),
            Err(CompressionError::Block)
        );
    }
}
