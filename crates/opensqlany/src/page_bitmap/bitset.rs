//! Domain-31 serialized bitsets, kept separate from table membership.

use crate::page_bitmap::words;
use crate::{ByteChainCandidate, ByteChainError, CalibratedStore, LongDescriptor, PageBitmapError};

/// Exact stored binary representation of a stored bitset.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedBitset {
    /// Dense bytes in least-significant-bit-first word order, including zero padding.
    pub bytes: Vec<u8>,
    /// Declared logical universe in bits; always a multiple of 32.
    pub bit_length: u32,
}

/// A decoded bitset together with every encoded source frame and page proof.
#[derive(Debug)]
pub struct StoredBitsetCandidate {
    /// Exact decoded logical bytes and universe, distinct from encoded RLE length.
    pub decoded: DecodedBitset,
    /// Serialized RLE bytes, complete frames, links, terminal surplus and pages.
    pub encoded: ByteChainCandidate,
}

/// A failed stored-bitset descriptor, source proof, encoding or resource bound.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoredBitsetError {
    /// The descriptor is outside the independently verified domain-31 family.
    #[error("unsupported stored bitset descriptor")]
    Descriptor,
    /// The serialized value lacks its required four-byte universe.
    #[error("stored bitset lacks a universe word")]
    MissingUniverse,
    /// The encoded chain did not pass its ordinary source and framing checks.
    #[error(transparent)]
    Chain(#[from] ByteChainError),
    /// The complete serialized words do not form one exact RLE universe.
    #[error(transparent)]
    Encoding(#[from] PageBitmapError),
    /// Encoded storage or dense output exceeds the caller's explicit byte bound.
    #[error("stored bitset exceeds its resource limit")]
    Limit,
    /// The allocator could not reserve the bounded logical output.
    #[error("cannot allocate stored bitset output")]
    Allocation,
}

/// Decode complete serialized bitset words with an explicit dense-output bound.
///
/// The first little-endian word is a bit universe, followed by zero/all-one
/// fill runs and literal words. The result retains the entire universe, even
/// after the last set bit. This checks no source page, referring row visibility,
/// table membership, physical-page bounds or catalog page count.
pub fn decode_serialized_bitset(
    encoded: &[u8],
    max_output_bytes: usize,
) -> Result<DecodedBitset, StoredBitsetError> {
    let first = encoded.get(..4).ok_or(StoredBitsetError::MissingUniverse)?;
    let bit_length = u32::from_le_bytes(first.try_into().unwrap());
    if !bit_length.is_multiple_of(32) {
        return Err(PageBitmapError::UniverseAlignment {
            universe: bit_length,
        }
        .into());
    }
    let size = (bit_length / 8) as usize;
    if size > max_output_bytes {
        return Err(StoredBitsetError::Limit);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| StoredBitsetError::Allocation)?;
    bytes.resize(size, 0);
    words::walk_serialized(encoded, encoded.len(), |_, word| {
        let output = &mut bytes[(word.start / 8) as usize..(word.end / 8) as usize];
        if word.literal {
            output.copy_from_slice(&word.bits.to_le_bytes());
        } else if word.bits != 0 {
            output.fill(0xff);
        }
        Ok(())
    })?;
    Ok(DecodedBitset { bytes, bit_length })
}

impl CalibratedStore<'_> {
    /// Resolve an explicit domain-31 bitset and decode its decoded logical bytes.
    ///
    /// The descriptor length and prefix describe the serialized RLE storage.
    /// Owner, exact slots, complete encoded pages, links, frame bounds and
    /// terminal surplus use the independently verified raw-chain checks.
    /// Decoding set bits does not establish table membership or row visibility.
    pub fn resolve_stored_bitset(
        &self,
        owner: u32,
        descriptor: &LongDescriptor<'_>,
        max_output_bytes: usize,
    ) -> Result<StoredBitsetCandidate, StoredBitsetError> {
        if descriptor.domain != 31 || !matches!(descriptor.tag, 0 | 0x80) || descriptor.unknown != 0
        {
            return Err(StoredBitsetError::Descriptor);
        }
        // Each progressing control accounts for at least one output word;
        // at most one control accompanies each literal word, plus the universe.
        if descriptor.total_len as usize > max_output_bytes.saturating_mul(2).saturating_add(4) {
            return Err(StoredBitsetError::Limit);
        }
        let encoded = self.resolve_bitset_storage(owner, descriptor)?;
        let decoded = decode_serialized_bitset(&encoded.bytes, max_output_bytes)?;
        Ok(StoredBitsetCandidate { decoded, encoded })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn retains_the_full_universe_and_little_endian_literal_bits() {
        let encoded = encode(&[192, 0x81, 0x8000_0001, 0xc1, 0x1234_5678, 0x100]);
        let decoded = decode_serialized_bitset(&encoded, 24).unwrap();
        let mut expected = vec![0; 4];
        expected.extend_from_slice(&0x8000_0001u32.to_le_bytes());
        expected.extend_from_slice(&[0xff; 4]);
        expected.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        expected.extend_from_slice(&[0; 8]);
        assert_eq!(decoded.bytes, expected);
        assert_eq!(decoded.bit_length, 192);
    }

    #[test]
    fn empty_universe_is_present_empty_and_not_a_missing_value() {
        assert_eq!(
            decode_serialized_bitset(&encode(&[0]), 0).unwrap(),
            DecodedBitset {
                bytes: vec![],
                bit_length: 0
            }
        );
        assert!(matches!(
            decode_serialized_bitset(&[], 0),
            Err(StoredBitsetError::MissingUniverse)
        ));
        assert_eq!(
            decode_serialized_bitset(&encode(&[64, 0x100]), 8)
                .unwrap()
                .bytes,
            [0; 8]
        );
    }

    #[test]
    fn generic_bitsets_do_not_weaken_table_page_membership() {
        let encoded = encode(&[32, 1, 1]);
        assert_eq!(
            decode_serialized_bitset(&encoded, 4).unwrap().bytes,
            [1, 0, 0, 0]
        );
        assert!(matches!(
            crate::TablePageBitmap::decode(&encoded, 100, 1),
            Err(PageBitmapError::OutOfStore { page: 0, .. })
        ));
    }

    #[test]
    fn rejects_incomplete_nonprogressing_or_overlong_encodings_and_bounds_output() {
        for words in [
            &[32][..],
            &[32, 0],
            &[32, 2, 0],
            &[32, 0x100],
            &[0, 0x80],
            &[31, 0x80],
        ] {
            assert!(
                decode_serialized_bitset(&encode(words), 1024).is_err(),
                "{words:?}"
            );
        }
        let mut unaligned = encode(&[0]);
        unaligned.push(0);
        assert!(matches!(
            decode_serialized_bitset(&unaligned, 0),
            Err(StoredBitsetError::Encoding(PageBitmapError::WordAlignment))
        ));
        assert!(matches!(
            decode_serialized_bitset(&encode(&[64, 0x100]), 7),
            Err(StoredBitsetError::Limit)
        ));
        assert!(matches!(
            decode_serialized_bitset(&encode(&[u32::MAX - 31]), 4096),
            Err(StoredBitsetError::Limit)
        ));
    }
}
