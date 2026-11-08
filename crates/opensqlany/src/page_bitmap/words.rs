//! Walk complete serialized bitmap words. The sparse-map search uses the same
//! grammar on a prefix, with the total field length fixed by the descriptor.

use super::PageBitmapError;

#[derive(Clone, Copy)]
pub(crate) struct BitmapWord {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) bits: u32,
    pub(crate) literal: bool,
}

/// Visit every complete control/literal word of this field prefix and return
/// its set-bit count so far. Partial last words remain unevaluated until all
/// four bytes are available. The full field must close exactly at its universe.
pub(super) fn walk(
    prefix: &[u8],
    field_len: usize,
    physical_pages: u64,
    mut observe: impl FnMut(usize, BitmapWord) -> Result<(), PageBitmapError>,
) -> Result<u32, PageBitmapError> {
    walk_serialized(prefix, field_len, |offset, word| {
        if word.bits != 0 {
            let first = word.start + u64::from(word.bits.trailing_zeros());
            let last = word.end - 1 - u64::from(word.bits.leading_zeros());
            if first == 0 || last >= physical_pages {
                return Err(PageBitmapError::OutOfStore {
                    page: if first == 0 { 0 } else { last },
                    physical_pages,
                });
            }
        }
        observe(offset, word)
    })
}

/// Shared RLE grammar without interpreting set bits as physical page numbers.
/// Table membership adds its original nonzero/in-store checks in `walk`.
pub(crate) fn walk_serialized(
    prefix: &[u8],
    field_len: usize,
    mut observe: impl FnMut(usize, BitmapWord) -> Result<(), PageBitmapError>,
) -> Result<u32, PageBitmapError> {
    if !field_len.is_multiple_of(4) || prefix.len() > field_len {
        return Err(PageBitmapError::WordAlignment);
    }
    let mut words = prefix
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let Some(universe) = words.next() else {
        return Ok(0);
    };
    if !universe.is_multiple_of(32) {
        return Err(PageBitmapError::UniverseAlignment { universe });
    }
    let mut cursor = 0u64;
    let mut literals = 0u32;
    let mut count = 0;
    for (i, word) in words.enumerate() {
        let offset = (i + 1) * 4;
        let start = cursor;
        let literal = literals != 0;
        let bits = if literal {
            literals -= 1;
            cursor += 32;
            word
        } else {
            let fill_words = word >> 7;
            literals = word & 0x3f;
            if fill_words == 0 && literals == 0 {
                return Err(PageBitmapError::NoProgress);
            }
            cursor += 32 * u64::from(fill_words);
            if cursor + 32 * u64::from(literals) > u64::from(universe) {
                return Err(PageBitmapError::UniverseCoverage { universe });
            }
            if literals as usize > (field_len - offset - 4) / 4 {
                return Err(PageBitmapError::TruncatedLiteral);
            }
            if word & 0x40 != 0 && fill_words != 0 {
                u32::MAX
            } else {
                0
            }
        };
        if bits != 0 {
            // The sum cannot exceed the aligned u32 universe.
            count += ((cursor - start) / 32) as u32 * bits.count_ones();
        }
        observe(
            offset,
            BitmapWord {
                start,
                end: cursor,
                bits,
                literal,
            },
        )?;
    }
    let closed = cursor == u64::from(universe) && literals == 0;
    if closed != (prefix.len() == field_len) {
        // A closed prefix cannot be followed by any progressing control.
        return Err(PageBitmapError::UniverseCoverage { universe });
    }
    Ok(count)
}
