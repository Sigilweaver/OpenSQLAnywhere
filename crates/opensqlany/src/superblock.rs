use crate::error::{Error, Result};
use crate::page::PAGE_SIZE;

/// Magic value at superblock offset 0x14. Appears as bytes `5E BA 7A DA`
/// (little-endian u32 = `0xDA7ABA5E`).
pub const SA_MAGIC: u32 = 0xDA7A_BA5E;

/// The 33-byte copyright substring that pins the engine to SAP SQL
/// Anywhere 17.0.4 build 2182 (2015 release).
pub const SA_COPYRIGHT_MARKER: &[u8] = b"SAP SE, Copyright (c)2015 17.0.4.";

/// Base value of [`Superblock::flags_06`] observed across the original
/// 112-file corpus, before any variant bits are set on top of it.
///
/// `flags_06` reads as a bitfield over this base rather than an enum of
/// magic values: the originally observed `0x49` is `0x09 | 0x40` (bit 6),
/// and a QuickBooks Enterprise 24.0 file adds `0x29 = 0x09 | 0x20` (bit 5).
/// Treat unrecognized bit combinations as unrecognized-but-valid rather
/// than rejecting them outright - each new edition is likelier to set
/// another bit than to replace the base value. See
/// [`Superblock::flags_06_variant_bits`].
pub const FLAGS_06_BASE: u8 = 0x09;

/// The `(format_major, version_a, version_b)` triple at superblock offsets
/// `0x10`, `0x18` and `0x1A`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct FormatVersion {
    /// `format_major` at offset 0x10.
    pub major: u32,
    /// `version_a` at offset 0x18.
    pub a: u16,
    /// `version_b` at offset 0x1A.
    pub b: u16,
}

impl FormatVersion {
    /// The triple observed on every SA17 build 2182 file in the corpus.
    pub const SA17: FormatVersion = FormatVersion {
        major: 3,
        a: 201,
        b: 12,
    };
}

impl std::fmt::Display for FormatVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.a, self.b)
    }
}

/// Parsed view of the page-0 superblock.
///
/// Only fields that are invariant across the 112-file corpus are named;
/// other fields are held as raw bytes. See `SPECIFICATION.md` section 3.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Superblock {
    flags_06: u8,
    current_lsn: u32,
    format_major: u32,
    magic: u32,
    version_a: u16,
    version_b: u16,
    page_count_hint: u32,
    sa_marker_present: bool,
}

impl Superblock {
    /// Parse the superblock from the first page of a store.
    ///
    /// `page0` must be exactly [`PAGE_SIZE`] bytes long, otherwise
    /// [`Error::WrongBufferLength`].
    pub fn parse(page0: &[u8]) -> Result<Self> {
        if page0.len() != PAGE_SIZE {
            return Err(Error::WrongBufferLength {
                expected: PAGE_SIZE,
                got: page0.len(),
            });
        }

        let u32_at =
            |o: usize| u32::from_le_bytes([page0[o], page0[o + 1], page0[o + 2], page0[o + 3]]);
        let u16_at = |o: usize| u16::from_le_bytes([page0[o], page0[o + 1]]);

        Ok(Superblock {
            flags_06: page0[0x06],
            current_lsn: u32_at(0x08),
            format_major: u32_at(0x10),
            magic: u32_at(0x14),
            version_a: u16_at(0x18),
            version_b: u16_at(0x1A),
            page_count_hint: u32_at(0x1C),
            sa_marker_present: memmem(page0, SA_COPYRIGHT_MARKER).is_some(),
        })
    }

    /// Flag byte at offset 0x06. See [`FLAGS_06_BASE`] and
    /// [`Superblock::flags_06_variant_bits`] for how to interpret it.
    #[inline]
    pub fn flags_06(&self) -> u8 {
        self.flags_06
    }

    /// u32_LE at offset 0x08 - the file's current log sequence number.
    ///
    /// Previously read as the low half of a per-file identifier. It is a
    /// write counter: across every file measured, the highest per-page
    /// [`PageTrailer::lsn`](crate::PageTrailer::lsn) is exactly this value
    /// minus ten, and offset `0x0C` - which a 64-bit identifier would need
    /// - is always zero. See `SPECIFICATION.md` section 3.1a.
    #[inline]
    pub fn current_lsn(&self) -> u32 {
        self.current_lsn
    }

    /// The `(format_major, version_a, version_b)` triple.
    #[inline]
    pub fn format(&self) -> FormatVersion {
        FormatVersion {
            major: self.format_major,
            a: self.version_a,
            b: self.version_b,
        }
    }

    /// u32_LE at offset 0x10. Always `3` in the corpus.
    #[inline]
    pub fn format_major(&self) -> u32 {
        self.format_major
    }

    /// u32_LE at offset 0x14.
    #[inline]
    pub fn magic(&self) -> u32 {
        self.magic
    }

    /// u16_LE at offset 0x18. Always `201` in the corpus.
    #[inline]
    pub fn version_a(&self) -> u16 {
        self.version_a
    }

    /// u16_LE at offset 0x1A. Always `12` in the corpus.
    #[inline]
    pub fn version_b(&self) -> u16 {
        self.version_b
    }

    /// u32_LE at offset 0x1C. Typically `total_pages - 128`.
    #[inline]
    pub fn page_count_hint(&self) -> u32 {
        self.page_count_hint
    }

    /// `true` iff [`SA_COPYRIGHT_MARKER`] is present anywhere in page 0.
    #[inline]
    pub fn sa_marker_present(&self) -> bool {
        self.sa_marker_present
    }

    /// `true` iff the 32-bit magic at offset 0x14 equals [`SA_MAGIC`].
    #[inline]
    pub fn magic_ok(&self) -> bool {
        self.magic == SA_MAGIC
    }

    /// `flags_06` with [`FLAGS_06_BASE`]'s bits masked out, leaving whatever
    /// variant bits (if any) are set on top of it.
    ///
    /// What any given bit *means* isn't known yet - only that bit 5 (`0x20`)
    /// and bit 6 (`0x40`) are the two observed so far. Bit 5 was seen to
    /// co-occur with a lowercase page-type-byte variant on one file, but
    /// that correlation isn't confirmed as causal. See `SPECIFICATION.md`
    /// section 6 and [`PageType::from_byte`](crate::PageType::from_byte).
    #[inline]
    pub fn flags_06_variant_bits(&self) -> u8 {
        self.flags_06 & !FLAGS_06_BASE
    }
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sb_with_flags(flags_06: u8) -> Superblock {
        Superblock {
            flags_06,
            current_lsn: 0,
            format_major: 3,
            magic: SA_MAGIC,
            version_a: 201,
            version_b: 12,
            page_count_hint: 0,
            sa_marker_present: true,
        }
    }

    #[test]
    fn flags_06_variant_bits_base_is_zero() {
        assert_eq!(sb_with_flags(FLAGS_06_BASE).flags_06_variant_bits(), 0x00);
    }

    #[test]
    fn flags_06_variant_bits_recovers_known_bits() {
        // 0x49 = base | bit 6 (originally observed second value).
        assert_eq!(sb_with_flags(0x49).flags_06_variant_bits(), 0x40);
        // 0x29 = base | bit 5 (QuickBooks Enterprise 24.0, openqbw#16).
        assert_eq!(sb_with_flags(0x29).flags_06_variant_bits(), 0x20);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(matches!(
            Superblock::parse(&[0u8; 100]),
            Err(Error::WrongBufferLength { .. })
        ));
    }
}
