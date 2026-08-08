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

/// Parsed view of the page-0 superblock.
///
/// Only fields that are invariant across the 112-file corpus are named;
/// other fields are held as raw bytes. See `SPECIFICATION.md §3`.
#[derive(Debug, Clone, Copy)]
pub struct Superblock {
    /// Flag byte at offset 0x06. See [`FLAGS_06_BASE`] and
    /// [`Superblock::flags_06_variant_bits`] for how to interpret it.
    pub flags_06: u8,
    /// Low 32 bits of the per-file identifier at offset 0x08.
    pub file_id_lo: u32,
    /// u32_LE at offset 0x10. Always `3` in the corpus.
    pub format_major: u32,
    /// u32_LE at offset 0x14.
    pub magic: u32,
    /// u16_LE at offset 0x18. Always `201` in the corpus.
    pub version_a: u16,
    /// u16_LE at offset 0x1A. Always `12` in the corpus.
    pub version_b: u16,
    /// u32_LE at offset 0x1C. Typically `total_pages - 128`.
    pub page_count_hint: u32,
    /// `true` iff [`SA_COPYRIGHT_MARKER`] is present anywhere in page 0.
    pub sa_marker_present: bool,
}

impl Superblock {
    /// Parse the superblock from the first page of a store.
    ///
    /// `page0` must be exactly [`PAGE_SIZE`] bytes long.
    pub fn parse(page0: &[u8]) -> Self {
        assert_eq!(page0.len(), PAGE_SIZE, "page 0 must be exactly 4096 bytes");

        let flags_06 = page0[0x06];
        let file_id_lo = u32::from_le_bytes(page0[0x08..0x0C].try_into().unwrap());
        let format_major = u32::from_le_bytes(page0[0x10..0x14].try_into().unwrap());
        let magic = u32::from_le_bytes(page0[0x14..0x18].try_into().unwrap());
        let version_a = u16::from_le_bytes(page0[0x18..0x1A].try_into().unwrap());
        let version_b = u16::from_le_bytes(page0[0x1A..0x1C].try_into().unwrap());
        let page_count_hint = u32::from_le_bytes(page0[0x1C..0x20].try_into().unwrap());

        let sa_marker_present = memmem(page0, SA_COPYRIGHT_MARKER).is_some();

        Superblock {
            flags_06,
            file_id_lo,
            format_major,
            magic,
            version_a,
            version_b,
            page_count_hint,
            sa_marker_present,
        }
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
    /// §6 and [`PageType::from_byte`](crate::PageType::from_byte).
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
            file_id_lo: 0,
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
}
