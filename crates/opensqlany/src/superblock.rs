use crate::page::PAGE_SIZE;

/// Magic value at superblock offset 0x14. Appears as bytes `5E BA 7A DA`
/// (little-endian u32 = `0xDA7ABA5E`).
pub const SA_MAGIC: u32 = 0xDA7A_BA5E;

/// The 33-byte copyright substring that pins the engine to SAP SQL
/// Anywhere 17.0.4 build 2182 (2015 release).
pub const SA_COPYRIGHT_MARKER: &[u8] = b"SAP SE, Copyright (c)2015 17.0.4.";

/// Parsed view of the page-0 superblock.
///
/// Only fields that are invariant across the 112-file corpus are named;
/// other fields are held as raw bytes. See `SPECIFICATION.md §3`.
#[derive(Debug, Clone, Copy)]
pub struct Superblock {
    /// Flag byte at offset 0x06. Observed values: `0x09`, `0x49`.
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
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
