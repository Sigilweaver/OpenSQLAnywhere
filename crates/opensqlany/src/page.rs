use crate::error::{Error, Result};

/// Size of a single SA17 page in bytes (4 KiB, fixed).
pub const PAGE_SIZE: usize = 4096;

const TRAILER_OFF: usize = 0xFF0;
const CRC_OFF: usize = 0xFFC;

/// A borrowed view of a single 4 KiB page.
///
/// The page is not copied — this wraps a `&[u8; PAGE_SIZE]` slice owned by
/// a [`PageStore`](crate::PageStore).
#[derive(Debug, Clone, Copy)]
pub struct Page<'a> {
    pub(crate) index: u64,
    pub(crate) bytes: &'a [u8],
}

impl<'a> Page<'a> {
    /// Zero-based page number within the store.
    #[inline]
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Raw bytes of the page (always [`PAGE_SIZE`] long).
    #[inline]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The 12-byte page trailer at offsets `0xFF0..0xFFB`.
    #[inline]
    pub fn trailer(&self) -> PageTrailer {
        let t = &self.bytes[TRAILER_OFF..CRC_OFF];
        PageTrailer {
            flag_ff0: t[0],
            flag_ff1: t[1],
            page_type_raw: t[2],
            zero_ff3: t[3],
            meta_ff4: t[4],
            meta_ff5: t[5],
            zero_ff6: [t[6], t[7], t[8], t[9], t[10], t[11]],
        }
    }

    /// CRC-32 stored in the footer at `0xFFC..0x1000` (little-endian).
    #[inline]
    pub fn stored_crc(&self) -> u32 {
        u32::from_le_bytes([
            self.bytes[CRC_OFF],
            self.bytes[CRC_OFF + 1],
            self.bytes[CRC_OFF + 2],
            self.bytes[CRC_OFF + 3],
        ])
    }

    /// CRC-32 (zlib/IEEE) computed over bytes `0..0xFFC`.
    #[inline]
    pub fn computed_crc(&self) -> u32 {
        crc32fast::hash(&self.bytes[..CRC_OFF])
    }

    /// Returns `Ok(())` if the stored and computed CRCs match, or
    /// [`Error::BadCrc`] otherwise.
    pub fn verify_crc(&self) -> Result<()> {
        let stored = self.stored_crc();
        let computed = self.computed_crc();
        if stored == computed {
            Ok(())
        } else {
            Err(Error::BadCrc {
                page: self.index,
                stored,
                computed,
            })
        }
    }

    /// Returns `Ok(())` if the trailer's reserved-zero regions are zero.
    ///
    /// Observed across 456 409 pages of 112 files: byte `0xFF3` and bytes
    /// `0xFF6..0xFFB` are always zero on pages with a non-zero body.
    pub fn verify_trailer(&self) -> Result<()> {
        let t = self.trailer();
        if t.zero_ff3 == 0 && t.zero_ff6 == [0; 6] {
            Ok(())
        } else {
            Err(Error::BadTrailer { page: self.index })
        }
    }
}

/// Parsed view of the 12-byte trailer at offsets `0xFF0..0xFFB`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PageTrailer {
    /// Byte at 0xFF0. Per-type variable.
    pub flag_ff0: u8,
    /// Byte at 0xFF1. Almost always 0x00.
    pub flag_ff1: u8,
    /// Raw page-type byte at 0xFF2 (ASCII).
    pub page_type_raw: u8,
    /// Byte at 0xFF3. Reserved, always 0x00.
    pub zero_ff3: u8,
    /// Byte at 0xFF4. Per-type variable.
    pub meta_ff4: u8,
    /// Byte at 0xFF5. Per-type variable.
    pub meta_ff5: u8,
    /// Bytes at 0xFF6..0xFFB. Reserved, always zero.
    pub zero_ff6: [u8; 6],
}

impl PageTrailer {
    /// Classify [`Self::page_type_raw`] into a known [`PageType`].
    #[inline]
    pub fn page_type(&self) -> PageType {
        PageType::from_byte(self.page_type_raw)
    }
}

/// Known page types, from the byte at trailer offset `0xFF2`.
///
/// Names reflect the working hypothesis from corpus analysis; see
/// `SPECIFICATION.md §2.2a`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PageType {
    /// `'E'` (0x45) — extent / data page. ~53 % of pages in the corpus.
    Extent,
    /// `'A'` (0x41) — allocation / free-space map. ~46 %.
    Alloc,
    /// `'M'` (0x4D) — map / metadata.
    Map,
    /// `'H'` (0x48) — header block.
    Header,
    /// `'C'` (0x43) — catalog.
    Catalog,
    /// `'@'` (0x40) — reserved / bootstrap (pages 4..7).
    Bootstrap,
    /// `'I'` (0x49) — index.
    Index,
    /// `'G'` (0x47) — currently unknown.
    UnknownG,
    /// Any other byte, retained for exhaustive classification.
    Other(u8),
}

impl PageType {
    /// Map a raw byte from trailer offset `0xFF2` to a [`PageType`].
    #[inline]
    pub fn from_byte(b: u8) -> Self {
        match b {
            b'E' => PageType::Extent,
            b'A' => PageType::Alloc,
            b'M' => PageType::Map,
            b'H' => PageType::Header,
            b'C' => PageType::Catalog,
            b'@' => PageType::Bootstrap,
            b'I' => PageType::Index,
            b'G' => PageType::UnknownG,
            other => PageType::Other(other),
        }
    }

    /// Short lowercase name suitable for logs and CLI output.
    pub fn name(&self) -> &'static str {
        match self {
            PageType::Extent => "extent",
            PageType::Alloc => "alloc",
            PageType::Map => "map",
            PageType::Header => "header",
            PageType::Catalog => "catalog",
            PageType::Bootstrap => "bootstrap",
            PageType::Index => "index",
            PageType::UnknownG => "unknown_G",
            PageType::Other(_) => "other",
        }
    }

    /// The raw byte at trailer offset `0xFF2`.
    pub fn as_byte(&self) -> u8 {
        match self {
            PageType::Extent => b'E',
            PageType::Alloc => b'A',
            PageType::Map => b'M',
            PageType::Header => b'H',
            PageType::Catalog => b'C',
            PageType::Bootstrap => b'@',
            PageType::Index => b'I',
            PageType::UnknownG => b'G',
            PageType::Other(b) => *b,
        }
    }
}
