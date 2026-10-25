use crate::error::{Error, Result};

/// Size of a single SA17 page in bytes (4 KiB, fixed).
pub const PAGE_SIZE: usize = 4096;

const TRAILER_OFF: usize = 0xFF0;
const CRC_OFF: usize = 0xFFC;

/// A borrowed view of a single 4 KiB page.
///
/// The page is not copied - this wraps a `&[u8; PAGE_SIZE]` slice owned by
/// a [`PageStore`](crate::PageStore).
#[derive(Debug, Clone, Copy)]
pub struct Page<'a> {
    pub(crate) index: u64,
    pub(crate) bytes: &'a [u8],
}

impl<'a> Page<'a> {
    /// Construct a `Page` view over an explicit byte slice.
    ///
    /// Useful for callers that already hold the bytes of a page (for
    /// example the plaintext from
    /// [`DeobfuscatedPage`](crate::DeobfuscatedPage)) and want to drive the
    /// slotted-page parser without a [`PageStore`](crate::PageStore).
    /// `bytes` must be exactly [`PAGE_SIZE`] long; any other length is
    /// [`Error::WrongBufferLength`], so a multi-page buffer is never
    /// silently cut to its first page.
    pub fn from_bytes(index: u64, bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != PAGE_SIZE {
            return Err(Error::WrongBufferLength {
                expected: PAGE_SIZE,
                got: bytes.len(),
            });
        }
        Ok(Page { index, bytes })
    }

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
        let mut raw = [0u8; 12];
        raw.copy_from_slice(&self.bytes[TRAILER_OFF..CRC_OFF]);
        PageTrailer { raw }
    }

    /// Log sequence number of this page's last write, from trailer
    /// `0xFF4..0xFF8`.
    ///
    /// Shorthand for `self.trailer().lsn()`. See [`PageTrailer::lsn`].
    #[inline]
    pub fn lsn(&self) -> u32 {
        self.trailer().lsn()
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
    ///
    /// For an AP-obfuscated store the CRC covers the stored (obfuscated)
    /// bytes, so it checks the page's integrity, not a deobfuscation
    /// guess.
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
    /// The reserved regions are byte `0xFF3` and bytes `0xFF8..0xFFB`.
    /// Bytes `0xFF6..0xFF7` were previously checked as reserved too, but
    /// they are the high half of [`PageTrailer::lsn`] and are non-zero on
    /// any file whose LSN has passed 65 535 - which rejected valid pages.
    pub fn verify_trailer(&self) -> Result<()> {
        if self.trailer().reserved_zero() {
            Ok(())
        } else {
            Err(Error::BadTrailer { page: self.index })
        }
    }
}

/// Parsed view of the 12-byte trailer at offsets `0xFF0..0xFFB`.
///
/// Accessors are named by meaning rather than by byte offset. [`raw`] is the
/// offset-neutral escape hatch for bytes whose meaning is not yet known.
///
/// [`raw`]: PageTrailer::raw
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct PageTrailer {
    raw: [u8; 12],
}

impl PageTrailer {
    /// The 12 trailer bytes as stored.
    #[inline]
    pub fn raw(&self) -> [u8; 12] {
        self.raw
    }

    /// Raw page-type byte at 0xFF2 (ASCII).
    #[inline]
    pub fn page_type_raw(&self) -> u8 {
        self.raw[2]
    }

    /// Classify [`Self::page_type_raw`] into a known [`PageType`].
    #[inline]
    pub fn page_type(&self) -> PageType {
        PageType::from_byte(self.page_type_raw())
    }

    /// `true` when the page-type byte carries the lowercase (0x20) case bit.
    ///
    /// Pages with the bit set show a newer LSN distribution than the same
    /// type without it; see `SPECIFICATION.md` section 2.3 and 6. What it
    /// means is not confirmed.
    #[inline]
    pub fn case_variant(&self) -> bool {
        let b = self.page_type_raw();
        b.is_ascii_lowercase()
    }

    /// u32_LE at 0xFF4..0xFF8 - the log sequence number of the page's
    /// last write.
    ///
    /// The per-file maximum tracks the u32 at superblock offset `0x08`
    /// ([`Superblock::current_lsn`](crate::Superblock::current_lsn)) minus
    /// ten. See `SPECIFICATION.md` section 2.2a.
    #[inline]
    pub fn lsn(&self) -> u32 {
        u32::from_le_bytes([self.raw[4], self.raw[5], self.raw[6], self.raw[7]])
    }

    /// `true` iff the reserved-zero bytes (`0xFF3` and `0xFF8..0xFFB`) are
    /// all zero.
    #[inline]
    pub fn reserved_zero(&self) -> bool {
        self.raw[3] == 0 && self.raw[8..12] == [0; 4]
    }
}

/// Known page types, from the byte at trailer offset `0xFF2`.
///
/// Names reflect the working hypothesis from corpus analysis; see
/// `SPECIFICATION.md` section 2.2a. New variants are added in minor
/// releases as page types are understood; match with a wildcard arm.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum PageType {
    /// `'E'` (0x45) - extent / data page. ~53 % of pages in the corpus.
    Extent,
    /// `'A'` (0x41) - allocation / free-space map. ~46 %.
    Alloc,
    /// `'M'` (0x4D) - map / metadata.
    Map,
    /// `'H'` (0x48) - header block.
    Header,
    /// `'C'` (0x43) - catalog.
    Catalog,
    /// `'@'` (0x40) - reserved / bootstrap (pages 4..7).
    Bootstrap,
    /// `'I'` (0x49) - index.
    Index,
    /// Any other byte, including types whose role is not yet known (for
    /// example `'G'`), retained for exhaustive classification.
    Other(u8),
}

impl PageType {
    /// Map a raw byte from trailer offset `0xFF2` to a [`PageType`].
    ///
    /// Classification is case-insensitive: some files (observed on
    /// QuickBooks Enterprise 24.0) carry a lowercase page-type byte (e.g.
    /// `'e'` 0x65 rather than `'E'` 0x45) on otherwise-ordinary extent
    /// pages. The case distinction - which may itself be meaningful - is
    /// available from [`PageTrailer::case_variant`].
    #[inline]
    pub fn from_byte(b: u8) -> Self {
        match b.to_ascii_uppercase() {
            b'E' => PageType::Extent,
            b'A' => PageType::Alloc,
            b'M' => PageType::Map,
            b'H' => PageType::Header,
            b'C' => PageType::Catalog,
            b'@' => PageType::Bootstrap,
            b'I' => PageType::Index,
            _ => PageType::Other(b),
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
            PageType::Other(_) => "other",
        }
    }

    /// The raw byte at trailer offset `0xFF2` (upper case for known types).
    pub fn as_byte(&self) -> u8 {
        match self {
            PageType::Extent => b'E',
            PageType::Alloc => b'A',
            PageType::Map => b'M',
            PageType::Header => b'H',
            PageType::Catalog => b'C',
            PageType::Bootstrap => b'@',
            PageType::Index => b'I',
            PageType::Other(b) => *b,
        }
    }
}
