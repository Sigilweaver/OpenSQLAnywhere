use std::io;

use thiserror::Error;

/// Convenience result type aliased to [`enum@Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the SA17 reader.
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error reading the page store.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// File size is not a multiple of the page size.
    #[error("file size {size} is not a multiple of page size {page_size}")]
    NotPageAligned {
        /// File size in bytes.
        size: u64,
        /// Expected page size.
        page_size: usize,
    },

    /// File is smaller than one page (no superblock).
    #[error("file too small for a page store ({size} bytes)")]
    TooSmall {
        /// File size in bytes.
        size: u64,
    },

    /// Page index out of range for this store.
    #[error("page {page} out of range (store has {total} pages)")]
    PageOutOfRange {
        /// Requested page number.
        page: u64,
        /// Total pages in the store.
        total: u64,
    },

    /// Superblock magic did not match the expected SA17 value.
    #[error("bad superblock magic: 0x{got:08X} (want 0x{want:08X})")]
    BadMagic {
        /// Magic found at superblock offset 0x14.
        got: u32,
        /// Expected magic.
        want: u32,
    },

    /// Per-page CRC-32 footer did not match the computed value.
    #[error("crc mismatch on page {page}: stored 0x{stored:08X}, computed 0x{computed:08X}")]
    BadCrc {
        /// Zero-based page number.
        page: u64,
        /// CRC stored in the page footer.
        stored: u32,
        /// CRC computed over the page body.
        computed: u32,
    },

    /// One of the reserved-zero regions of the page trailer was non-zero.
    #[error("bad page trailer on page {page}: reserved bytes non-zero")]
    BadTrailer {
        /// Zero-based page number.
        page: u64,
    },
}
