use std::io;

use thiserror::Error;

/// Convenience result type aliased to [`enum@Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Broad category of an [`enum@Error`], for callers that map failures to
/// their own error types without matching every variant.
///
/// New categories can be added in a minor release; match with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Reading from the operating system failed.
    Io,
    /// The input is not shaped like an SA17 page store (size, magic, buffer
    /// length).
    Format,
    /// The input is shaped like a page store but a stored integrity check
    /// (CRC, reserved bytes) failed.
    Integrity,
    /// The input is a page store this reader does not support (format
    /// version).
    Unsupported,
    /// The AP keystream could not be determined with enough confidence.
    Keystream,
    /// A page's internal structure (slot directory, prelude) could not be
    /// determined with enough confidence.
    Structure,
}

/// Errors returned by the SA17 reader.
///
/// This enum is `#[non_exhaustive]`: new variants are added in minor
/// releases. Use [`Error::kind`] to branch on a category, and treat the
/// `Display` text as a human-readable message rather than something to
/// parse.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error reading the page store.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// File size is not a multiple of the page size.
    #[error("file size {size} is not a multiple of page size {page_size}")]
    #[non_exhaustive]
    NotPageAligned {
        /// File size in bytes.
        size: u64,
        /// Expected page size.
        page_size: usize,
    },

    /// File is smaller than one page (no superblock).
    #[error("file too small for a page store ({size} bytes)")]
    #[non_exhaustive]
    TooSmall {
        /// File size in bytes.
        size: u64,
    },

    /// Fewer bytes were read than the file size reported before reading.
    #[error("short read: expected {expected} bytes, read {got}")]
    #[non_exhaustive]
    ShortRead {
        /// Size reported by the file system before the read.
        expected: u64,
        /// Bytes actually read.
        got: u64,
    },

    /// A buffer handed to the reader does not have the length of the
    /// structure being parsed.
    #[error("wrong buffer length: need {expected} bytes, got {got}")]
    #[non_exhaustive]
    WrongBufferLength {
        /// Bytes required.
        expected: usize,
        /// Bytes supplied.
        got: usize,
    },

    /// Page index out of range for this store.
    #[error("page {page} out of range (store has {total} pages)")]
    #[non_exhaustive]
    PageOutOfRange {
        /// Requested page number.
        page: u64,
        /// Total pages in the store.
        total: u64,
    },

    /// Superblock magic did not match the expected SA17 value.
    #[error("bad superblock magic: 0x{got:08X} (want 0x{want:08X})")]
    #[non_exhaustive]
    BadMagic {
        /// Magic found at superblock offset 0x14.
        got: u32,
        /// Expected magic.
        want: u32,
    },

    /// The superblock names a format version this reader does not decode.
    #[error("unsupported format version {major}.{a}.{b}")]
    #[non_exhaustive]
    UnsupportedVersion {
        /// `format_major` at superblock offset 0x10.
        major: u32,
        /// `version_a` at superblock offset 0x18.
        a: u16,
        /// `version_b` at superblock offset 0x1A.
        b: u16,
    },

    /// Per-page CRC-32 footer did not match the computed value.
    #[error("crc mismatch on page {page}: stored 0x{stored:08X}, computed 0x{computed:08X}")]
    #[non_exhaustive]
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
    #[non_exhaustive]
    BadTrailer {
        /// Zero-based page number.
        page: u64,
    },

    /// No page in the store carries enough AP fill to calibrate the
    /// keystream.
    #[error("no pure-AP page could calibrate the keystream")]
    NoCalibration,

    /// The calibration pages read as plaintext, so the store is not
    /// AP-obfuscated.
    #[error("store does not look AP-obfuscated")]
    NotObfuscated,

    /// A sector's step could not be told apart from its runner-up.
    #[error(
        "page {page} sector {sector}: keystream step is low confidence (peak {peak}, runner-up {runner_up})"
    )]
    #[non_exhaustive]
    LowConfidenceKeystream {
        /// Zero-based page number.
        page: u64,
        /// Sector index within the page (0..8).
        sector: usize,
        /// Histogram peak of the chosen step.
        peak: usize,
        /// Histogram peak of the best competing step.
        runner_up: usize,
    },

    /// Calibration evidence on one page points at more than one `bv`.
    #[error("page {page}: calibration is ambiguous between bv candidates {candidates:?}")]
    #[non_exhaustive]
    AmbiguousCalibration {
        /// Zero-based page number.
        page: u64,
        /// The competing `bv` values, ascending.
        candidates: Vec<u8>,
    },

    /// The decoded page matched no structural check, so the guessed keystream
    /// is unverified.
    #[error("page {page}: keystream bv 0x{bv:02X} could not be verified")]
    #[non_exhaustive]
    KeystreamUnverified {
        /// Zero-based page number.
        page: u64,
        /// The best-scoring `bv`.
        bv: u8,
    },

    /// A row offset points into the slot directory itself.
    #[error(
        "page {page}: slot offset 0x{offset:04X} lies inside the directory ending at 0x{directory_end:04X}"
    )]
    #[non_exhaustive]
    SlotOffsetInDirectory {
        /// Zero-based page number.
        page: u64,
        /// The offending row offset.
        offset: u16,
        /// First byte after the directory.
        directory_end: usize,
    },

    /// More than one slot directory candidate fits the page.
    #[error("page {page}: more than one slot directory candidate fits")]
    #[non_exhaustive]
    AmbiguousSlotDirectory {
        /// Zero-based page number.
        page: u64,
    },

    /// The slot directory has fewer entries than the page prelude declares.
    #[error("page {page}: slot directory has {found} entries, prelude declares {expected}")]
    #[non_exhaustive]
    SlotDirectoryTruncated {
        /// Zero-based page number.
        page: u64,
        /// Entries found.
        found: usize,
        /// Entries the prelude declares.
        expected: usize,
    },

    /// The bytes before the slot directory could not be interpreted.
    #[error("page {page}: page prelude could not be interpreted")]
    #[non_exhaustive]
    UnknownPrelude {
        /// Zero-based page number.
        page: u64,
    },

    /// No slot directory was found on a page that was expected to have one.
    #[error("page {page}: no slot directory found ({reason})")]
    #[non_exhaustive]
    NoSlotDirectory {
        /// Zero-based page number.
        page: u64,
        /// Why no directory qualified.
        reason: &'static str,
    },
}

impl Error {
    /// The broad category of this error.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::Io(_) => ErrorKind::Io,
            Error::NotPageAligned { .. }
            | Error::TooSmall { .. }
            | Error::ShortRead { .. }
            | Error::WrongBufferLength { .. }
            | Error::PageOutOfRange { .. }
            | Error::BadMagic { .. } => ErrorKind::Format,
            Error::UnsupportedVersion { .. } => ErrorKind::Unsupported,
            Error::BadCrc { .. } | Error::BadTrailer { .. } => ErrorKind::Integrity,
            Error::NoCalibration
            | Error::NotObfuscated
            | Error::LowConfidenceKeystream { .. }
            | Error::AmbiguousCalibration { .. }
            | Error::KeystreamUnverified { .. } => ErrorKind::Keystream,
            Error::SlotOffsetInDirectory { .. }
            | Error::AmbiguousSlotDirectory { .. }
            | Error::SlotDirectoryTruncated { .. }
            | Error::UnknownPrelude { .. }
            | Error::NoSlotDirectory { .. } => ErrorKind::Structure,
        }
    }

    /// The zero-based page number the error refers to, when it is about one
    /// page.
    pub fn page(&self) -> Option<u64> {
        match self {
            Error::PageOutOfRange { page, .. }
            | Error::BadCrc { page, .. }
            | Error::BadTrailer { page }
            | Error::LowConfidenceKeystream { page, .. }
            | Error::AmbiguousCalibration { page, .. }
            | Error::KeystreamUnverified { page, .. }
            | Error::SlotOffsetInDirectory { page, .. }
            | Error::AmbiguousSlotDirectory { page }
            | Error::SlotDirectoryTruncated { page, .. }
            | Error::UnknownPrelude { page }
            | Error::NoSlotDirectory { page, .. } => Some(*page),
            _ => None,
        }
    }
}
