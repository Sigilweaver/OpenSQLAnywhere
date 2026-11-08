//! SAP SQL Anywhere page-store reader.
//!
//! This crate parses the on-disk page-store format of SAP SQL Anywhere
//! (initially targeting SA17 build 2182, 2015 release). It provides:
//!
//! * [`PageStore`]: zero-copy random-access iteration over 4 KiB pages.
//! * [`Superblock`]: page-0 parser (magic, format version triple).
//! * [`PageTrailer`]: the universal 12-byte trailer at `0xFF0..0xFFB`.
//!   Call [`Page::verify_crc`] for per-page CRC-32 integrity checks.
//! * [`SlottedPage`]: descending row-offset-array catalog-page parser.
//! * [`ApModel`]: arithmetic-progression stream-cipher deobfuscation.
//!
//! # Errors, options and warnings
//!
//! Every decoding entry point returns [`Result`]. Reads are strict by
//! default: input the reader cannot decode with confidence is an
//! [`Error`]. [`ReadOptions`] carries a [`Leniency`] set that turns named
//! families of errors into [`Warning`]s on the returned result. [`Error`],
//! [`WarningKind`], [`PageType`] and the result types are
//! `#[non_exhaustive]`, so new variants and fields are added in minor
//! releases.
//!
//! # Scope
//!
//! The page-store API opens files, validates their integrity and inspects
//! physical pages. For QBW row pages, [`RowSectorReader`] reconstructs
//! length-checked slots with evidence for the regions it used. [`CatalogFragment`]
//! reads observed physical table and column definitions. [`SchemaHistory`]
//! selects a catalog-declared column layout and [`TablePageBitmap`] checks a
//! physical table record's page list. Unresolved regions and historical
//! copies matter when interpreting these records as current SQL rows.
//!
//! # Example
//!
//! ```no_run
//! use opensqlany::PageStore;
//!
//! let store = PageStore::open("database.db")?;
//! let sb = store.superblock()?;
//! assert!(sb.magic_ok());
//!
//! for (pn, page) in store.pages().enumerate().skip(1) {
//!     let page = page?;
//!     let trailer = page.trailer();
//!     page.verify_crc()?;
//!     println!("page {pn}: type {:?}", trailer.page_type());
//! }
//! # Ok::<(), opensqlany::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod ap;
mod calibration;
mod catalog;
mod error;
mod options;
mod page;
mod page_bitmap;
mod record;
mod row;
mod slotted;
mod store;
mod superblock;
mod verify;
mod warning;

pub use ap::{
    ApModel, BvSource, Confidence, DeobfuscatedPage, Evidence, LearnReport, SECTOR_SIZE,
    SECTORS_PER_PAGE, SectorFit,
};
pub use calibration::{
    CalibratedPage, CalibratedStore, CalibrationGap, WholePageFraming, WholePageRecovery,
};
pub use catalog::CatalogFragment;
pub use catalog::bootstrap::{CatalogBootstrapError, SelfCatalogBootstrap};
pub use catalog::columns::{ColumnCatalogMap, ColumnCatalogMembers, ColumnCatalogSlots};
pub use catalog::recovery::{
    CatalogRecoveryContext, CatalogRecoveryError, CatalogRowCandidate, CorroboratedCatalogPage,
    recover_catalog_slot,
};
pub use catalog::schema_history::{CatalogSchemaVersions, SchemaHistory, SchemaHistoryError};
pub use catalog::witness::{
    CatalogChunkWitness, CatalogChunkWitnessError, CatalogChunkWitnesses, Witnessed,
};
pub use error::{Error, ErrorKind, Result};
pub use options::{Leniency, ReadOptions};
pub use page::{PAGE_SIZE, Page, PageTrailer, PageType};
pub use page_bitmap::bitset::{
    DecodedBitset, StoredBitsetCandidate, StoredBitsetError, decode_serialized_bitset,
};
pub use page_bitmap::{
    BitmapConflictWitness, BitmapLiteralWitness, BitmapSectorWitness, CatalogPageClaims,
    EmptyMapAllocation, LinkedBitmapSearch, LinkedBitmapSector, LinkedMapChunk, LinkedMapEvidence,
    PageBitmapError, TableMapRead, TablePageBitmap, TablePageCounts,
};
pub use record::byte_chain::{ByteChainCandidate, ByteChainChunk, ByteChainError};
pub use record::compression::{
    CompressedByteCandidate, CompressionError, StoredByteError, decode_compressed_stream,
};
pub use record::long_value::{
    LongValueCandidate, LongValueError, TextChunkPeer, resolve_single_chunk,
};
pub use record::{
    CompressedDescriptor, LongDescriptor, MinimumPaddedRecord, PhysicalNumeric, PhysicalRecord,
    PhysicalValue, RecordColumn, RecordError, RecordLayout,
};
pub use row::forwarded::{ForwardedRow, ForwardedRowError, ForwardedSlot, forwarded_row_address};
pub use row::header::{RowHeaderError, RowPageHeader};
pub use row::physical::{PhysicalRow, RowLengthMismatch};
pub use row::sector::{
    RowSectorCandidate, RowSectorReader, RowSectorRecovery, RowSlotRecovery, RowSlotSector,
};
pub use row::tail::{RowTail, RowTailError};
pub use slotted::{Row, SlotDirectory, SlottedPage};
pub use store::{PageStore, Pages};
pub use superblock::{FLAGS_06_BASE, FormatVersion, SA_COPYRIGHT_MARKER, SA_MAGIC, Superblock};
pub use warning::{Warning, WarningKind};
