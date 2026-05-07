//! SAP SQL Anywhere page-store reader.
//!
//! This crate parses the on-disk page-store format of SAP SQL Anywhere
//! (initially targeting SA17 build 2182, 2015 release). It provides:
//!
//! * [`PageStore`]: zero-copy random-access iteration over 4 KiB pages.
//! * [`Superblock`]: page-0 parser (magic, format version triple).
//! * [`PageTrailer`]: the universal 12-byte trailer at `0xFF0..0xFFB`.
//! * [`verify_crc`]: per-page CRC-32 integrity check.
//! * [`SlottedPage`]: descending row-offset-array catalog-page parser.
//!
//! # Scope
//!
//! This release (v0.1) covers the **page-store layer only**: opening a file,
//! iterating pages, validating integrity, classifying pages by type, and
//! decoding slotted-page directories. System catalog parsing
//! (`SYSTABLE`/`SYSCOLUMN`/`SYSINDEX` rows and typed column values) is
//! planned for a later release.
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
//!     let trailer = page.trailer();
//!     page.verify_crc()?;
//!     println!("page {pn}: type {:?}", trailer.page_type());
//! }
//! # Ok::<(), opensqlany::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod page;
mod slotted;
mod store;
mod superblock;

pub use error::{Error, Result};
pub use page::{Page, PageTrailer, PageType, PAGE_SIZE};
pub use slotted::{SlotDirectory, SlottedPage};
pub use store::{PageStore, Pages};
pub use superblock::{Superblock, SA_COPYRIGHT_MARKER, SA_MAGIC};

/// The page-size in bytes (4 KiB). This is fixed across all SA17 files
/// observed to date.
pub const PAGE_SIZE_BYTES: usize = 4096;
