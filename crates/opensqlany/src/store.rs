use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::{Error, Result};
use crate::options::{Leniency, ReadOptions};
use crate::page::{PAGE_SIZE, Page};
use crate::superblock::{FLAGS_06_BASE, FormatVersion, SA_MAGIC, Superblock};
use crate::warning::{Warning, WarningKind};

/// An SA17 page-store opened from disk.
///
/// The whole file is read into memory on [`PageStore::open`]. This is
/// appropriate for the file sizes the format typically produces
/// (13-45 MiB in the QBW corpus) and keeps the API zero-copy at the
/// per-page level.
#[derive(Debug)]
pub struct PageStore {
    bytes: Vec<u8>,
    warnings: Vec<Warning>,
}

/// How the superblock's bookkeeping compares with the pages actually present.
///
/// Neither relation is a test for a damaged copy. On the 112-file corpus 80
/// files satisfy both; 29 have a page-count match but a highest page LSN
/// that is 14 (not 10) below the superblock LSN; 3 have a page count that
/// differs from the hint by 242, 197 and 78. All 32 have clean CRCs.
/// The values are reported so a caller can look at them; nothing enforces
/// them. See `SPECIFICATION.md` sections 2.2a and 3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Consistency {
    page_count: u64,
    page_count_hint: u32,
    max_page_lsn: u32,
    current_lsn: u32,
}

impl Consistency {
    /// Pages in the store.
    pub fn page_count(&self) -> u64 {
        self.page_count
    }

    /// The superblock's page-count hint.
    pub fn page_count_hint(&self) -> u32 {
        self.page_count_hint
    }

    /// `true` when `page_count_hint + 128` equals the number of pages (109 of
    /// the 112 corpus files).
    pub fn page_count_matches(&self) -> bool {
        self.page_count == u64::from(self.page_count_hint) + 128
    }

    /// Highest page LSN present in the store.
    pub fn max_page_lsn(&self) -> u32 {
        self.max_page_lsn
    }

    /// The superblock's current LSN.
    pub fn current_lsn(&self) -> u32 {
        self.current_lsn
    }

    /// Superblock LSN minus the highest page LSN: 10 on 83 corpus files and
    /// 14 on 29. `None` when the page LSN is the larger.
    pub fn lsn_gap(&self) -> Option<u32> {
        self.current_lsn.checked_sub(self.max_page_lsn)
    }
}

fn check_size(size: u64) -> Result<()> {
    if size < PAGE_SIZE as u64 {
        return Err(Error::TooSmall { size });
    }
    if !size.is_multiple_of(PAGE_SIZE as u64) {
        return Err(Error::NotPageAligned {
            size,
            page_size: PAGE_SIZE,
        });
    }
    Ok(())
}

impl PageStore {
    /// Open a page store by path, requiring a SQL Anywhere 17 superblock.
    ///
    /// Shorthand for [`PageStore::open_with`] with strict options.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(path, &ReadOptions::default())
    }

    /// Open a page store by path and validate the superblock: the magic, the
    /// `(3, 201, 12)` format triple and the `flags_06` base bits.
    ///
    /// # Errors
    ///
    /// * [`Error::ShortRead`] when fewer bytes were read than the file size
    ///   reported before reading (a file that changed while being read).
    /// * [`Error::BadMagic`] always when the magic is wrong.
    /// * [`Error::UnsupportedVersion`] or [`Error::UnsupportedFlags`] for
    ///   another build; accepted with a warning under [`Leniency::FORMAT`].
    pub fn open_with(path: impl AsRef<Path>, opts: &ReadOptions) -> Result<Self> {
        Self::from_bytes_with(Self::read_file(path)?, opts)
    }

    /// Open a page store by path without validating the superblock, for
    /// inspecting files that might not be SA17.
    pub fn open_unchecked(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_bytes_unchecked(Self::read_file(path)?)
    }

    fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
        let mut f = File::open(path)?;
        let size = f.metadata()?.len();
        check_size(size)?;
        let mut bytes = Vec::with_capacity(size as usize);
        f.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != size {
            return Err(Error::ShortRead {
                expected: size,
                got: bytes.len() as u64,
            });
        }
        Ok(bytes)
    }

    /// Wrap an already-materialised byte buffer as a page store, requiring a
    /// SQL Anywhere 17 superblock. Shorthand for
    /// [`PageStore::from_bytes_with`] with strict options.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Self::from_bytes_with(bytes, &ReadOptions::default())
    }

    /// As [`PageStore::open_with`], over a buffer. The buffer length must be a
    /// positive multiple of [`PAGE_SIZE`].
    pub fn from_bytes_with(bytes: Vec<u8>, opts: &ReadOptions) -> Result<Self> {
        let mut store = Self::from_bytes_unchecked(bytes)?;
        let sb = store.try_superblock()?;
        if !sb.magic_ok() {
            return Err(Error::BadMagic {
                got: sb.magic(),
                want: SA_MAGIC,
            });
        }
        let lenient = opts.leniency.contains(Leniency::FORMAT);
        if sb.format() != FormatVersion::SA17 {
            let FormatVersion { major, a, b } = sb.format();
            if !lenient {
                return Err(Error::UnsupportedVersion { major, a, b });
            }
            store
                .warnings
                .push(Warning::new(WarningKind::UnsupportedVersion {
                    major,
                    a,
                    b,
                }));
        }
        if sb.flags_06() & FLAGS_06_BASE != FLAGS_06_BASE {
            if !lenient {
                return Err(Error::UnsupportedFlags {
                    flags_06: sb.flags_06(),
                });
            }
            store
                .warnings
                .push(Warning::new(WarningKind::UnsupportedFlags {
                    flags_06: sb.flags_06(),
                }));
        }
        Ok(store)
    }

    /// Wrap a buffer without validating the superblock.
    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Result<Self> {
        check_size(bytes.len() as u64)?;
        Ok(PageStore {
            bytes,
            warnings: Vec::new(),
        })
    }

    /// Conditions accepted while opening under lenient [`ReadOptions`].
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    /// Total number of pages in the store.
    #[inline]
    pub fn page_count(&self) -> u64 {
        (self.bytes.len() / PAGE_SIZE) as u64
    }

    /// Total file size in bytes.
    #[inline]
    pub fn size_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Borrow a single page by zero-based index. The CRC is not checked; see
    /// [`PageStore::page_verified`].
    pub fn page(&self, index: u64) -> Result<Page<'_>> {
        let total = self.page_count();
        if index >= total {
            return Err(Error::PageOutOfRange { page: index, total });
        }
        let start = index as usize * PAGE_SIZE;
        Ok(Page {
            index,
            bytes: &self.bytes[start..start + PAGE_SIZE],
        })
    }

    /// Borrow a page after checking its CRC and trailer.
    ///
    /// An all-zero page is unallocated and passes: its stored CRC is zero
    /// while the CRC of zeros is not. Anything else that fails is
    /// [`Error::BadCrc`] or [`Error::BadTrailer`].
    pub fn page_verified(&self, index: u64) -> Result<Page<'_>> {
        let page = self.page(index)?;
        if !page.is_unallocated() {
            page.verify_crc()?;
            page.verify_trailer()?;
        }
        Ok(page)
    }

    /// Iterate over every page in order, starting at page 0.
    ///
    /// Items are `Result`s so an error is delivered to the caller instead of
    /// ending the iteration early. The iterator returns raw physical
    /// pages: it does not skip free or superseded pages, and it does not
    /// verify the CRC (see [`PageStore::verified_pages`]).
    pub fn pages(&self) -> Pages<'_> {
        Pages {
            store: self,
            next: 0,
            verify: false,
        }
    }

    /// As [`PageStore::pages`], but each item is checked as by
    /// [`PageStore::page_verified`]. A bad page is an `Err` item and the
    /// iteration continues with the next page.
    pub fn verified_pages(&self) -> Pages<'_> {
        Pages {
            store: self,
            next: 0,
            verify: true,
        }
    }

    /// Parse and return the page-0 superblock. This also verifies the
    /// superblock magic; use [`PageStore::try_superblock`] for a
    /// non-failing variant.
    pub fn superblock(&self) -> Result<Superblock> {
        let sb = self.try_superblock()?;
        if !sb.magic_ok() {
            return Err(Error::BadMagic {
                got: sb.magic(),
                want: SA_MAGIC,
            });
        }
        Ok(sb)
    }

    /// Parse the page-0 superblock without validating the magic. Useful
    /// when inspecting files that might not be SA17.
    pub fn try_superblock(&self) -> Result<Superblock> {
        let page0 = self.page(0)?;
        Superblock::parse(page0.bytes())
    }

    /// Compare the superblock's page-count hint and LSN with the pages
    /// present.
    pub fn consistency(&self) -> Result<Consistency> {
        let sb = self.try_superblock()?;
        let mut max_page_lsn = 0u32;
        for page in self.pages().skip(1) {
            max_page_lsn = max_page_lsn.max(page?.lsn());
        }
        Ok(Consistency {
            page_count: self.page_count(),
            page_count_hint: sb.page_count_hint(),
            max_page_lsn,
            current_lsn: sb.current_lsn(),
        })
    }
}

/// Iterator returned by [`PageStore::pages`] and
/// [`PageStore::verified_pages`].
#[derive(Debug)]
pub struct Pages<'a> {
    store: &'a PageStore,
    next: u64,
    verify: bool,
}

impl<'a> Iterator for Pages<'a> {
    type Item = Result<Page<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.store.page_count() {
            return None;
        }
        let index = self.next;
        self.next += 1;
        Some(if self.verify {
            self.store.page_verified(index)
        } else {
            self.store.page(index)
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.store.page_count() - self.next) as usize;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for Pages<'a> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn superblock_page(version_b: u16, flags: u8, magic: u32) -> Vec<u8> {
        let mut p = vec![0u8; PAGE_SIZE];
        p[0x06] = flags;
        p[0x10..0x14].copy_from_slice(&3u32.to_le_bytes());
        p[0x14..0x18].copy_from_slice(&magic.to_le_bytes());
        p[0x18..0x1A].copy_from_slice(&201u16.to_le_bytes());
        p[0x1A..0x1C].copy_from_slice(&version_b.to_le_bytes());
        p
    }

    #[test]
    fn open_rejects_any_page_aligned_file() {
        // Audit finding 11: a file of 0x41 bytes opened fine.
        let err = PageStore::from_bytes(vec![0x41; 2 * PAGE_SIZE]).unwrap_err();
        assert!(matches!(err, Error::BadMagic { .. }), "{err:?}");
        assert!(PageStore::from_bytes_unchecked(vec![0x41; 2 * PAGE_SIZE]).is_ok());
    }

    #[test]
    fn other_builds_are_unsupported_unless_lenient() {
        let bytes = superblock_page(13, 0x09, SA_MAGIC);
        let err = PageStore::from_bytes(bytes.clone()).unwrap_err();
        assert!(matches!(
            err,
            Error::UnsupportedVersion {
                major: 3,
                a: 201,
                b: 13
            }
        ));
        let opts = ReadOptions::default().with_leniency(Leniency::FORMAT);
        let store = PageStore::from_bytes_with(bytes, &opts).unwrap();
        assert_eq!(store.warnings().len(), 1);
    }

    #[test]
    fn flags_without_the_base_bits_are_unsupported() {
        for flags in [0x00u8, 0x40] {
            let err = PageStore::from_bytes(superblock_page(12, flags, SA_MAGIC)).unwrap_err();
            assert!(matches!(err, Error::UnsupportedFlags { flags_06 } if flags_06 == flags));
        }
        for flags in [0x09u8, 0x49, 0x29] {
            assert!(PageStore::from_bytes(superblock_page(12, flags, SA_MAGIC)).is_ok());
        }
    }

    #[test]
    fn open_reads_a_file_from_disk_and_rejects_bad_sizes() {
        let dir = std::env::temp_dir().join(format!("opensqlany-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.db");
        std::fs::write(&good, superblock_page(12, 0x09, SA_MAGIC)).unwrap();
        assert_eq!(PageStore::open(&good).unwrap().page_count(), 1);

        let short = dir.join("short.db");
        std::fs::write(&short, vec![0u8; PAGE_SIZE + 5]).unwrap();
        assert!(matches!(
            PageStore::open_unchecked(&short),
            Err(Error::NotPageAligned { .. })
        ));
        assert!(matches!(
            PageStore::open(dir.join("missing.db")),
            Err(Error::Io(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verified_pages_report_a_bad_page_and_continue() {
        let mut bytes = superblock_page(12, 0x09, SA_MAGIC);
        let mut bad = vec![5u8; PAGE_SIZE];
        bad[PAGE_SIZE - 4..].copy_from_slice(&[1, 2, 3, 4]);
        let mut good = vec![5u8; PAGE_SIZE];
        good[0xFF3] = 0;
        good[0xFF8..0xFFC].fill(0);
        let crc = crc32fast::hash(&good[..0xFFC]);
        good[0xFFC..].copy_from_slice(&crc.to_le_bytes());
        bytes.extend_from_slice(&bad);
        bytes.extend_from_slice(&good);
        bytes.extend_from_slice(&vec![0u8; PAGE_SIZE]); // unallocated
        let store = PageStore::from_bytes_unchecked(bytes).unwrap();
        let results: Vec<bool> = store.verified_pages().skip(1).map(|p| p.is_ok()).collect();
        assert_eq!(results, vec![false, true, true]);
        // Audit finding 18: raw iteration still yields every page as Ok.
        assert_eq!(store.pages().filter(|p| p.is_ok()).count(), 4);
    }

    #[test]
    fn a_page_lsn_gap_other_than_ten_is_reported_not_rejected() {
        // Review S7: 29 of 112 healthy corpus files have a gap of 14.
        let mut sb = superblock_page(12, 0x09, SA_MAGIC);
        sb[0x08..0x0C].copy_from_slice(&114u32.to_le_bytes());
        let mut page = vec![0u8; PAGE_SIZE];
        page[0xFF4..0xFF8].copy_from_slice(&100u32.to_le_bytes());
        let mut bytes = sb;
        bytes.extend_from_slice(&page);
        let store = PageStore::from_bytes(bytes).unwrap();
        assert_eq!(store.consistency().unwrap().lsn_gap(), Some(14));
    }

    #[test]
    fn consistency_compares_hint_and_lsn_with_the_pages() {
        let mut sb = superblock_page(12, 0x09, SA_MAGIC);
        sb[0x08..0x0C].copy_from_slice(&110u32.to_le_bytes());
        sb[0x1C..0x20].copy_from_slice(&(2u32.wrapping_sub(128)).to_le_bytes());
        let mut page = vec![0u8; PAGE_SIZE];
        page[0xFF4..0xFF8].copy_from_slice(&100u32.to_le_bytes());
        let mut bytes = sb;
        bytes.extend_from_slice(&page);
        let store = PageStore::from_bytes_unchecked(bytes).unwrap();
        let c = store.consistency().unwrap();
        assert_eq!(c.lsn_gap(), Some(10));
        assert_eq!(c.max_page_lsn(), 100);
        assert_eq!(c.current_lsn(), 110);
        assert_eq!(c.page_count(), 2);
        assert!(
            !c.page_count_matches(),
            "the hint implies 2 - 128 + 128 pages"
        );
    }
}
