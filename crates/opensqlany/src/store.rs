use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Error, Result};
use crate::page::{PAGE_SIZE, Page};
use crate::superblock::Superblock;

/// An SA17 page-store opened from disk.
///
/// The whole file is read into memory on [`PageStore::open`]. This is
/// appropriate for the file sizes the format typically produces
/// (13-45 MiB in the QBW corpus) and keeps the API zero-copy at the
/// per-page level.
#[derive(Debug)]
pub struct PageStore {
    bytes: Vec<u8>,
}

impl PageStore {
    /// Open a page store by path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut f = File::open(path)?;
        let size = f.seek(SeekFrom::End(0))?;
        f.seek(SeekFrom::Start(0))?;

        if size < PAGE_SIZE as u64 {
            return Err(Error::TooSmall { size });
        }
        if !size.is_multiple_of(PAGE_SIZE as u64) {
            return Err(Error::NotPageAligned {
                size,
                page_size: PAGE_SIZE,
            });
        }

        let mut bytes = Vec::with_capacity(size as usize);
        f.read_to_end(&mut bytes)?;
        Ok(PageStore { bytes })
    }

    /// Wrap an already-materialised byte buffer as a page store.
    ///
    /// The buffer length must be a positive multiple of [`PAGE_SIZE`].
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let size = bytes.len() as u64;
        if size < PAGE_SIZE as u64 {
            return Err(Error::TooSmall { size });
        }
        if !size.is_multiple_of(PAGE_SIZE as u64) {
            return Err(Error::NotPageAligned {
                size,
                page_size: PAGE_SIZE,
            });
        }
        Ok(PageStore { bytes })
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

    /// Borrow a single page by zero-based index.
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

    /// Iterate over every page in order, starting at page 0.
    pub fn pages(&self) -> Pages<'_> {
        Pages {
            store: self,
            next: 0,
        }
    }

    /// Parse and return the page-0 superblock. This also verifies the
    /// superblock magic; use [`PageStore::try_superblock`] for a
    /// non-failing variant.
    pub fn superblock(&self) -> Result<Superblock> {
        let sb = self.try_superblock()?;
        if !sb.magic_ok() {
            return Err(Error::BadMagic {
                got: sb.magic,
                want: crate::superblock::SA_MAGIC,
            });
        }
        Ok(sb)
    }

    /// Parse the page-0 superblock without validating the magic. Useful
    /// when inspecting files that might not be SA17.
    pub fn try_superblock(&self) -> Result<Superblock> {
        let page0 = self.page(0)?;
        Ok(Superblock::parse(page0.bytes()))
    }
}

/// Iterator returned by [`PageStore::pages`].
#[derive(Debug)]
pub struct Pages<'a> {
    store: &'a PageStore,
    next: u64,
}

impl<'a> Iterator for Pages<'a> {
    type Item = Page<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.store.page_count() {
            return None;
        }
        let page = self.store.page(self.next).ok()?;
        self.next += 1;
        Some(page)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.store.page_count() - self.next) as usize;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for Pages<'a> {}
