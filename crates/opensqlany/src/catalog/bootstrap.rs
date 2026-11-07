//! The SA17 ISYSTAB data-page bitmap has a reserved bootstrap stream when its
//! own catalog field is NULL. This reader accepts only the observed, terminal
//! H-page-10 form whose entire stream fits in the independently recovered first
//! sector. It does not infer membership by scanning owner IDs or fitting counts.
//!
//! Catalog growth, drop and reuse controls check the selected page sets.
//! Row ownership, directory completeness and record visibility remain separate.

use crate::{Error, Page, PageBitmapError, PageStore, TablePageBitmap, TablePageCounts};

/// Failure to recover the supported SA17 self-catalog bootstrap stream.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogBootstrapError {
    /// Reading or checking the stored page failed.
    #[error(transparent)]
    Integrity(#[from] Error),
    /// The physical page type, terminal framing or stream bounds are unsupported.
    #[error("unsupported self-catalog bootstrap framing")]
    UnsupportedFraming,
    /// No structural header matches reserved page 10 and the stream kind.
    #[error("self-catalog bootstrap header is unavailable")]
    NoHeader,
    /// Multiple structural headers match, before interpreting any bitmap.
    #[error("self-catalog bootstrap header is ambiguous")]
    AmbiguousHeader,
    /// The complete serialized bitmap, bounds or declared page count failed.
    #[error(transparent)]
    Bitmap(#[from] PageBitmapError),
}

/// Reserved ISYSTAB data-page membership and the bytes supporting it.
///
/// Obtaining this bitmap does not establish current SQL row visibility. Callers
/// must still check every selected page's owner, directory and complete records.
#[derive(Debug)]
pub struct SelfCatalogBootstrap {
    /// Complete membership decoded from the terminal reserved stream.
    pub bitmap: TablePageBitmap,
    stored_page: Box<[u8; 4096]>,
    sector0: Box<[u8; 512]>,
    rotation: usize,
    base: u8,
    step: u8,
    end: usize,
}

impl SelfCatalogBootstrap {
    /// Read the supported terminal reserved page, checking its CRC, trailer,
    /// unique structural header, complete RLE stream and declared cardinality.
    /// No chained, cross-sector, empty or other-version form is guessed.
    ///
    /// # Errors
    ///
    /// * [`CatalogBootstrapError::Integrity`] when the stored page fails its
    ///   CRC or trailer check, or cannot be read.
    /// * [`CatalogBootstrapError::UnsupportedFraming`] for other stream forms.
    /// * [`CatalogBootstrapError::NoHeader`] or
    ///   [`CatalogBootstrapError::AmbiguousHeader`] when no unique header exists.
    /// * [`CatalogBootstrapError::Bitmap`] when the RLE stream, member bounds
    ///   or declared cardinality do not agree.
    pub fn read(store: &PageStore, declared_pages: u32) -> Result<Self, CatalogBootstrapError> {
        if store.superblock()?.format() != crate::FormatVersion::SA17 {
            return Err(CatalogBootstrapError::UnsupportedFraming);
        }
        Self::from_page(store.page(10)?, store.page_count(), declared_pages)
    }

    fn from_page(
        page: Page<'_>,
        physical_pages: u64,
        declared_pages: u32,
    ) -> Result<Self, CatalogBootstrapError> {
        if page.index() != 10 || !page.trailer().page_type_raw().eq_ignore_ascii_case(&b'H') {
            return Err(CatalogBootstrapError::UnsupportedFraming);
        }
        page.verify_crc()?;
        page.verify_trailer()?;
        // Obfuscation stashes the original header word in the physical trailer,
        // as for the directory-prefix count on row pages. The logical header's
        // bytes 18..20 instead hold displaced tail bytes, not the stream end.
        let end = usize::from(u16::from_le_bytes(
            page.bytes()[4080..4082].try_into().unwrap(),
        ));
        if !(28..=512).contains(&end) || !end.is_multiple_of(4) || declared_pages == 0 {
            return Err(CatalogBootstrapError::UnsupportedFraming);
        }
        let raw = &page.bytes()[..512];
        let mut candidates = (1..512).step_by(2).filter_map(|rotation| {
            let step = raw[(rotation + 1) % 512]
                .wrapping_sub(raw[rotation])
                .wrapping_add(10);
            let base = raw[rotation]
                .wrapping_sub(10)
                .wrapping_sub((rotation as u8).wrapping_mul(step));
            let decode = |logical: usize| {
                let i = (rotation + logical) % 512;
                raw[i]
                    .wrapping_sub(base)
                    .wrapping_sub((i as u8).wrapping_mul(step))
            };
            if [decode(0), decode(1), decode(2), decode(3)] != 10u32.to_le_bytes()
                || [decode(16), decode(17)] != [20, 0]
            {
                return None;
            }
            Some((Box::new(std::array::from_fn(decode)), rotation, base, step))
        });
        let (sector0, rotation, base, step) =
            candidates.next().ok_or(CatalogBootstrapError::NoHeader)?;
        // Exhaust structural alternatives before the terminal pointer, payload
        // grammar or external count can prefer a candidate.
        if candidates.next().is_some() {
            return Err(CatalogBootstrapError::AmbiguousHeader);
        }
        if sector0[20..24] != [0; 4] {
            return Err(CatalogBootstrapError::UnsupportedFraming);
        }
        let bitmap = TablePageBitmap::decode(&sector0[24..end], physical_pages, declared_pages)?;
        Ok(Self {
            bitmap,
            stored_page: Box::new(page.bytes().try_into().expect("checked page length")),
            sector0,
            rotation,
            base,
            step,
            end,
        })
    }

    /// Logical first sector, including the still displaced tail bytes in its header.
    pub fn sector0(&self) -> &[u8; 512] {
        &self.sector0
    }

    /// Complete serialized stream bytes; no allocation padding is included.
    pub fn serialized(&self) -> &[u8] {
        &self.sector0[24..self.end]
    }

    /// Original encoded page, including its independent trailer and CRC.
    pub fn stored_page(&self) -> &[u8; 4096] {
        &self.stored_page
    }

    /// Exclusive logical stream end, from the stored trailer's first word.
    pub fn stream_end(&self) -> usize {
        self.end
    }

    /// Unique first-sector odd rotation and additive base/step, respectively.
    pub fn header_key(&self) -> (usize, u8, u8) {
        (self.rotation, self.base, self.step)
    }

    /// Check every selected data page independently of the bootstrap header.
    /// Complete, prefix-consistent directories and allocated owner-1 row kinds
    /// are required; retired kind-zero pages are rejected even if readable.
    pub fn verify_members(&self, store: &PageStore) -> Result<TablePageCounts, PageBitmapError> {
        let mut counts = TablePageCounts {
            live_slots: 0,
            occupied_slots: Some(0),
        };
        for page in self.bitmap.pages() {
            let header = crate::page_bitmap::member_header(store, page, 1)?;
            if header.page_kind() == 0 || header.directory_prefix_matches() != Some(true) {
                return Err(PageBitmapError::LinkedMemberCounts);
            }
            let slots = header
                .complete_slot_starts()
                .ok_or(PageBitmapError::LinkedMemberCounts)?;
            counts.live_slots += u64::from(header.directory_prefix_count());
            *counts.occupied_slots.as_mut().unwrap() += slots.iter().flatten().count() as u64;
        }
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(mutate: impl FnOnce(&mut [u8; 512]), end: u16) -> [u8; 4096] {
        let mut logical = [0; 512];
        logical[..4].copy_from_slice(&10u32.to_le_bytes());
        logical[16] = 20;
        // Universe 64: literal pages 2 and 4, then one all-zero word.
        for (i, word) in [64u32, 1, 20, 128].iter().enumerate() {
            logical[24 + i * 4..28 + i * 4].copy_from_slice(&word.to_le_bytes());
        }
        mutate(&mut logical);
        let mut raw = [0; 4096];
        for (i, &byte) in logical.iter().enumerate() {
            let stored = (3 + i) % 512;
            raw[stored] = byte
                .wrapping_add(42)
                .wrapping_add((stored as u8).wrapping_mul(7));
        }
        raw[4080..4082].copy_from_slice(&end.to_le_bytes());
        raw[4082] = b'H';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    fn read(raw: &[u8; 4096], count: u32) -> Result<SelfCatalogBootstrap, CatalogBootstrapError> {
        SelfCatalogBootstrap::from_page(Page::from_bytes(10, raw).unwrap(), 64, count)
    }

    #[test]
    fn reserved_stream_uses_the_retained_trailer_end_and_exact_bitmap() {
        let raw = page(|p| p[18..20].copy_from_slice(&[255, 255]), 40);
        let result = read(&raw, 2).unwrap();
        assert_eq!(result.bitmap.pages().collect::<Vec<_>>(), [2, 4]);
        assert_eq!(result.stream_end(), 40);
        assert_eq!(result.header_key(), (3, 42, 7));
        assert_eq!(result.serialized().len(), 16);
        assert!(matches!(
            read(&raw, 3),
            Err(CatalogBootstrapError::Bitmap(PageBitmapError::Count { .. }))
        ));
    }

    #[test]
    fn reserved_stream_rejects_unsupported_bounds_and_continuations() {
        for end in [0, 24, 30, 516, 4092] {
            assert!(matches!(
                read(&page(|_| {}, end), 2),
                Err(CatalogBootstrapError::UnsupportedFraming)
            ));
        }
        assert!(matches!(
            read(&page(|p| p[20] = 11, 40), 2),
            Err(CatalogBootstrapError::UnsupportedFraming)
        ));
        assert!(matches!(
            read(&page(|_| {}, 40), 0),
            Err(CatalogBootstrapError::UnsupportedFraming)
        ));
    }

    #[test]
    fn reserved_stream_never_uses_the_bitmap_to_break_a_header_tie() {
        let raw = page(
            |p| {
                p[256..260].copy_from_slice(&10u32.to_le_bytes());
                p[272] = 20;
                // The alternative's stream bytes are invalid; it must still reject.
            },
            40,
        );
        assert!(matches!(
            read(&raw, 2),
            Err(CatalogBootstrapError::AmbiguousHeader)
        ));
    }

    #[test]
    fn reserved_stream_rejects_corruption_wrong_kind_and_outside_members() {
        let mut raw = page(|_| {}, 40);
        raw[100] ^= 1;
        assert!(matches!(
            read(&raw, 2),
            Err(CatalogBootstrapError::Integrity(Error::BadCrc { .. }))
        ));
        assert!(matches!(
            read(&page(|p| p[16] = 19, 40), 2),
            Err(CatalogBootstrapError::NoHeader)
        ));
        assert!(matches!(
            read(
                &page(|p| p[32..36].copy_from_slice(&1u32.to_le_bytes()), 40),
                1
            ),
            Err(CatalogBootstrapError::Bitmap(
                PageBitmapError::OutOfStore { .. }
            ))
        ));
    }
}
