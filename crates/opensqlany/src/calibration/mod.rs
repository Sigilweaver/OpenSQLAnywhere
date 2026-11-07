//! Optional, store-local recovery for sparse or ambiguous row sectors.
//!
//! Parameters are learned from unique sector keys on other 32-page blocks.
//! A target still needs an entire row-length word of its own, and all
//! overlapping length bytes must match. Complete-page recovery is a separate
//! explicit opt-in with its own frame and held-out checks.

pub(crate) mod rotation;
mod whole_page;

use std::sync::{Arc, OnceLock};

use crate::calibration::rotation::{
    HeaderWitness, RotationModel, SectorWitness, bucket, consensus, models,
};
use crate::row::sector::{LocalEvidence, inverse_odd, sector_streams};
use crate::row::tail::{STASH_START, permutations};
use crate::{
    Page, PageStore, RowHeaderError, RowPageHeader, RowSectorReader, RowSectorRecovery,
    RowSlotRecovery, RowSlotSector, RowTail, SECTOR_SIZE,
};

pub use whole_page::{WholePageFraming, WholePageRecovery};

/// Why optional store-local recovery could not supply a sector.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CalibrationGap {
    /// No complete physical length word in the region.
    #[error("no complete local row-length word")]
    NoAnchor,
    /// A corroborated row header could not be safely read.
    #[error("integrity error while collecting calibration witnesses")]
    Integrity,
    /// No consistent parameters or an insufficiently constrained training family.
    #[error("training blocks do not identify a supported model")]
    Training,
    /// Too few independent cross-checks in the excluded blocks.
    #[error("too few held-out sector or tail witnesses")]
    InsufficientHoldout,
    /// A prediction contradicts an independently recovered key or header.
    #[error("a held-out witness disagrees with the trained model")]
    HoldoutConflict,
    /// Not every retained model predicts the same key at this position.
    #[error("calibration models disagree on the sector key")]
    Disagreement,
    /// The predicted key falls outside the page-local rotation/stream family.
    #[error("predicted key is not a supported local sector candidate")]
    OutsideLocalModel,
    /// Resolving competing plaintexts requires at least two complete local words.
    #[error("too few complete local row-length words to distinguish candidates")]
    InsufficientLocalWords,
    /// A predicted byte differs from a row-length byte in this sector.
    #[error("a local row-length byte disagrees with the prediction")]
    LocalConflict,
}

/// Lazily collect calibration witnesses from this immutable store and fit
/// each requested held-out fold at most once. Ordinary sector reads always
/// take precedence. Models and their witnesses are never shared across stores.
pub struct CalibratedStore<'a> {
    store: &'a PageStore,
    pub(crate) identity: Arc<()>,
    witnesses: OnceLock<Result<Vec<HeaderWitness>, CalibrationGap>>,
    folds: [OnceLock<Result<Fit, CalibrationGap>>; 5],
    whole_folds: [OnceLock<Result<whole_page::WholeFit, CalibrationGap>>; 5],
    whole_enabled: bool,
}

impl<'a> CalibratedStore<'a> {
    /// Bind a new calibration to this store. No pages are read yet.
    pub fn new(store: &'a PageStore) -> Self {
        Self {
            store,
            identity: Arc::new(()),
            witnesses: OnceLock::new(),
            folds: std::array::from_fn(|_| OnceLock::new()),
            whole_folds: std::array::from_fn(|_| OnceLock::new()),
            whole_enabled: false,
        }
    }

    /// The store supplying all pages and witnesses for this reader.
    pub fn store(&self) -> &'a PageStore {
        self.store
    }

    /// Permit checked complete-page evidence when a sector has no complete
    /// local length word, or competing local plaintexts remain unresolved by
    /// the ordinary calibrated key family. Ordinary reads take precedence.
    /// Consuming the reader preserves its identity and frozen calibration.
    pub fn with_whole_pages(mut self) -> Self {
        self.whole_enabled = true;
        self
    }

    /// Open a page through this store. Its ordinary header checks apply before
    /// any calibrated recovery, and each sparse sector is tried once per page reader.
    pub fn page(&self, number: u32) -> Result<CalibratedPage<'_, 'a>, RowHeaderError> {
        let page = self.store.page(u64::from(number))?;
        let header = RowPageHeader::recover(page)?;
        Ok(self.page_with_header(page, header))
    }

    /// Recover a complete page under a separately checked, store-local key
    /// equation. Every retained training model must agree. This opt-in API
    /// does not alter ordinary slot reads or establish a row's visibility.
    pub fn recover_whole_page(&self, number: u32) -> Result<WholePageRecovery, CalibrationGap> {
        let page = self
            .store
            .page(u64::from(number))
            .map_err(|_| CalibrationGap::Integrity)?;
        let header = RowPageHeader::recover(page).map_err(|_| CalibrationGap::Integrity)?;
        self.whole_page_from_header(page, &header)
    }

    pub(crate) fn whole_page_from_header(
        &self,
        page: Page<'a>,
        header: &RowPageHeader,
    ) -> Result<WholePageRecovery, CalibrationGap> {
        self.whole_page_with_framing(page, header, false)
    }

    pub(crate) fn whole_lob_page(
        &self,
        page: Page<'a>,
        header: &RowPageHeader,
    ) -> Result<WholePageRecovery, CalibrationGap> {
        self.whole_page_with_framing(page, header, true)
    }

    fn whole_page_with_framing(
        &self,
        page: Page<'a>,
        header: &RowPageHeader,
        lob: bool,
    ) -> Result<WholePageRecovery, CalibrationGap> {
        let fold = bucket(header.page_number());
        let fit = self.whole_folds[usize::from(fold)]
            .get_or_init(|| {
                let ordinary = self.fit(header.page_number())?;
                let data = self
                    .witnesses
                    .get()
                    .ok_or(CalibrationGap::Training)?
                    .as_ref()
                    .map_err(|e| *e)?;
                whole_page::WholeFit::train(data, ordinary, fold)
            })
            .as_ref()
            .map_err(|e| *e)?;
        if lob {
            fit.recover_lob(page, header)
        } else {
            fit.recover(page, header)
        }
    }

    // The caller must have recovered this header from this page in this store.
    pub(crate) fn page_with_header(
        &self,
        page: Page<'a>,
        header: RowPageHeader,
    ) -> CalibratedPage<'_, 'a> {
        CalibratedPage {
            calibration: self,
            page,
            reader: RowSectorReader::from_header(page, header),
            sectors: std::array::from_fn(|_| OnceLock::new()),
            whole: OnceLock::new(),
        }
    }

    fn fit(&self, page: u32) -> Result<&Fit, CalibrationGap> {
        let fold = bucket(page);
        self.folds[usize::from(fold)]
            .get_or_init(|| {
                let witnesses = self
                    .witnesses
                    .get_or_init(|| collect(self.store))
                    .as_ref()
                    .map_err(|e| *e)?;
                Fit::train(witnesses, fold)
            })
            .as_ref()
            .map_err(|e| *e)
    }
}

/// A physical page read through a store-bound calibration.
pub struct CalibratedPage<'store, 'page> {
    calibration: &'store CalibratedStore<'page>,
    page: Page<'page>,
    reader: RowSectorReader<'page>,
    sectors: [OnceLock<Result<AnchoredSector, CalibrationGap>>; 7],
    whole: OnceLock<Result<Arc<WholePageRecovery>, CalibrationGap>>,
}

impl<'page> CalibratedPage<'_, 'page> {
    pub(crate) fn belongs_to(&self, store: &CalibratedStore<'_>) -> bool {
        std::ptr::eq(self.calibration, store)
    }

    /// Independently recovered ordinary header.
    pub fn header(&self) -> &RowPageHeader {
        self.reader.header()
    }

    /// Resolve a nine-byte forward at this already validated source page and
    /// physical slot. Both the referring slot and terminal target are retained.
    pub fn resolve_forwarded_row(
        &self,
        slot: u16,
    ) -> Result<crate::ForwardedRow<'page>, crate::ForwardedRowError> {
        crate::row::forwarded::from_page(self.calibration, self, slot)
    }

    /// Prefer ordinary evidence. A held-out model may supply a sparse region
    /// with one local word or choose between competing local candidates with
    /// at least two. The unanimous key must belong to the same page-local
    /// family and match every complete and partial length byte. Unresolved
    /// ambiguities retain their ordinary evidence. With complete pages enabled,
    /// a separately unanimous complete-word family can resolve disagreement in
    /// the ordinary calibrated family without weakening its own page checks.
    pub fn read_slot(&self, slot: u16) -> Option<RowSlotRecovery<'page>> {
        self.reader
            .read_with(slot, |sector, local, from, to, buffer| {
                let result = self.sectors[sector - 1].get_or_init(|| self.solve(sector, local));
                match result {
                    Ok(agreed) => {
                        buffer.extend_from_slice(&agreed.bytes[from..to]);
                        Some(match &agreed.whole {
                            Some(evidence) => RowSlotSector::WholePage {
                                index: sector,
                                evidence: Arc::clone(evidence),
                            },
                            None => RowSlotSector::Calibrated {
                                index: sector,
                                words: agreed.words,
                            },
                        })
                    }
                    Err(_) if matches!(local, LocalEvidence::Ambiguous) => None,
                    Err(reason) => Some(RowSlotSector::CalibrationGap {
                        index: sector,
                        reason: *reason,
                    }),
                }
            })
    }

    // Used by the bitmap-specific reader to retain already corroborated parts
    // of a row when another part of that row is still missing.
    pub(crate) fn anchored_region(
        &self,
        sector: usize,
        local: LocalEvidence,
    ) -> Result<&[u8], CalibrationGap> {
        self.sectors[sector - 1]
            .get_or_init(|| self.solve(sector, local))
            .as_ref()
            .map(|s| s.bytes.as_ref())
            .map_err(|e| *e)
    }

    fn solve(&self, sector: usize, local: LocalEvidence) -> Result<AnchoredSector, CalibrationGap> {
        let minimum_words = match local {
            LocalEvidence::Sparse(0) if self.calibration.whole_enabled => {
                return self.whole_sector(sector);
            }
            LocalEvidence::Sparse(0) => return Err(CalibrationGap::NoAnchor),
            LocalEvidence::Sparse(_) => 1,
            LocalEvidence::Ambiguous => 2,
        };
        match self.predict_sector(sector, minimum_words) {
            Err(CalibrationGap::Disagreement)
                if self.calibration.whole_enabled && matches!(local, LocalEvidence::Ambiguous) =>
            {
                // A separately frozen complete-word family may agree where
                // the ordinary sector-key family does not. It still checks
                // every known sector and length word across the entire page;
                // this does not retry local contradictions or unsupported keys.
                self.whole_sector(sector)
            }
            result => result,
        }
    }

    fn whole_sector(&self, sector: usize) -> Result<AnchoredSector, CalibrationGap> {
        let evidence = self
            .whole
            .get_or_init(|| {
                self.calibration
                    .whole_page_from_header(self.page, self.header())
                    .map(Arc::new)
            })
            .as_ref()
            .map_err(|e| *e)?;
        let start = sector * SECTOR_SIZE;
        let end = if sector == 7 {
            STASH_START
        } else {
            start + SECTOR_SIZE
        };
        Ok(AnchoredSector {
            bytes: evidence.bytes[start..end].into(),
            words: 0,
            whole: Some(Arc::clone(evidence)),
        })
    }

    // Used only for payload bytes of the specifically framed ISYSTAB linked
    // bitmap. Zero local words require two independent bitmap literal witnesses
    // before the caller can return any bytes or map. Never cache this prediction
    // as an anchored sector for general slot reads.
    pub(crate) fn linked_bitmap_sector(
        &self,
        sector: usize,
    ) -> Result<(Vec<u8>, Option<usize>), CalibrationGap> {
        let local = if sector == 7 {
            match RowTail::recover_from_header(self.page, self.header()) {
                Ok(tail) => return Ok((tail.bytes()[..STASH_START % SECTOR_SIZE].to_vec(), None)),
                Err(crate::RowTailError::InsufficientAnchors { count, .. }) => {
                    LocalEvidence::Sparse(count)
                }
                Err(crate::RowTailError::Ambiguous { .. }) => LocalEvidence::Ambiguous,
                Err(_) => return Err(CalibrationGap::LocalConflict),
            }
        } else {
            match self.reader.recover(sector) {
                Some(RowSectorRecovery::Unique(key)) => {
                    return Ok((key.candidate_bytes().to_vec(), None));
                }
                Some(RowSectorRecovery::Equivalent { bytes, .. }) => {
                    return Ok((bytes.to_vec(), None));
                }
                Some(RowSectorRecovery::InsufficientLengths { words }) => {
                    LocalEvidence::Sparse(words)
                }
                Some(RowSectorRecovery::Ambiguous { .. }) => LocalEvidence::Ambiguous,
                _ => return Err(CalibrationGap::LocalConflict),
            }
        };
        let predicted = if matches!(local, LocalEvidence::Sparse(0)) {
            self.predict_sector(sector, 0)?
        } else {
            self.solve(sector, local)?
        };
        Ok((predicted.bytes.into_vec(), Some(predicted.words)))
    }

    fn predict_sector(
        &self,
        sector: usize,
        minimum_words: usize,
    ) -> Result<AnchoredSector, CalibrationGap> {
        let header = self.header();
        let h = header_witness(header);
        let fit = self.calibration.fit(h.page)?;
        let key = fit.key(&h, sector as u8)?;
        key.check_local_family(&h, sector as u8)?;
        let start = sector * SECTOR_SIZE;
        let end = if sector == 7 {
            STASH_START
        } else {
            start + SECTOR_SIZE
        };
        let rows = header.physical_rows().ok_or(CalibrationGap::NoAnchor)?;
        let spans = rows.iter().map(|r| (r.start(), r.length() as u16));
        anchored_bytes(
            &self.page.bytes()[start..end],
            start,
            key,
            minimum_words,
            spans,
        )
    }
}

fn header_witness(h: &RowPageHeader) -> HeaderWitness {
    HeaderWitness {
        page: h.page_number(),
        header_rotation: h.rotation() as u16,
        header_base: h.base(),
        header_increment: h.step().wrapping_mul(h.rotation() as u8),
        keys: Vec::new(),
        tail_phase: None,
    }
}

fn collect(store: &PageStore) -> Result<Vec<HeaderWitness>, CalibrationGap> {
    let mut data = Vec::new();
    for item in store.pages().skip(1) {
        let page = item.map_err(|_| CalibrationGap::Integrity)?;
        if !RowPageHeader::supports_type(page.trailer().page_type_raw()) {
            continue;
        }
        let reader = match RowSectorReader::new(page) {
            Ok(reader) => reader,
            Err(RowHeaderError::Ambiguous { .. } | RowHeaderError::NoMatch { .. }) => continue,
            Err(_) => return Err(CalibrationGap::Integrity),
        };
        let mut h = header_witness(reader.header());
        for sector in 1u8..=6 {
            if let Some(RowSectorRecovery::Unique(key)) = reader.recover(usize::from(sector)) {
                h.keys.push(SectorWitness {
                    sector,
                    rotation: key.rotation() as u16,
                    step: key.step(),
                    base: key.base(),
                });
            }
        }
        if let Ok(tail) = RowTail::recover_from_header(page, reader.header()) {
            h.tail_phase = tail.phase();
            if let Some(rotation) = tail.rotation() {
                let mut key = SectorWitness {
                    sector: 7,
                    rotation: rotation as u16,
                    step: 0,
                    base: 0,
                };
                if let Some(phase) = h.tail_phase {
                    // Independently recovered tail bytes give the additive offset
                    // at two consecutive cursor steps and therefore the increment.
                    let map = &permutations()[rotation / 2];
                    let stored = &page.bytes()[7 * SECTOR_SIZE..STASH_START];
                    let first = usize::from(map.positions[0]);
                    let second = usize::from(map.positions[first]);
                    let a = stored[first].wrapping_sub(tail.bytes()[0]);
                    let b = stored[second].wrapping_sub(tail.bytes()[first]);
                    let increment = b.wrapping_sub(a);
                    key.step = increment.wrapping_mul(inverse_odd(rotation as u8));
                    key.base = a.wrapping_sub(increment.wrapping_mul(phase.wrapping_add(1)));
                    let fitted = SectorKey {
                        rotation: key.rotation,
                        increment,
                        base: key.base,
                        phase,
                    };
                    if (0..stored.len()).any(|i| fitted.byte(stored, i) != tail.bytes()[i]) {
                        return Err(CalibrationGap::Integrity);
                    }
                }
                h.keys.push(key);
            }
        }
        data.push(h);
    }
    Ok(data)
}

struct Fit {
    rotations: Vec<RotationModel>,
    joint: Vec<(RotationModel, u8)>,
    phase: u8,
}

impl Fit {
    fn train(data: &[HeaderWitness], fold: u8) -> Result<Self, CalibrationGap> {
        let phase = consensus(
            data.iter()
                .filter(|h| bucket(h.page) != fold)
                .filter_map(|h| h.tail_phase),
        )
        .ok_or(CalibrationGap::Training)?;
        let rotations = models(data, phase, fold).map_err(|_| CalibrationGap::Training)?;
        let mut joint = Vec::new();
        for &model in &rotations {
            for selector in 0..6 {
                if data.iter().filter(|h| bucket(h.page) != fold).all(|h| {
                    h.keys
                        .iter()
                        .filter(|k| k.sector != 7)
                        .all(|k| model.stream(h, k.sector, selector) == witnessed_stream(k))
                }) {
                    joint.push((model, selector));
                }
            }
        }
        if joint.is_empty() {
            return Err(CalibrationGap::Training);
        }
        let fit = Self {
            rotations,
            joint,
            phase,
        };
        fit.validate(data, fold)?;
        Ok(fit)
    }

    fn validate(&self, data: &[HeaderWitness], fold: u8) -> Result<(), CalibrationGap> {
        let mut full_pages = 0;
        let mut tail_pages = 0;
        // Validate across whole excluded blocks. Never drop an individual
        // hypothesis to make a held-out counterexample disappear.
        for h in data.iter().filter(|h| bucket(h.page) == fold) {
            self.check_header(h)?;
            if h.tail_phase.is_some_and(|p| p != self.phase) {
                return Err(CalibrationGap::HoldoutConflict);
            }
            let mut full = false;
            for k in &h.keys {
                let rotation = self.rotation(h, k.sector);
                let stream = self.stream(h, k.sector);
                if rotation.is_some_and(|r| r != k.rotation) {
                    return Err(CalibrationGap::HoldoutConflict);
                }
                if k.sector != 7 || h.tail_phase.is_some() {
                    if stream.is_some_and(|s| s != witnessed_stream(k)) {
                        return Err(CalibrationGap::HoldoutConflict);
                    }
                    if rotation.is_some() && stream.is_some() {
                        if k.sector == 7 {
                            tail_pages += 1;
                        } else {
                            full = true;
                        }
                    }
                }
            }
            full_pages += usize::from(full);
        }
        if full_pages < 32 || tail_pages < 32 {
            return Err(CalibrationGap::InsufficientHoldout);
        }
        Ok(())
    }

    fn check_header(&self, h: &HeaderWitness) -> Result<(), CalibrationGap> {
        if self
            .rotations
            .iter()
            .all(|m| m.word(h.page) as u8 == h.low_byte(self.phase))
        {
            Ok(())
        } else {
            Err(CalibrationGap::HoldoutConflict)
        }
    }

    fn rotation(&self, h: &HeaderWitness, sector: u8) -> Option<u16> {
        consensus(self.rotations.iter().map(|m| m.rotate(h, sector, 0)))
    }

    fn stream(&self, h: &HeaderWitness, sector: u8) -> Option<(u8, u8)> {
        consensus(self.joint.iter().map(|(m, sel)| m.stream(h, sector, *sel)))
    }

    fn key(&self, h: &HeaderWitness, sector: u8) -> Result<SectorKey, CalibrationGap> {
        self.check_header(h)?;
        let rotation = self
            .rotation(h, sector)
            .ok_or(CalibrationGap::Disagreement)?;
        let (increment, base) = self.stream(h, sector).ok_or(CalibrationGap::Disagreement)?;
        Ok(SectorKey {
            rotation,
            increment,
            base,
            phase: self.phase,
        })
    }
}

fn witnessed_stream(k: &SectorWitness) -> (u8, u8) {
    ((k.rotation as u8).wrapping_mul(k.step), k.base)
}

#[derive(Clone, Copy)]
struct SectorKey {
    rotation: u16,
    increment: u8,
    base: u8,
    phase: u8,
}

impl SectorKey {
    fn check_local_family(self, h: &HeaderWitness, sector: u8) -> Result<(), CalibrationGap> {
        if !(1..=7).contains(&sector)
            || self.rotation >= SECTOR_SIZE as u16
            || self.rotation.is_multiple_of(2)
        {
            return Err(CalibrationGap::OutsideLocalModel);
        }
        let allowed = sector_streams(h.header_base, h.header_increment, sector);
        if !allowed
            .iter()
            .flatten()
            .any(|&stream| stream == (self.phase, self.increment, self.base))
        {
            return Err(CalibrationGap::OutsideLocalModel);
        }
        Ok(())
    }

    fn byte(self, stored: &[u8], i: usize) -> u8 {
        let rotation = usize::from(self.rotation);
        if stored.len() == SECTOR_SIZE {
            let at = (rotation + i) % SECTOR_SIZE;
            let step = inverse_odd(self.rotation as u8).wrapping_mul(self.increment);
            stored[at]
                .wrapping_sub(self.base)
                .wrapping_sub((at as u8).wrapping_mul(step))
        } else {
            let map = &permutations()[rotation / 2];
            let adjusted = self
                .base
                .wrapping_add(self.increment.wrapping_mul(self.phase));
            map.decode(stored, i, adjusted, self.increment)
        }
    }
}

struct AnchoredSector {
    bytes: Box<[u8]>,
    words: usize,
    whole: Option<Arc<WholePageRecovery>>,
}

fn anchored_bytes(
    stored: &[u8],
    start: usize,
    key: SectorKey,
    minimum_words: usize,
    spans: impl Iterator<Item = (usize, u16)>,
) -> Result<AnchoredSector, CalibrationGap> {
    let end = start + stored.len();
    let mut words = 0;
    for (at, length) in spans {
        if length < 2 {
            return Err(CalibrationGap::LocalConflict);
        }
        if at >= start && at + 1 < end {
            words += 1;
        }
        for (i, value) in length.to_le_bytes().into_iter().enumerate() {
            if (start..end).contains(&(at + i)) && key.byte(stored, at + i - start) != value {
                return Err(CalibrationGap::LocalConflict);
            }
        }
    }
    if words == 0 && minimum_words > 0 {
        return Err(CalibrationGap::NoAnchor);
    }
    if words < minimum_words {
        return Err(CalibrationGap::InsufficientLocalWords);
    }
    Ok(AnchoredSector {
        bytes: (0..stored.len()).map(|i| key.byte(stored, i)).collect(),
        words,
        whole: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PAGE_SIZE;

    // Invented equation and layout, independent of any store supplied by a user.
    const MODEL: RotationModel = RotationModel {
        xor_mask: 0x449a,
        addend: 0x9107,
        polarity: 1,
        carry_sign: -1,
        phase: 16,
    };

    fn fit() -> Fit {
        Fit {
            rotations: vec![MODEL],
            joint: vec![(MODEL, 2)],
            phase: MODEL.phase,
        }
    }

    fn witness(page: u32) -> HeaderWitness {
        HeaderWitness {
            page,
            header_rotation: 101,
            header_base: MODEL.word(page) as u8,
            header_increment: 61,
            keys: Vec::new(),
            tail_phase: Some(MODEL.phase),
        }
    }

    #[test]
    fn local_word_and_boundary_bytes_must_all_agree() {
        let sector = 1;
        let start = sector * SECTOR_SIZE;
        let key = SectorKey {
            rotation: 475,
            increment: 209,
            base: 13,
            phase: 0,
        };
        let mut plain = [37; SECTOR_SIZE];
        plain[0] = 2;
        plain[9..11].copy_from_slice(&500u16.to_le_bytes());
        plain[511] = 21;
        let step = (0u8..=255)
            .find(|s| s.wrapping_mul(key.rotation as u8) == key.increment)
            .unwrap();
        let mut stored = [0u8; SECTOR_SIZE];
        for (logical, &value) in plain.iter().enumerate() {
            let i = (usize::from(key.rotation) + logical) % SECTOR_SIZE;
            stored[i] = value
                .wrapping_add(key.base)
                .wrapping_add((i as u8).wrapping_mul(step));
        }
        let spans = [(start - 1, 512), (start + 9, 500), (start + 511, 21)];
        let read =
            |spans: &[(usize, u16)]| anchored_bytes(&stored, start, key, 1, spans.iter().copied());
        assert_eq!(read(&spans).unwrap().bytes.as_ref(), &plain);
        assert!(matches!(
            read(&[spans[0], spans[2]]),
            Err(CalibrationGap::NoAnchor)
        ));
        for index in 0..3 {
            let mut bad = spans;
            bad[index].1 ^= if index == 0 { 256 } else { 1 };
            assert!(matches!(read(&bad), Err(CalibrationGap::LocalConflict)));
        }
    }

    #[test]
    fn sparse_tail_checks_words_at_the_skip_permutation_and_stash_boundary() {
        let start = 7 * SECTOR_SIZE;
        for phase in [0, 16] {
            let key = SectorKey {
                rotation: 499,
                increment: 95,
                base: 249,
                phase,
            };
            let mut body: [u8; 496] = std::array::from_fn(|i| (i / 3 + 19) as u8);
            body[0] = 1; // Upper byte of a word crossing into the tail.
            body[120..122].copy_from_slice(&375u16.to_le_bytes());
            body[495] = 13; // Lower byte of a word crossing into the header stash.
            let mut raw = [0u8; 496];
            let mut pos = 0;
            for ordinal in 1..=496 {
                let mut next = (pos + usize::from(key.rotation)) % SECTOR_SIZE;
                while next >= raw.len() {
                    next = (next + usize::from(key.rotation)) % SECTOR_SIZE;
                }
                raw[next] = body[pos].wrapping_add(key.base).wrapping_add(
                    key.increment
                        .wrapping_mul((ordinal as u8).wrapping_add(phase)),
                );
                pos = next;
            }
            let spans = [(start - 1, 256), (start + 120, 375), (start + 495, 13)];
            let read = |s: &[(usize, u16)]| anchored_bytes(&raw, start, key, 1, s.iter().copied());
            assert_eq!(read(&spans).unwrap().bytes.as_ref(), &body);
            assert!(matches!(
                read(&[spans[0], spans[2]]),
                Err(CalibrationGap::NoAnchor)
            ));
            assert!(matches!(
                read(&[spans[1], (start + 495, 12)]),
                Err(CalibrationGap::LocalConflict)
            ));
        }
    }

    #[test]
    fn heldout_conflicts_never_refit_or_accept_a_different_model() {
        let model = fit();
        let mut data: Vec<_> = (1..4000)
            .filter(|&pn| bucket(pn) == 0)
            .map(|pn| {
                let mut h = witness(pn);
                for s in [1, 7] {
                    let key = model.key(&h, s).unwrap();
                    h.keys.push(SectorWitness {
                        sector: s,
                        rotation: key.rotation,
                        step: key.increment.wrapping_mul(inverse_odd(key.rotation as u8)),
                        base: key.base,
                    });
                }
                h
            })
            .collect();
        assert!(model.validate(&data, 0).is_ok());
        assert_eq!(
            model.validate(&data[..20], 0),
            Err(CalibrationGap::InsufficientHoldout)
        );
        data[0].keys[1].base ^= 1;
        assert_eq!(
            model.validate(&data, 0),
            Err(CalibrationGap::HoldoutConflict)
        );
        data[0].keys[1].base ^= 1;
        data[0].tail_phase = Some(0);
        assert_eq!(
            model.validate(&data, 0),
            Err(CalibrationGap::HoldoutConflict)
        );
        data[0].tail_phase = Some(16);
        data[0].header_base ^= 1;
        assert_eq!(
            model.validate(&data, 0),
            Err(CalibrationGap::HoldoutConflict)
        );
        let mut ambiguous = fit();
        ambiguous.rotations.push(RotationModel {
            polarity: MODEL.polarity ^ 1,
            ..MODEL
        });
        assert!(matches!(
            ambiguous.key(&data[1], 1),
            Err(CalibrationGap::Disagreement)
        ));
    }

    fn encode_sector(raw: &mut [u8], data: &[u8], rotation: u16, increment: u8, base: u8) {
        let step = (0u8..=255)
            .find(|s| s.wrapping_mul(rotation as u8) == increment)
            .unwrap();
        for (i, value) in data.iter().copied().enumerate() {
            let pos = (usize::from(rotation) + i) % SECTOR_SIZE;
            raw[pos] = value
                .wrapping_add(base)
                .wrapping_add(step.wrapping_mul(pos as u8));
        }
    }

    fn sparse_store(kind: u8, flags: u8) -> PageStore {
        let mut bytes = vec![0; 2 * PAGE_SIZE];
        let page = &mut bytes[PAGE_SIZE..];
        let h = witness(1);
        let starts = [498u16, 800, 1070, 2070, 3810];
        let mut header = [0x37; SECTOR_SIZE];
        header[..4].copy_from_slice(&1u32.to_le_bytes());
        header[16] = 4;
        header[17] = kind;
        header[24..28].copy_from_slice(&77u32.to_le_bytes());
        header[20..22].copy_from_slice(&(starts[0] - 28).to_le_bytes());
        header[22..24].copy_from_slice(&(starts.len() as u16).to_le_bytes());
        for (slot, at) in starts.iter().enumerate() {
            header[28 + 2 * slot..30 + 2 * slot].copy_from_slice(&(at - 28).to_le_bytes());
        }
        header[498..500].copy_from_slice(&(starts[1] - starts[0]).to_le_bytes());
        header[500] = flags;
        let mut sector = [91; SECTOR_SIZE];
        sector[288..290].copy_from_slice(&(starts[2] - starts[1]).to_le_bytes());
        for (data, start, rotation, increment, base) in [
            (
                &header,
                0,
                h.header_rotation,
                h.header_increment,
                h.header_base,
            ),
            {
                let k = fit().key(&h, 1).unwrap();
                (&sector, 512, k.rotation, k.increment, k.base)
            },
        ] {
            encode_sector(
                &mut page[start..start + 512],
                data,
                rotation,
                increment,
                base,
            );
        }
        page[4080] = starts.len() as u8;
        page[4082] = b'E';
        let crc = crc32fast::hash(&page[..4092]);
        page[4092..].copy_from_slice(&crc.to_le_bytes());
        PageStore::from_bytes_unchecked(bytes).unwrap()
    }

    #[test]
    fn store_bound_reader_labels_model_bytes_and_keeps_zero_word_interiors_unavailable() {
        let store = sparse_store(3, 0);
        let ordinary = RowSectorReader::new(store.page(1).unwrap()).unwrap();
        assert!(matches!(
            ordinary.read_slot(0),
            Some(RowSlotRecovery::Unavailable { .. })
        ));

        let untrained = CalibratedStore::new(&store);
        let reader = untrained.page(1).unwrap();
        let Some(RowSlotRecovery::Unavailable { sectors, .. }) = reader.read_slot(0) else {
            panic!("small store should not identify a model");
        };
        assert!(matches!(
            sectors.last(),
            Some(RowSlotSector::CalibrationGap {
                reason: CalibrationGap::Training,
                ..
            })
        ));

        let trained = CalibratedStore::new(&store);
        assert!(trained.folds[usize::from(bucket(1))].set(Ok(fit())).is_ok());
        let reader = trained.page(1).unwrap();
        let Some(RowSlotRecovery::Candidate { bytes, sectors, .. }) = reader.read_slot(0) else {
            panic!("observed word should corroborate the modeled sector");
        };
        assert_eq!(&bytes[..2], &302u16.to_le_bytes());
        assert!(bytes[14..].iter().all(|&v| v == 91));
        assert!(matches!(
            sectors.as_slice(),
            [
                RowSlotSector::Header,
                RowSlotSector::Calibrated { index: 1, words: 1 }
            ]
        ));
        let Some(RowSlotRecovery::Unavailable { sectors, .. }) = reader.read_slot(3) else {
            panic!("unanchored interior sectors must stay unavailable");
        };
        assert!(sectors.iter().any(|s| matches!(
            s,
            RowSlotSector::CalibrationGap {
                reason: CalibrationGap::NoAnchor,
                ..
            }
        )));
    }
    #[test]
    fn calibrated_catalog_slot_needs_model_bytes_and_first_pass_fields() {
        use crate::catalog::recovery::tests::sample_column;
        const SOURCE: u32 = 63;
        let (context, layout, row) = sample_column();
        // The first copy fits in sector zero. A second copy ends exactly at
        // 1024 with one whole local length word in sector one.
        let source = |sparse_row: &[u8]| {
            let mut bytes = vec![0; (SOURCE as usize + 1) * PAGE_SIZE];
            let raw = &mut bytes[SOURCE as usize * PAGE_SIZE..];
            let h = witness(SOURCE);
            let mut plain = [0x53; SECTOR_SIZE];
            let starts = [
                100,
                100 + row.len() as u16,
                1024 - sparse_row.len() as u16,
                1024,
            ];
            plain[..4].copy_from_slice(&SOURCE.to_le_bytes());
            plain[16] = 4;
            plain[17] = 3;
            plain[20..22].copy_from_slice(&(starts[0] - 28).to_le_bytes());
            plain[22..24].copy_from_slice(&(starts.len() as u16).to_le_bytes());
            plain[24..28].copy_from_slice(&2u32.to_le_bytes());
            for (slot, start) in starts.iter().enumerate() {
                plain[28 + 2 * slot..30 + 2 * slot].copy_from_slice(&(start - 28).to_le_bytes());
            }
            plain[100..100 + row.len()].copy_from_slice(&row);
            encode_sector(
                &mut raw[..512],
                &plain,
                h.header_rotation,
                h.header_increment,
                h.header_base,
            );
            let mut sector = [0x53; SECTOR_SIZE];
            sector[512 - sparse_row.len()..].copy_from_slice(sparse_row);
            let k = fit().key(&h, 1).unwrap();
            encode_sector(
                &mut raw[512..1024],
                &sector,
                k.rotation,
                k.increment,
                k.base,
            );
            raw[4080] = starts.len() as u8;
            raw[4082] = b'E';
            let crc = crc32fast::hash(&raw[..4092]);
            raw[4092..].copy_from_slice(&crc.to_le_bytes());
            PageStore::from_bytes_unchecked(bytes).unwrap()
        };
        let mut bad_field = row.clone();
        bad_field[4..8].copy_from_slice(&43u32.to_le_bytes());
        let mut bad_length = row.clone();
        bad_length[0] ^= 1;
        for (bytes, good) in [(&row, true), (&bad_field, false), (&bad_length, false)] {
            let store = source(bytes);
            let trained = CalibratedStore::new(&store);
            assert!(
                trained.folds[usize::from(bucket(SOURCE))]
                    .set(Ok(fit()))
                    .is_ok()
            );
            let page = trained.page(SOURCE).unwrap();
            assert!(matches!(
                page.read_slot(0),
                Some(RowSlotRecovery::Candidate { .. })
            ));
            assert!(
                context
                    .corroborated_calibrated_slot(&page, 0, &layout)
                    .is_none()
            );
            let recovered = context.corroborated_calibrated_slot(&page, 2, &layout);
            assert_eq!(recovered.as_deref(), good.then_some(row.as_slice()));
        }
    }

    #[test]
    fn referenced_chunk_combines_anchored_bytes_only_after_owner_and_terminal_checks() {
        use crate::{LongDescriptor, LongValueError, resolve_single_chunk};

        // The first eleven payload bytes lie in the header. The prefix crosses
        // into the modeled sector and therefore checks those bytes as well.
        let mut prefix = [0x37u8; 13];
        prefix[11..].fill(91);
        let descriptor = LongDescriptor {
            domain: 12,
            prefix: &prefix,
            tag: 0,
            total_len: 299,
            first_page: 1,
            unknown: 0,
            slot: 0,
        };
        let store = sparse_store(0x12, 0);
        assert!(matches!(
            resolve_single_chunk(&store, 77, &descriptor),
            Err(LongValueError::Unavailable)
        ));
        let calibrated = CalibratedStore::new(&store);
        assert!(
            calibrated.folds[usize::from(bucket(1))]
                .set(Ok(fit()))
                .is_ok()
        );

        let resolved = calibrated.resolve_single_chunk(77, &descriptor).unwrap();
        assert_eq!(resolved.bytes.len(), 299);
        assert_eq!(&resolved.bytes[..11], &[0x37; 11]);
        assert!(resolved.bytes[11..].iter().all(|&b| b == 91));
        assert!(matches!(
            resolved.sectors.as_slice(),
            [
                RowSlotSector::Header,
                RowSlotSector::Calibrated { index: 1, words: 1 }
            ]
        ));
        assert!(matches!(
            calibrated.resolve_single_chunk(78, &descriptor),
            Err(LongValueError::Owner { .. })
        ));
        let wrong_length = LongDescriptor {
            total_len: 298,
            ..descriptor
        };
        assert!(matches!(
            calibrated.resolve_single_chunk(77, &wrong_length),
            Err(LongValueError::Length { .. })
        ));
        let mut wrong = prefix;
        wrong[12] ^= 1;
        let wrong_prefix = LongDescriptor {
            prefix: &wrong,
            ..descriptor
        };
        assert!(matches!(
            calibrated.resolve_single_chunk(77, &wrong_prefix),
            Err(LongValueError::Prefix)
        ));
        let unsupported = LongDescriptor {
            domain: 31,
            ..descriptor
        };
        assert!(matches!(
            calibrated.resolve_single_chunk(77, &unsupported),
            Err(LongValueError::UnsupportedDomain(31))
        ));
        let interior = LongDescriptor {
            slot: 3,
            ..descriptor
        };
        assert!(matches!(
            calibrated.resolve_single_chunk(77, &interior),
            Err(LongValueError::Calibration(CalibrationGap::NoAnchor))
        ));

        let continuation = sparse_store(0x12, 4);
        let calibrated = CalibratedStore::new(&continuation);
        assert!(
            calibrated.folds[usize::from(bucket(1))]
                .set(Ok(fit()))
                .is_ok()
        );
        assert!(matches!(
            calibrated.resolve_single_chunk(77, &descriptor),
            Err(LongValueError::Continuation)
        ));

        let wrong_kind = sparse_store(3, 0);
        let calibrated = CalibratedStore::new(&wrong_kind);
        assert!(matches!(
            calibrated.resolve_single_chunk(77, &descriptor),
            Err(LongValueError::PageKind(3))
        ));
        // Kind rejection precedes model collection.
        assert!(calibrated.witnesses.get().is_none());
    }
    fn map_store(next_word: u16, chunk_flags: u8, repeated_number: bool) -> PageStore {
        let mut raw = vec![0; 5 * PAGE_SIZE];
        for (pn, owner, kind) in [(2usize, 1u32, 0x11), (4, 77, 3)] {
            let mut plain = [0x47; PAGE_SIZE];
            plain[..4].copy_from_slice(&(pn as u32).to_le_bytes());
            plain[16] = 4;
            plain[17] = kind;
            plain[24..28].copy_from_slice(&owner.to_le_bytes());
            let mut live = 0;
            if pn == 2 {
                if repeated_number {
                    plain[400..404].copy_from_slice(&(pn as u32).to_le_bytes());
                }
                // The 19-byte terminal chunk straddles two sparse sectors.
                // Its own word is in sector one. The next row's word is in
                // sector two and independently constrains the second half.
                for (at, word) in [
                    (20, 1018u16 - 28),
                    (22, 2),
                    (28, 1018 - 28),
                    (30, 1037 - 28),
                    (1018, 19),
                    (1037, next_word),
                ] {
                    plain[at..at + 2].copy_from_slice(&word.to_le_bytes());
                }
                plain[1020] = chunk_flags;
                for (word, out) in [64u32, 2, 16, 0]
                    .into_iter()
                    .zip(plain[1021..1037].chunks_exact_mut(4))
                {
                    out.copy_from_slice(&word.to_le_bytes());
                }
                live = 2;
            } else {
                plain[20..24].fill(0);
            }
            let h = witness(pn as u32);
            let page = &mut raw[pn * PAGE_SIZE..(pn + 1) * PAGE_SIZE];
            encode_sector(
                &mut page[..512],
                &plain[..512],
                h.header_rotation,
                h.header_increment,
                h.header_base,
            );
            for sector in 1..=2 {
                let k = fit().key(&h, sector).unwrap();
                let range = usize::from(sector) * 512..(usize::from(sector) + 1) * 512;
                encode_sector(
                    &mut page[range.clone()],
                    &plain[range],
                    k.rotation,
                    k.increment,
                    k.base,
                );
            }
            page[4080] = live;
            page[4082] = b'E';
            let crc = crc32fast::hash(&page[..4092]);
            page[4092..].copy_from_slice(&crc.to_le_bytes());
        }
        PageStore::from_bytes_unchecked(raw).unwrap()
    }

    #[test]
    fn linked_map_uses_the_frozen_key_only_for_witnessed_logical_bytes() {
        use crate::page_bitmap::tests::stored_page;
        use crate::{LongDescriptor, PageBitmapError, PhysicalValue};

        const HEAD: u32 = 56;
        const TAIL: u32 = 57;
        const OWNER: u32 = 87;
        let mut words = vec![384, 12];
        let mut literal = [0u32; 12];
        literal[8] = 2;
        literal[9] = 4;
        words.extend(literal);
        let bitmap: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let member_ids = [257, 290];

        let mut pointer = TAIL.to_le_bytes().to_vec();
        pointer.extend_from_slice(&0u16.to_le_bytes());
        pointer.extend_from_slice(&bitmap[..5]);
        let mut head = stored_page(HEAD, 1, 0x11, 2, 2, Some(&pointer));
        let flag_offset = 162 + 55;
        head[flag_offset] = head[flag_offset].wrapping_add(4);
        let crc = crc32fast::hash(&head[..4092]);
        head[4092..].copy_from_slice(&crc.to_le_bytes());

        // The selected terminal record spans 480..1536; sector 1 has no
        // row starts. Its logical data ends at 534, leaving a large opaque
        // suffix, including an entire sector that the map must never decode.
        let mut plain = [0x75u8; PAGE_SIZE];
        plain[..4].copy_from_slice(&TAIL.to_le_bytes());
        plain[16] = 4;
        plain[17] = 0x12;
        plain[24..28].copy_from_slice(&1u32.to_le_bytes());
        for (at, n) in [
            (20, 480 - 28u16),
            (22, 2),
            (28, 480 - 28),
            (30, 1536 - 28),
            (480, 1536 - 480),
        ] {
            plain[at..at + 2].copy_from_slice(&n.to_le_bytes());
        }
        plain[482] = 0;
        plain[483..483 + bitmap.len() - 5].copy_from_slice(&bitmap[5..]);
        let h = witness(TAIL);
        let mut tail = [0x5au8; PAGE_SIZE];
        encode_sector(
            &mut tail[..512],
            &plain[..512],
            h.header_rotation,
            h.header_increment,
            h.header_base,
        );
        let key = fit().key(&h, 1).unwrap();
        encode_sector(
            &mut tail[512..1024],
            &plain[512..1024],
            key.rotation,
            key.increment,
            key.base,
        );
        tail[4080..4092].fill(0);
        tail[4080] = 2;
        tail[4082] = b'E';
        let crc = crc32fast::hash(&tail[..4092]);
        tail[4092..].copy_from_slice(&crc.to_le_bytes());

        let field = PhysicalValue::OutOfRow(LongDescriptor {
            domain: 31,
            tag: 0x80,
            unknown: 0,
            prefix: &[],
            first_page: HEAD,
            slot: 0,
            total_len: bitmap.len() as u32,
        });
        for add_negatives in [true, false] {
            let mut bytes = vec![0; 384 * PAGE_SIZE];
            for (n, page) in [(HEAD, head), (TAIL, tail)] {
                bytes[n as usize * PAGE_SIZE..(n as usize + 1) * PAGE_SIZE].copy_from_slice(&page);
            }
            for n in 224..352 {
                let positive = member_ids.contains(&n);
                if positive || add_negatives {
                    let member = stored_page(n, if positive { OWNER } else { 91 }, 3, 2, 1, None);
                    bytes[n as usize * PAGE_SIZE..(n as usize + 1) * PAGE_SIZE]
                        .copy_from_slice(&member);
                }
            }
            let db = PageStore::from_bytes_unchecked(bytes).unwrap();
            let reader = CalibratedStore::new(&db);
            if add_negatives {
                // Bitmap membership alone cannot select the deobfuscation key.
                assert!(matches!(
                    CalibratedStore::new(&db).linked_table_page_map(&field, 2, 2, OWNER),
                    Err(PageBitmapError::Chunk(crate::LongValueError::Calibration(
                        _
                    )))
                ));
            }
            assert!(
                reader.folds[usize::from(bucket(TAIL))]
                    .set(Ok(fit()))
                    .is_ok()
            );
            let regular = reader.page(TAIL).unwrap();
            assert!(matches!(
                regular.read_slot(0),
                Some(RowSlotRecovery::Unavailable { .. })
            ));
            let result = reader.linked_table_page_map(&field, 2, 2, OWNER);
            if !add_negatives {
                assert!(matches!(result, Err(PageBitmapError::LinkedWitness)));
                continue;
            }
            let proof = result.unwrap().linked_map.unwrap();
            assert_eq!(proof.bytes, bitmap);
            let sector = &proof.chunks[1].sectors[0];
            assert_eq!(sector.sector, 1);
            assert_eq!(sector.bitmap_range, 34..56);
            assert_eq!(proof.chunks[1].opaque_surplus, 534..1536);
            assert_eq!(*proof.chunks[1].stored_page, tail);
            let [left, right] = sector.literals;
            assert_ne!(left.member_page, right.member_page);
            assert_ne!(left.alternative_page, right.alternative_page);
            assert!(
                member_ids.contains(&left.member_page) && member_ids.contains(&right.member_page)
            );
            for w in sector.literals {
                assert!(34 <= w.payload_offset && w.payload_offset + 4 <= 56);
            }
        }
    }

    #[test]
    fn sparse_search_can_abstain_on_a_repeated_column_member_that_exact_calibrated_bytes_prove() {
        use crate::catalog::recovery::tests::{sample_column, stored_catalog_page};
        use crate::{LongDescriptor, PageBitmapError, PhysicalValue};
        let (context, layout, row) = sample_column();
        let mut second = row.clone();
        second[8..12].copy_from_slice(&14u32.to_le_bytes());
        let source = 57usize;
        let target = 62usize;
        let mut bytes = vec![0; 63 * PAGE_SIZE];
        let mut plain = [0x47; PAGE_SIZE];
        plain[..4].copy_from_slice(&(source as u32).to_le_bytes());
        plain[16] = 4;
        plain[17] = 0x11;
        plain[24..28].copy_from_slice(&1u32.to_le_bytes());
        for (at, word) in [
            (20, 1009 - 28u16),
            (22, 2),
            (28, 1009 - 28),
            (30, 1024 - 28),
            (1009, 15),
        ] {
            plain[at..at + 2].copy_from_slice(&word.to_le_bytes());
        }
        plain[1011] = 0;
        let map = [64u32, 129, 1 << 30]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        plain[1012..1024].copy_from_slice(&map);
        let h = witness(source as u32);
        let raw = &mut bytes[source * PAGE_SIZE..(source + 1) * PAGE_SIZE];
        encode_sector(
            &mut raw[..512],
            &plain[..512],
            h.header_rotation,
            h.header_increment,
            h.header_base,
        );
        let key = fit().key(&h, 1).unwrap();
        encode_sector(
            &mut raw[512..1024],
            &plain[512..1024],
            key.rotation,
            key.increment,
            key.base,
        );
        raw[4080] = 2;
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        bytes[target * PAGE_SIZE..(target + 1) * PAGE_SIZE].copy_from_slice(&stored_catalog_page(
            target as u32,
            2,
            3,
            &[row, second],
            true,
            false,
        ));
        let db = PageStore::from_bytes_unchecked(bytes).unwrap();
        let cal = CalibratedStore::new(&db);
        assert!(
            cal.folds[usize::from(bucket(source as u32))]
                .set(Ok(fit()))
                .is_ok()
        );
        let val = PhysicalValue::OutOfRow(LongDescriptor {
            domain: 31,
            tag: 0,
            prefix: &map[..4],
            total_len: 12,
            first_page: source as u32,
            unknown: 0,
            slot: 0,
        });
        assert!(matches!(
            cal.table_page_map(&val, 1, 2),
            Err(PageBitmapError::NoSparseMap)
        ));
        let got = context
            .column_catalog_map(&cal, &val, 1, &[None, Some(layout)])
            .unwrap();
        assert_eq!(got.slots.repeated_pages, vec![target as u32]);
        assert_eq!(got.read.calibrated_sector_uses, 1);
        assert_eq!(got.slots.occupied.len(), 3);
    }
    #[test]
    fn positive_catalog_map_can_use_two_independently_anchored_sparse_sectors() {
        use crate::{
            LongDescriptor, LongValueError, PageBitmapError, PhysicalValue, TablePageBitmap,
        };

        let descriptor = || LongDescriptor {
            domain: 31,
            prefix: &[64, 0, 0, 0],
            tag: 0,
            total_len: 16,
            first_page: 2,
            unknown: 0,
            slot: 0,
        };
        let value = PhysicalValue::OutOfRow(descriptor());
        let store = map_store(4092 - 1037, 0, false);
        assert!(matches!(
            TablePageBitmap::from_catalog_value_for_owner(&store, &value, 1, 77),
            Err(PageBitmapError::SparseBounds)
        ));
        let calibrated = CalibratedStore::new(&store);
        assert!(
            calibrated.folds[usize::from(bucket(2))]
                .set(Ok(fit()))
                .is_ok()
        );
        let map = calibrated.table_page_map(&value, 1, 77).unwrap();
        assert_eq!(map.bitmap.pages().collect::<Vec<_>>(), [4]);
        assert_eq!(map.counts.live_slots, 0);
        assert_eq!(map.counts.occupied_slots, Some(0));
        assert_eq!(map.calibrated_sector_uses, 2);
        assert!(!map.repeated_map_header);
        let repeated = map_store(4092 - 1037, 0, true);
        let model = CalibratedStore::new(&repeated);
        assert!(model.folds[usize::from(bucket(2))].set(Ok(fit())).is_ok());
        let map = model.table_page_map(&value, 1, 77).unwrap();
        assert_eq!(map.calibrated_sector_uses, 2);
        assert!(map.repeated_map_header);
        assert_eq!(map.bitmap.pages().collect::<Vec<_>>(), [4]);
        assert!(matches!(
            calibrated.table_page_map(&value, 2, 77),
            Err(PageBitmapError::Count { .. })
        ));
        assert!(matches!(
            calibrated.table_page_map(&value, 1, 78),
            Err(PageBitmapError::Owner { .. })
        ));
        let wrong_prefix = PhysicalValue::OutOfRow(LongDescriptor {
            prefix: &[64, 1],
            ..descriptor()
        });
        assert!(matches!(
            calibrated.table_page_map(&wrong_prefix, 1, 77),
            Err(PageBitmapError::Chunk(LongValueError::Prefix))
        ));
        let wrong_len = PhysicalValue::OutOfRow(LongDescriptor {
            total_len: 15,
            ..descriptor()
        });
        assert!(matches!(
            calibrated.table_page_map(&wrong_len, 1, 77),
            Err(PageBitmapError::Chunk(LongValueError::Length { .. }))
        ));
        assert!(calibrated.table_page_map(&value, 0, 77).is_err());
        for (next, flags) in [(4091 - 1037, 0), (4092 - 1037, 4)] {
            let invalid = map_store(next, flags, false);
            let calibrated = CalibratedStore::new(&invalid);
            assert!(
                calibrated.folds[usize::from(bucket(2))]
                    .set(Ok(fit()))
                    .is_ok()
            );
            let result = calibrated.table_page_map(&value, 1, 77);
            if flags == 4 {
                assert!(matches!(
                    result,
                    Err(PageBitmapError::Chunk(LongValueError::Continuation))
                ));
            } else {
                assert!(result.is_err());
            }
        }
    }
    #[test]
    fn forwarded_source_can_cross_one_locally_corroborated_calibrated_sector() {
        let mut bytes = vec![0; 5 * PAGE_SIZE];
        let stub = [9, 0, 4, 4, 0, 0, 0, 0, 0];
        let terminal = [6, 0, 0, 0, 0xfb, 0xff];
        for (pn, kind, start, row) in [
            (2, 3, 508, stub.as_slice()),
            (4, 0x11, 160, terminal.as_slice()),
        ] {
            let mut plain = [0x37; 1024];
            plain[..4].copy_from_slice(&(pn as u32).to_le_bytes());
            plain[16] = 4;
            plain[17] = kind;
            plain[24..28].copy_from_slice(&77u32.to_le_bytes());
            let end = start + row.len();
            for (at, word) in [
                (20, start - 28),
                (22, 2),
                (28, start - 28),
                (30, end - 28),
                (end, 4092 - end),
            ] {
                plain[at..at + 2].copy_from_slice(&(word as u16).to_le_bytes());
            }
            plain[start..end].copy_from_slice(row);
            let h = witness(pn as u32);
            let raw = &mut bytes[pn * PAGE_SIZE..][..PAGE_SIZE];
            encode_sector(
                &mut raw[..512],
                &plain[..512],
                h.header_rotation,
                h.header_increment,
                h.header_base,
            );
            let k = fit().key(&h, 1).unwrap();
            encode_sector(
                &mut raw[512..1024],
                &plain[512..],
                k.rotation,
                k.increment,
                k.base,
            );
            raw[4080] = 2;
            raw[4082] = b'E';
            let crc = crc32fast::hash(&raw[..4092]);
            raw[4092..].copy_from_slice(&crc.to_le_bytes());
        }
        let store = PageStore::from_bytes_unchecked(bytes).unwrap();
        let untrained = CalibratedStore::new(&store);
        assert!(matches!(
            untrained.resolve_forwarded_row(2, 0),
            Err(crate::ForwardedRowError::Calibration {
                page: 2,
                slot: 0,
                sector: 1,
                reason: CalibrationGap::Training
            })
        ));
        let calibrated = CalibratedStore::new(&store);
        assert!(
            calibrated.folds[usize::from(bucket(2))]
                .set(Ok(fit()))
                .is_ok()
        );
        let read = calibrated
            .page(2)
            .unwrap()
            .resolve_forwarded_row(0)
            .unwrap();
        assert_eq!(read.source.bytes, stub);
        assert!(matches!(
            read.source.sectors.as_slice(),
            [
                RowSlotSector::Header,
                RowSlotSector::Calibrated { index: 1, words: 1 }
            ]
        ));
        assert_eq!(read.target.bytes, terminal);
        assert!(matches!(
            read.target.sectors.as_slice(),
            [RowSlotSector::Header]
        ));
    }
    // Produce stored positions/pads independently of the reader. Traverse the
    // tail cursor explicitly and skip all sixteen trailer positions.
    fn encoding(width: usize, key: SectorKey) -> Vec<(usize, u8)> {
        let rot = usize::from(key.rotation);
        if width == 512 {
            let step = (0u8..=255)
                .find(|s| s.wrapping_mul(rot as u8) == key.increment)
                .unwrap();
            return (0..width)
                .map(|i| {
                    let pos = (i + rot) % 512;
                    (pos, key.base.wrapping_add(step.wrapping_mul(pos as u8)))
                })
                .collect();
        }
        let mut map = vec![(0, 0); width];
        let mut cursor = 0;
        for j in 1..=width {
            let mut next = (cursor + rot) % 512;
            while next >= width {
                next = (next + rot) % 512;
            }
            map[cursor] = (
                next,
                key.base.wrapping_add(
                    key.increment
                        .wrapping_mul((j as u8).wrapping_add(key.phase)),
                ),
            );
            cursor = next;
        }
        assert_eq!(cursor, 0);
        map
    }

    fn competing_store(
        sector: usize,
        damaged_at: Option<usize>,
        bad_stash: bool,
    ) -> (PageStore, Vec<u8>) {
        use std::collections::BTreeSet;

        let mut bytes = vec![0; 2 * PAGE_SIZE];
        let raw = &mut bytes[PAGE_SIZE..];
        let h = witness(1);
        let key = fit().key(&h, sector as u8).unwrap();
        let width = if sector == 7 { 496 } else { 512 };
        let start = sector * 512;
        let offsets = [20, 68, width - 1];
        let mut logical: Vec<_> = (0..width)
            .map(|i| ((i * i + 7 * i + 9) / 11) as u8)
            .collect();
        let mut header = [0x37; 512];
        header[..4].copy_from_slice(&1u32.to_le_bytes());
        header[16] = 4;
        header[17] = 3;
        header[18] = u8::from(bad_stash);
        header[20..22].copy_from_slice(&((start + offsets[0] - 28) as u16).to_le_bytes());
        header[22..24].copy_from_slice(&(offsets.len() as u16).to_le_bytes());
        let mut constraints = Vec::new();
        for (i, &offset) in offsets.iter().enumerate() {
            let at = start + offset;
            header[28 + 2 * i..30 + 2 * i].copy_from_slice(&((at - 28) as u16).to_le_bytes());
            let next = offsets.get(i + 1).map_or(4092, |n| start + n);
            for (j, value) in ((next - at) as u16).to_le_bytes().into_iter().enumerate() {
                if offset + j < width {
                    constraints.push((offset + j, value));
                    logical[offset + j] = value;
                }
            }
        }
        encode_sector(
            &mut raw[..512],
            &header,
            h.header_rotation,
            h.header_increment,
            h.header_base,
        );
        let stored = &mut raw[start..start + width];
        let actual = encoding(width, key);
        for (i, &(pos, pad)) in actual.iter().enumerate() {
            stored[pos] = logical[i].wrapping_add(pad);
        }
        // Plant two rival keys at disjoint stored positions. The physical
        // words used by the real key and its entire first row stay intact.
        let mut reserved: BTreeSet<_> = (20..68)
            .map(|i| actual[i].0)
            .chain(constraints.iter().map(|&(i, _)| actual[i].0))
            .collect();
        let mut rivals = 0;
        for r in (1u16..512).step_by(2) {
            if r == key.rotation {
                continue;
            }
            let other = encoding(width, SectorKey { rotation: r, ..key });
            if constraints
                .iter()
                .any(|&(i, _)| reserved.contains(&other[i].0))
            {
                continue;
            }
            for &(i, value) in &constraints {
                let (pos, pad) = other[i];
                stored[pos] = value.wrapping_add(pad);
                reserved.insert(pos);
            }
            rivals += 1;
            if rivals == 2 {
                break;
            }
        }
        assert_eq!(rivals, 2);
        if let Some(i) = damaged_at {
            stored[actual[i].0] ^= 1;
        }
        raw[4080] = 3;
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        (
            PageStore::from_bytes_unchecked(bytes).unwrap(),
            logical[20..68].to_vec(),
        )
    }

    fn is_local_ambiguity(slot: Option<RowSlotRecovery<'_>>, sector: usize) -> bool {
        let Some(RowSlotRecovery::Unavailable { sectors, .. }) = slot else {
            return false;
        };
        match sectors.as_slice() {
            [
                RowSlotSector::Full {
                    index,
                    recovery: RowSectorRecovery::Ambiguous { words: 2, .. },
                },
            ] => *index == sector,
            [RowSlotSector::TailGap(crate::RowTailError::Ambiguous { .. })] => sector == 7,
            _ => false,
        }
    }

    #[test]
    fn heldout_key_distinguishes_competing_full_and_tail_plaintexts() {
        for sector in [1, 7] {
            let (store, expected) = competing_store(sector, None, false);
            let ordinary = RowSectorReader::new(store.page(1).unwrap()).unwrap();
            assert!(is_local_ambiguity(ordinary.read_slot(0), sector));
            let calibrated = CalibratedStore::new(&store);
            assert!(is_local_ambiguity(
                calibrated.page(1).unwrap().read_slot(0),
                sector
            ));
            let calibrated = CalibratedStore::new(&store);
            assert!(
                calibrated.folds[usize::from(bucket(1))]
                    .set(Ok(fit()))
                    .is_ok()
            );
            let Some(RowSlotRecovery::Candidate { bytes, sectors, .. }) =
                calibrated.page(1).unwrap().read_slot(0)
            else {
                panic!("expected unanimous key and all local anchors");
            };
            assert_eq!(bytes, expected);
            assert!(
                matches!(sectors.as_slice(), [RowSlotSector::Calibrated { index, words: 2 }] if *index == sector)
            );
            // A dissenting retained training model cannot be dropped in favor
            // of the model that would recover the desired row.
            let mut disagree = fit();
            disagree.rotations.push(RotationModel {
                polarity: MODEL.polarity ^ 1,
                ..MODEL
            });
            let calibrated = CalibratedStore::new(&store);
            assert!(
                calibrated.folds[usize::from(bucket(1))]
                    .set(Ok(disagree))
                    .is_ok()
            );
            assert!(is_local_ambiguity(
                calibrated.page(1).unwrap().read_slot(0),
                sector
            ));
        }
    }

    #[test]
    fn wrong_predicted_length_or_boundary_byte_preserves_ordinary_ambiguity() {
        for (sector, width) in [(1, 512), (7, 496)] {
            for offset in [20, width - 1] {
                let (store, _) = competing_store(sector, Some(offset), false);
                let calibrated = CalibratedStore::new(&store);
                assert!(
                    calibrated.folds[usize::from(bucket(1))]
                        .set(Ok(fit()))
                        .is_ok()
                );
                assert!(is_local_ambiguity(
                    calibrated.page(1).unwrap().read_slot(0),
                    sector
                ));
            }
        }
        // The second byte of the split tail word resides in the header stash.
        // A mismatch there is an ordinary NoMatch, never a calibrated retry.
        let (store, _) = competing_store(7, None, true);
        let calibrated = CalibratedStore::new(&store);
        let Some(RowSlotRecovery::Unavailable { sectors, .. }) =
            calibrated.page(1).unwrap().read_slot(0)
        else {
            panic!("bad stash");
        };
        assert!(matches!(
            sectors.as_slice(),
            [RowSlotSector::TailGap(crate::RowTailError::NoMatch { .. })]
        ));
        assert!(calibrated.folds[usize::from(bucket(1))].get().is_none());
    }

    #[test]
    fn a_key_outside_the_local_phase_rotation_or_stream_family_cannot_be_selected() {
        let mut h = witness(1);
        h.header_base = 255;
        // This header permits the phase-16 counter carry for a final sector.
        let key = SectorKey {
            rotation: 73,
            phase: 16,
            increment: h.header_increment.wrapping_sub(2),
            base: 6,
        };
        assert!(key.check_local_family(&h, 7).is_ok());
        for wrong in [
            SectorKey {
                rotation: 72,
                ..key
            },
            SectorKey {
                rotation: 513,
                ..key
            },
            SectorKey { phase: 0, ..key },
            SectorKey { base: 7, ..key },
            SectorKey {
                increment: h.header_increment.wrapping_add(4),
                ..key
            },
        ] {
            assert_eq!(
                wrong.check_local_family(&h, 7),
                Err(CalibrationGap::OutsideLocalModel)
            );
        }
        let mut raw = [0; 512];
        let local = 20;
        let map = encoding(512, key);
        for (i, v) in 30u16.to_le_bytes().into_iter().enumerate() {
            let (pos, pad) = map[local + i];
            raw[pos] = v.wrapping_add(pad);
        }
        assert!(matches!(
            anchored_bytes(&raw, 512, key, 2, [(512 + local, 30)].into_iter()),
            Err(CalibrationGap::InsufficientLocalWords)
        ));
    }
    #[test]
    fn no_match_and_unmodeled_full_sectors_never_request_calibration() {
        let (base, _) = competing_store(1, None, false);
        let raw_page = base.page(1).unwrap();
        let header = RowPageHeader::recover(raw_page).unwrap();
        let spans = header.physical_rows().unwrap();
        let mut plain: [u8; 512] = std::array::from_fn(|i| ((13 * i * i + 3 * i + 8) / 19) as u8);
        for row in spans {
            for (j, byte) in (row.length() as u16).to_le_bytes().into_iter().enumerate() {
                if (512..1024).contains(&(row.start() + j)) {
                    plain[row.start() + j - 512] = byte;
                }
            }
        }
        let nominal = header.base().wrapping_add(1);
        for candidate_base in [nominal, nominal.wrapping_add(29)] {
            let mut store_bytes = vec![0; 2 * PAGE_SIZE];
            let page = &mut store_bytes[PAGE_SIZE..];
            page.copy_from_slice(raw_page.bytes());
            encode_sector(&mut page[512..1024], &plain, 71, 113, candidate_base);
            let crc = crc32fast::hash(&page[..4092]);
            page[4092..].copy_from_slice(&crc.to_le_bytes());
            let store = PageStore::from_bytes_unchecked(store_bytes).unwrap();
            let calibrated = CalibratedStore::new(&store);
            let Some(RowSlotRecovery::Unavailable { sectors, .. }) =
                calibrated.page(1).unwrap().read_slot(0)
            else {
                panic!("unmodeled keys cannot supply rows");
            };
            match sectors.as_slice() {
                [
                    RowSlotSector::Full {
                        recovery: RowSectorRecovery::Unmodeled { .. },
                        ..
                    },
                ] => assert_eq!(candidate_base, nominal),
                [
                    RowSlotSector::Full {
                        recovery: RowSectorRecovery::NoMatch { .. },
                        ..
                    },
                ] => assert_ne!(candidate_base, nominal),
                _ => panic!("unexpected evidence"),
            }
            assert!(calibrated.folds[usize::from(bucket(1))].get().is_none());
        }
    }
    #[test]
    fn text_peer_crossing_sparse_sectors_must_be_fully_corroborated() {
        use crate::{LongDescriptor, LongValueError, resolve_single_chunk};

        let mut bytes = vec![0; 2 * PAGE_SIZE];
        let raw = &mut bytes[PAGE_SIZE..];
        let mut plain = [0x79; 1536];
        plain[..4].copy_from_slice(&1u32.to_le_bytes());
        plain[16] = 4;
        plain[17] = 0x12;
        plain[24..28].copy_from_slice(&111u32.to_le_bytes());
        let starts = [160, 169, 1019, 1028];
        for (at, val) in [(20, starts[0] - 28), (22, starts.len())] {
            plain[at..at + 2].copy_from_slice(&(val as u16).to_le_bytes());
        }
        for (slot, &at) in starts.iter().enumerate() {
            let next = starts.get(slot + 1).copied().unwrap_or(4092);
            plain[28 + 2 * slot..30 + 2 * slot].copy_from_slice(&((at - 28) as u16).to_le_bytes());
            plain[at..at + 2].copy_from_slice(&((next - at) as u16).to_le_bytes());
        }
        plain[162] = 0;
        plain[163..169].copy_from_slice(b"ABCDxy");
        plain[1021] = 0;
        plain[1022..1028].copy_from_slice(b"ABCXxy");
        let h = witness(1);
        encode_sector(
            &mut raw[..512],
            &plain[..512],
            h.header_rotation,
            h.header_increment,
            h.header_base,
        );
        for sector in [1, 2] {
            let key = fit().key(&h, sector as u8).unwrap();
            let range = sector * 512..(sector + 1) * 512;
            encode_sector(
                &mut raw[range.clone()],
                &plain[range],
                key.rotation,
                key.increment,
                key.base,
            );
        }
        raw[4080] = starts.len() as u8;
        raw[4082] = b'E';
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        let store = PageStore::from_bytes_unchecked(bytes).unwrap();
        let d = LongDescriptor {
            domain: 10,
            tag: 0,
            prefix: b"ABCD",
            total_len: 6,
            first_page: 1,
            unknown: 0,
            slot: 0,
        };
        assert!(matches!(
            resolve_single_chunk(&store, 111, &d),
            Err(LongValueError::IndeterminateTextPeer(2))
        ));
        assert!(matches!(
            CalibratedStore::new(&store).resolve_single_chunk(111, &d),
            Err(LongValueError::IndeterminateTextPeer(2))
        ));
        let calibrated = CalibratedStore::new(&store);
        assert!(
            calibrated.folds[usize::from(bucket(1))]
                .set(Ok(fit()))
                .is_ok()
        );
        let result = calibrated.resolve_single_chunk(111, &d).unwrap();
        assert_eq!(result.bytes, b"ABCDxy");
        assert!(matches!(result.sectors.as_slice(), [RowSlotSector::Header]));
        assert_eq!(result.text_peers.len(), 1);
        let peer = &result.text_peers[0];
        assert_eq!(peer.slot, 2);
        assert!(!peer.identical_payload);
        assert!(matches!(
            peer.sectors.as_slice(),
            [
                RowSlotSector::Calibrated { index: 1, words: 1 },
                RowSlotSector::Calibrated { index: 2, words: 1 }
            ]
        ));
    }
}
