//! Arithmetic-progression (AP) fill deobfuscation for SA17 page-store files.
//!
//! SAP SQL Anywhere 17 applies a per-sector additive stream cipher to every
//! page body. The fill formula observed across the entire QBW corpus is:
//!
//! ```text
//! stored[i] = (fill(pn, si, i) + plaintext[i]) mod 256
//! fill(pn, si, i) = (base(pn, si) + i * step(pn, si)) mod 256
//! base(pn, si)    = (bv(pn / 16) + pn + si - 4 * ((pn % 16) / 2)) mod 256
//! ```
//!
//! where:
//! - `pn` - zero-based page number
//! - `si` - sector index within the page (0..8, each sector = 512 bytes)
//! - `i` - byte index within the sector
//! - `bv(bi)` - a calibration byte, learned from the file
//!
//! `step` varies per sector and is recovered empirically by finding the
//! candidate step value that produces the highest histogram peak in the
//! deobfuscated plaintext (i.e., the step that makes the most bytes equal
//! to some repeated value, exploiting the fact that SA stores many zero bytes
//! in padding and unused column areas).
//!
//! `bv` is learned from pages whose plaintext is almost entirely zero - the
//! "pure AP" page types: `'@'` (0x40), `'C'` (0x43), `'H'` (0x48), and
//! `'M'` (0x4D). For these pages the stored bytes are virtually equal to the
//! fill, so `bv` can be back-calculated directly.
//!
//! On the original corpus `bv` is constant per 16-page block, but that does
//! not hold on every file - some QuickBooks Enterprise 24.0 files show
//! several distinct `bv` values inside a single block (`opensqlany` issue
//! #8). [`ApModel::deobfuscate`] therefore resolves `bv` per page.
//!
//! # References
//!
//! See `NOTES.md §C.14` and `§C.19` for the empirical derivation.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::options::ReadOptions;
use crate::page::{PAGE_SIZE, Page};
use crate::store::PageStore;
use crate::warning::Warning;

/// Size of a single AP sector in bytes.
pub const SECTOR_SIZE: usize = 512;
/// Number of sectors per page (8 × 512 = 4096 bytes).
pub const SECTORS_PER_PAGE: usize = PAGE_SIZE / SECTOR_SIZE;
/// Byte offset at which the page trailer begins.
const TRAILER_START: usize = 0xFF0;

/// Minimum AP-purity fraction required to trust a sector when learning `bv`.
/// A sector is "pure" if at least this fraction of bytes match the predicted
/// AP fill. Python's `_sector_fit` requires a perfect 100% match; we use the
/// same threshold to avoid accepting noisy partial matches as calibration data.
const LEARN_PURITY: f64 = 1.0;

/// Page types whose bodies are dominated by AP fill (sectors 1..6 are
/// essentially zero plaintext). We learn `bv` only from these pages.
const PURE_AP_TYPES: [u8; 4] = [0x40, 0x43, 0x48, 0x4D]; // '@', 'C', 'H', 'M'

// ---------------------------------------------------------------------------
// Low-level AP arithmetic
// ---------------------------------------------------------------------------

/// Compute `base(pn, si, bv)`.
///
/// ```text
/// base = (bv + pn + si − 4 × floor((pn % 16) / 2)) mod 256
/// ```
#[inline]
fn ap_base(pn: u64, si: usize, bv: u8) -> u8 {
    let p16 = (pn % 16) as u8;
    let offset = p16 / 2 * 4; // 4 * floor(p16/2), saturates at 28
    bv.wrapping_add(pn as u8)
        .wrapping_add(si as u8)
        .wrapping_sub(offset)
}

/// Find the dominant adjacent-byte difference in `sec`.
///
/// This is the most likely `step` when the sector is a pure AP sequence.
fn dominant_step(sec: &[u8]) -> u8 {
    let mut hist = [0u32; 256];
    for w in sec.windows(2) {
        let diff = w[1].wrapping_sub(w[0]);
        hist[diff as usize] += 1;
    }
    hist.iter()
        .enumerate()
        .max_by_key(|&(_, &v)| v)
        .map(|(i, _)| i as u8)
        .unwrap_or(0)
}

/// Find the `base` that maximises hits of `(base + i * step) mod 256 == sec[i]`.
///
/// For each index `i`, the base that would produce a hit is
/// `(sec[i] − i * step) mod 256`.  The mode of that distribution is the
/// best `base`.
fn recover_base(sec: &[u8], step: u8) -> u8 {
    let mut hist = [0u32; 256];
    for (i, &b) in sec.iter().enumerate() {
        let candidate = b.wrapping_sub((i as u8).wrapping_mul(step));
        hist[candidate as usize] += 1;
    }
    hist.iter()
        .enumerate()
        .max_by_key(|&(_, &v)| v)
        .map(|(i, _)| i as u8)
        .unwrap_or(0)
}

/// Verify that the AP prediction `(base + i * step) mod 256` matches `sec[i]`
/// for at least `min_fraction` of bytes.
fn sector_purity(sec: &[u8], base: u8, step: u8) -> f64 {
    let hits = sec
        .iter()
        .enumerate()
        .filter(|&(i, &b)| b == base.wrapping_add((i as u8).wrapping_mul(step)))
        .count();
    hits as f64 / sec.len() as f64
}

/// Find the `step` that maximises the peak of the plaintext histogram.
///
/// For each candidate step `s`, compute `plain[i] = (sec[i] - base - i*s) mod 256`
/// and find the frequency of the most common byte.  The step with the highest
/// peak is returned; ties keep the lowest step.
///
/// Returns `(best_step, peak_count, runner_up_peak)`, where the runner-up is
/// the best peak among all other steps.
fn recover_step_peak(sec: &[u8], base: u8) -> (u8, usize, usize) {
    let mut best_step = 0u8;
    let mut best_count = 0usize;
    let mut second_count = 0usize;

    for step in 0u8..=255 {
        let mut hist = [0u16; 256];
        for (i, &b) in sec.iter().enumerate() {
            let plain = b
                .wrapping_sub(base)
                .wrapping_sub((i as u8).wrapping_mul(step));
            hist[plain as usize] += 1;
        }
        let peak = hist.iter().copied().max().unwrap_or(0) as usize;
        if peak > best_count {
            second_count = best_count;
            best_count = peak;
            best_step = step;
        } else if peak > second_count {
            second_count = peak;
        }
    }

    (best_step, best_count, second_count)
}

/// Deobfuscate `sec` given `(base, step)`: `plain[i] = (sec[i] − base − i*step) mod 256`.
fn apply_stream(sec: &[u8], base: u8, step: u8, out: &mut [u8]) {
    for (i, (&stored, plain)) in sec.iter().zip(out.iter_mut()).enumerate() {
        *plain = stored
            .wrapping_sub(base)
            .wrapping_sub((i as u8).wrapping_mul(step));
    }
}

/// Score every candidate `bv` (0..=255) against a single page's sectors,
/// accumulating into `bv_score`. Shared by the per-page and per-block
/// brute-force recovery paths.
///
/// Sectors 0..7: sector 7 uses fewer data bytes, but its prefix is still
/// AP-filled.  Using the full 512-byte window (including the trailer) would
/// introduce noise; we use 0..7 (not 0..8) to skip the sector-7 tail that
/// overlaps the trailer.
fn score_bv_candidates(bytes: &[u8], pn: u64, bv_score: &mut [i64; 256]) {
    let p16 = (pn % 16) as u8;
    let bias = p16 / 2 * 4;

    for si in 0..7usize {
        let off = si * SECTOR_SIZE;
        let sec = &bytes[off..off + SECTOR_SIZE];
        let offset = (pn as u8).wrapping_add(si as u8).wrapping_sub(bias);

        // For each step, build the histogram of
        //   M[i] = (sec[i] - offset - i*step) mod 256
        //         = (bv + plain[i]) mod 256   when step is correct.
        // The histogram peak at position `bv` is maximised when
        // plain[i] == 0 (which is the common case for padding bytes).
        let mut step_bv_max = [0u16; 256];

        for step in 0u8..=255 {
            let mut hist = [0u16; 256];
            for (i, &b) in sec.iter().enumerate() {
                let m = b
                    .wrapping_sub(offset)
                    .wrapping_sub((i as u8).wrapping_mul(step));
                hist[m as usize] += 1;
            }
            for (bv, &h) in hist.iter().enumerate() {
                if h > step_bv_max[bv] {
                    step_bv_max[bv] = h;
                }
            }
        }

        for (bv, &m) in step_bv_max.iter().enumerate() {
            bv_score[bv] += m as i64;
        }
    }
}

/// Attempt to learn `bv` directly from a single pure-AP page, using the same
/// technique as [`ApModel::learn`] but scoped to exactly one page rather than
/// aggregated as votes across its 16-page block.
///
/// Returns `None` if `ptype` isn't a pure-AP page type, or the page's sectors
/// don't reach [`LEARN_PURITY`].
fn learn_bv_for_page(bytes: &[u8], pn: u64, ptype: u8) -> Option<u8> {
    if !PURE_AP_TYPES.contains(&ptype) {
        return None;
    }
    let p16 = (pn % 16) as u8;
    let mut votes: HashMap<u8, u32> = HashMap::new();

    for si in 0..SECTORS_PER_PAGE {
        let off = si * SECTOR_SIZE;
        let data_end = if si + 1 == SECTORS_PER_PAGE {
            TRAILER_START
        } else {
            off + SECTOR_SIZE
        };
        let sec = &bytes[off..data_end];

        let step = dominant_step(sec);
        let base = recover_base(sec, step);
        if sector_purity(sec, base, step) < LEARN_PURITY {
            continue;
        }

        let bv = base
            .wrapping_sub(pn as u8)
            .wrapping_sub(si as u8)
            .wrapping_add(p16 / 2 * 4);
        *votes.entry(bv).or_default() += 1;
    }

    votes.into_iter().max_by_key(|&(_, v)| v).map(|(bv, _)| bv)
}

// ---------------------------------------------------------------------------
// Public AP model
// ---------------------------------------------------------------------------

/// How a page's `bv` was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BvSource {
    /// The page is a pure-AP page and its own sectors gave `bv`.
    PureSectors,
    /// `bv` was recovered by scoring every candidate against the page.
    Histogram,
    /// The caller supplied `bv`.
    Supplied,
}

/// How well one 512-byte sector's step fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SectorFit {
    step: u8,
    peak: usize,
    runner_up: usize,
}

impl SectorFit {
    /// The step used to decode the sector.
    pub fn step(&self) -> u8 {
        self.step
    }

    /// Histogram peak (count of the most common plaintext byte) under the
    /// chosen step.
    pub fn peak(&self) -> usize {
        self.peak
    }

    /// Best peak among all other steps. A runner-up close to [`peak`]
    /// means the step is not well determined.
    ///
    /// [`peak`]: SectorFit::peak
    pub fn runner_up(&self) -> usize {
        self.runner_up
    }
}

/// A deobfuscated page and how the keystream was determined.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DeobfuscatedPage {
    index: u64,
    bytes: Vec<u8>,
    bv: u8,
    bv_source: BvSource,
    sectors: [SectorFit; SECTORS_PER_PAGE],
    warnings: Vec<Warning>,
}

impl DeobfuscatedPage {
    /// Zero-based page number within the store.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The plaintext, [`PAGE_SIZE`] bytes. The trailer and CRC footer are
    /// copied verbatim from the stored page.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the result and return the plaintext.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The plaintext as a [`Page`], for the slotted-page parser.
    pub fn as_page(&self) -> Page<'_> {
        Page {
            index: self.index,
            bytes: &self.bytes,
        }
    }

    /// The calibration byte used for this page.
    pub fn bv(&self) -> u8 {
        self.bv
    }

    /// How [`Self::bv`] was chosen.
    pub fn bv_source(&self) -> BvSource {
        self.bv_source
    }

    /// Per-sector step fits.
    pub fn sectors(&self) -> &[SectorFit; SECTORS_PER_PAGE] {
        &self.sectors
    }

    /// Conditions accepted under lenient [`ReadOptions`]. Empty means every
    /// check passed.
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }
}

/// What [`ApModel::learn`] found while calibrating.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LearnReport {
    pure_pages: usize,
    warnings: Vec<Warning>,
}

impl LearnReport {
    /// Pure-AP pages that contributed calibration votes.
    pub fn pure_pages(&self) -> usize {
        self.pure_pages
    }

    /// Conditions accepted under lenient [`ReadOptions`].
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }
}

/// AP deobfuscation model for a single SA17 page-store file.
///
/// Build one with [`ApModel::learn`], then call [`ApModel::deobfuscate`]
/// to recover plaintext for any page.
///
/// The model is cheap to clone; it stores at most one `u8` per 16-page block.
#[derive(Debug, Clone)]
pub struct ApModel {
    /// Learned `bv` values, keyed by block index (`pn / 16`).
    bv_map: HashMap<u64, u8>,
    report: LearnReport,
}

impl ApModel {
    /// Construct an [`ApModel`] by scanning every pure-AP page in `store`.
    ///
    /// Pure-AP page types - `'@'`, `'C'`, `'H'`, `'M'` - have bodies
    /// dominated by the AP fill (sectors 1..6 are almost entirely fill).
    /// From those sectors we can back-calculate `bv(block)` precisely.
    ///
    /// Pages of other types, whose plaintext is dense, contribute nothing
    /// to the calibration.
    pub fn learn(store: &PageStore, _opts: &ReadOptions) -> Result<Self> {
        let mut votes: HashMap<u64, HashMap<u8, u32>> = HashMap::new();
        let mut pure_pages = 0usize;

        for page in store.pages() {
            let page = page?;
            let ptype = page.trailer().page_type_raw();
            if !PURE_AP_TYPES.contains(&ptype) {
                continue;
            }
            pure_pages += 1;
            let pn = page.index();
            let bi = pn / 16;
            let p16 = (pn % 16) as u8;
            let bytes = page.bytes();

            // All 8 sectors, same as the Python reference implementation.
            // For sector 7, the usable data ends at TRAILER_START (not at the
            // end of the 512-byte sector window) - the 16-byte trailer is not
            // AP-obfuscated, so we must exclude it from purity checks.
            for si in 0..SECTORS_PER_PAGE {
                let off = si * SECTOR_SIZE;
                let data_end = if si + 1 == SECTORS_PER_PAGE {
                    TRAILER_START
                } else {
                    off + SECTOR_SIZE
                };
                let sec = &bytes[off..data_end];

                let step = dominant_step(sec);
                let base = recover_base(sec, step);
                if sector_purity(sec, base, step) < LEARN_PURITY {
                    continue;
                }

                // Invert the base formula: bv = base - pn - si + 4*(p16/2)
                let bv = base
                    .wrapping_sub(pn as u8)
                    .wrapping_sub(si as u8)
                    .wrapping_add(p16 / 2 * 4);

                *votes.entry(bi).or_default().entry(bv).or_default() += 1;
            }
        }

        let mut bv_map: HashMap<u64, u8> = HashMap::new();
        for (bi, ctr) in &votes {
            if let Some((&bv, _)) = ctr.iter().max_by_key(|&(_, &v)| v) {
                bv_map.insert(*bi, bv);
            }
        }

        Ok(ApModel {
            bv_map,
            report: LearnReport {
                pure_pages,
                warnings: Vec::new(),
            },
        })
    }

    /// What calibration found.
    pub fn report(&self) -> &LearnReport {
        &self.report
    }

    /// Number of blocks for which `bv` was directly learned from a pure-AP page.
    pub fn learned_block_count(&self) -> usize {
        self.bv_map.len()
    }

    /// Deobfuscate page `pn` of `store`, recovering `bv` for this specific
    /// page rather than trusting a value shared across its 16-page block.
    ///
    /// `bv` is not reliably constant per block on every file - some
    /// QuickBooks Enterprise 24.0 files show 6-8 distinct `bv` values inside
    /// a single block (`opensqlany` issue #8). So this always resolves `bv`
    /// per page: directly, if `pn` is itself a pure-AP page with a clean
    /// signal, otherwise by scoring every candidate `bv` against the page.
    ///
    /// The page trailer (`0xFF0..0xFFC`) and CRC footer (`0xFFC..0x1000`) are
    /// copied verbatim; they are stored in plaintext.
    pub fn deobfuscate(
        &self,
        store: &PageStore,
        pn: u64,
        opts: &ReadOptions,
    ) -> Result<DeobfuscatedPage> {
        let page = store.page(pn)?;
        let raw = page.bytes();
        let ptype = raw[TRAILER_START + 2];
        let (bv, source) = match learn_bv_for_page(raw, pn, ptype) {
            Some(bv) => (bv, BvSource::PureSectors),
            None => (recover_bv_for_page(raw, pn), BvSource::Histogram),
        };
        Self::decode_with_bv(page, bv, source, opts)
    }

    /// Deobfuscate using an explicitly supplied `bv`.
    ///
    /// The caller is responsible for supplying the correct `bv`; the model's
    /// calibration is not consulted.
    pub fn deobfuscate_with_bv(
        page: Page<'_>,
        bv: u8,
        opts: &ReadOptions,
    ) -> Result<DeobfuscatedPage> {
        Self::decode_with_bv(page, bv, BvSource::Supplied, opts)
    }

    fn decode_with_bv(
        page: Page<'_>,
        bv: u8,
        source: BvSource,
        _opts: &ReadOptions,
    ) -> Result<DeobfuscatedPage> {
        let pn = page.index();
        let raw = page.bytes();
        if raw.len() != PAGE_SIZE {
            return Err(Error::WrongBufferLength {
                expected: PAGE_SIZE,
                got: raw.len(),
            });
        }

        let mut out = vec![0u8; PAGE_SIZE];
        let mut sectors = [SectorFit {
            step: 0,
            peak: 0,
            runner_up: 0,
        }; SECTORS_PER_PAGE];

        for (si, fit) in sectors.iter_mut().enumerate() {
            let off = si * SECTOR_SIZE;
            let data_end = if si + 1 == SECTORS_PER_PAGE {
                TRAILER_START
            } else {
                off + SECTOR_SIZE
            };
            let sec = &raw[off..data_end];
            let base = ap_base(pn, si, bv);
            let (step, peak, runner_up) = recover_step_peak(sec, base);
            apply_stream(sec, base, step, &mut out[off..data_end]);
            *fit = SectorFit {
                step,
                peak,
                runner_up,
            };
        }

        out[TRAILER_START..PAGE_SIZE].copy_from_slice(&raw[TRAILER_START..PAGE_SIZE]);
        Ok(DeobfuscatedPage {
            index: pn,
            bytes: out,
            bv,
            bv_source: source,
            sectors,
            warnings: Vec::new(),
        })
    }
}

/// Brute-force recover `bv` for a single page, independent of its block.
///
/// Histogram-peak search over candidate `(bv, step)` pairs, scoped to exactly
/// this page.
fn recover_bv_for_page(raw: &[u8], pn: u64) -> u8 {
    let mut bv_score = [0i64; 256];
    score_bv_candidates(raw, pn, &mut bv_score);
    bv_score
        .iter()
        .enumerate()
        .max_by_key(|&(_, &v)| v)
        .map(|(i, _)| i as u8)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal AP-fill sector with given base and step.
    fn make_ap_sector(base: u8, step: u8) -> [u8; SECTOR_SIZE] {
        let mut sec = [0u8; SECTOR_SIZE];
        for (i, b) in sec.iter_mut().enumerate() {
            *b = base.wrapping_add((i as u8).wrapping_mul(step));
        }
        sec
    }

    #[test]
    fn dominant_step_pure_ap() {
        let sec = make_ap_sector(0x63, 3);
        assert_eq!(dominant_step(&sec), 3);
    }

    #[test]
    fn recover_base_pure_ap() {
        let sec = make_ap_sector(0x71, 7);
        let step = dominant_step(&sec);
        assert_eq!(step, 7);
        assert_eq!(recover_base(&sec, step), 0x71);
    }

    #[test]
    fn sector_purity_perfect() {
        let sec = make_ap_sector(0x40, 11);
        let step = dominant_step(&sec);
        let base = recover_base(&sec, step);
        assert!(sector_purity(&sec, base, step) > 0.99);
    }

    #[test]
    fn roundtrip_zero_plaintext() {
        // If plaintext is all zeros, stored == fill; deobfuscating recovers zeros.
        let base: u8 = 0x55;
        let step: u8 = 19;
        let stored: Vec<u8> = (0..SECTOR_SIZE)
            .map(|i| base.wrapping_add((i as u8).wrapping_mul(step)))
            .collect();
        let (recovered_step, _, _) = recover_step_peak(&stored, base);
        let mut plain = vec![0u8; SECTOR_SIZE];
        apply_stream(&stored, base, recovered_step, &mut plain);
        assert!(plain.iter().all(|&b| b == 0));
    }

    #[test]
    fn ap_base_formula() {
        // Spot-check the closed-form formula against the Python derivation.
        // pn=10, si=2, bv=0xC0:
        //   p16 = 10 % 16 = 10
        //   offset = (10/2)*4 = 20
        //   base = (0xC0 + 10 + 2 - 20) mod 256 = (192+12-20) = 184 = 0xB8
        assert_eq!(ap_base(10, 2, 0xC0), 0xB8);

        // pn=0, si=0, bv=0x00: base = 0
        assert_eq!(ap_base(0, 0, 0x00), 0x00);

        // pn=16, si=3, bv=0x10: p16=0, offset=0 → base = 0x10+16+3 = 0x23
        assert_eq!(ap_base(16, 3, 0x10), 0x23);
    }

    /// Encode a page's data region (sectors 0..7, trailer untouched) under a
    /// fixed `(bv, step)`, for a given plaintext. `plaintext` must be exactly
    /// `TRAILER_START` bytes.
    fn encode_page(pn: u64, ptype: u8, bv: u8, step: u8, plaintext: &[u8]) -> Vec<u8> {
        assert_eq!(plaintext.len(), TRAILER_START);
        let mut out = vec![0u8; PAGE_SIZE];
        for si in 0..SECTORS_PER_PAGE {
            let off = si * SECTOR_SIZE;
            let data_end = if si + 1 == SECTORS_PER_PAGE {
                TRAILER_START
            } else {
                off + SECTOR_SIZE
            };
            let base = ap_base(pn, si, bv);
            for (i, &p) in plaintext[off..data_end].iter().enumerate() {
                out[off + i] = base
                    .wrapping_add((i as u8).wrapping_mul(step))
                    .wrapping_add(p);
            }
        }
        out[TRAILER_START + 2] = ptype;
        out
    }

    #[test]
    fn deobfuscate_uses_per_page_bv_not_block_bv() {
        // Block 0: page 0 is a pure-AP calibration page with bv=10; page 1
        // is a dense 'E' page whose true bv is 200, different from the
        // block's learned value. Reproduces the per-page bv variation
        // reported against a QuickBooks Enterprise 24.0 file (opensqlany#8):
        // a single block-level bv does not decode every page in the block.
        let zero_plain = vec![0u8; TRAILER_START];
        let page0 = encode_page(0, b'@', 10, 3, &zero_plain);
        let page1 = encode_page(1, b'E', 200, 7, &zero_plain);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&page0);
        bytes.extend_from_slice(&page1);
        let store = PageStore::from_bytes(bytes).unwrap();

        let opts = ReadOptions::default();
        let model = ApModel::learn(&store, &opts).unwrap();
        assert_eq!(model.learned_block_count(), 1);

        let plain = model.deobfuscate(&store, 1, &opts).unwrap();
        assert_eq!(plain.bv(), 200);
        assert!(
            plain.bytes()[..TRAILER_START].iter().all(|&b| b == 0),
            "per-page recovery should find page 1's true bv (200), not the block's (10)"
        );
    }

    #[test]
    fn recover_bv_for_page_matches_direct_learn() {
        // A single pure-AP page should recover the same bv whether learned
        // directly (learn_bv_for_page) or brute-forced (recover_bv_for_page).
        let zero_plain = vec![0u8; TRAILER_START];
        let page = encode_page(0, b'H', 77, 13, &zero_plain);

        assert_eq!(learn_bv_for_page(&page, 0, b'H'), Some(77));
        assert_eq!(recover_bv_for_page(&page, 0), 77);
    }
}
