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
//! - `pn`  — zero-based page number
//! - `si`  — sector index within the page (0..8, each sector = 512 bytes)
//! - `i`   — byte index within the sector
//! - `bv(bi)` — a per–16-page-block calibration byte, learned from the file
//!
//! `step` varies per sector and is recovered empirically by finding the
//! candidate step value that produces the highest histogram peak in the
//! deobfuscated plaintext (i.e., the step that makes the most bytes equal
//! to some repeated value, exploiting the fact that SA stores many zero bytes
//! in padding and unused column areas).
//!
//! `bv` is learned from pages whose plaintext is almost entirely zero — the
//! "pure AP" page types: `'@'` (0x40), `'C'` (0x43), `'H'` (0x48), and
//! `'M'` (0x4D). For these pages the stored bytes are virtually equal to the
//! fill, so `bv` can be back-calculated directly.
//!
//! # References
//!
//! See `NOTES.md §C.14` and `§C.19` for the empirical derivation.

use std::collections::HashMap;

use crate::page::PAGE_SIZE;
use crate::store::PageStore;

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
/// For each candidate step `s`, compute `plain[i] = (sec[i] − base − i*s) mod 256`
/// and find the frequency of the most common byte.  The step with the highest
/// peak is returned.  For sectors with many zero-valued plaintext bytes this
/// reliably finds the correct step.
///
/// Returns `(best_step, peak_count)`.
fn recover_step_peak(sec: &[u8], base: u8) -> (u8, usize) {
    let mut best_step = 0u8;
    let mut best_count = 0usize;

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
            best_count = peak;
            best_step = step;
        }
    }

    (best_step, best_count)
}

/// Deobfuscate `sec` given `(base, step)`: `plain[i] = (sec[i] − base − i*step) mod 256`.
fn apply_stream(sec: &[u8], base: u8, step: u8, out: &mut [u8]) {
    for (i, (&stored, plain)) in sec.iter().zip(out.iter_mut()).enumerate() {
        *plain = stored
            .wrapping_sub(base)
            .wrapping_sub((i as u8).wrapping_mul(step));
    }
}

// ---------------------------------------------------------------------------
// Public AP model
// ---------------------------------------------------------------------------

/// AP deobfuscation model for a single SA17 page-store file.
///
/// Build one with [`ApModel::learn`], then call [`ApModel::deobfuscate`]
/// to recover plaintext for any page.
///
/// The model is cheap to clone; it stores at most one `u8` per 16-page block.
#[derive(Debug, Clone, Default)]
pub struct ApModel {
    /// Learned `bv` values, keyed by block index (`pn / 16`).
    bv_map: HashMap<u64, u8>,
    /// Best single `bv` to use when a block has no pure-AP page (fallback).
    bv0: u8,
}

impl ApModel {
    /// Construct an [`ApModel`] by scanning every pure-AP page in `store`.
    ///
    /// Pure-AP page types — `'@'`, `'C'`, `'H'`, `'M'` — have bodies
    /// dominated by the AP fill (sectors 1..6 are almost entirely fill).
    /// From those sectors we can back-calculate `bv(block)` precisely.
    ///
    /// Pages of other types, whose plaintext is dense, contribute nothing
    /// to the calibration.  At least one pure-AP page must exist in the
    /// store (SA17 files always have some).
    pub fn learn(store: &PageStore) -> Self {
        let mut votes: HashMap<u64, HashMap<u8, u32>> = HashMap::new();

        for page in store.pages() {
            let ptype = page.trailer().page_type_raw;
            if !PURE_AP_TYPES.contains(&ptype) {
                continue;
            }
            let pn = page.index();
            let bi = pn / 16;
            let p16 = (pn % 16) as u8;
            let bytes = page.bytes();

            // All 8 sectors, same as the Python reference implementation.
            // For sector 7, the usable data ends at TRAILER_START (not at the
            // end of the 512-byte sector window) — the 16-byte trailer is not
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

                // Invert the base formula: bv = base − pn − si + 4*(p16/2)
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

        // Fallback: the bv for block 0, or the lowest observed block.
        let bv0 = bv_map
            .get(&0)
            .copied()
            .unwrap_or_else(|| bv_map.values().copied().next().unwrap_or(0));

        ApModel { bv_map, bv0 }
    }

    /// Return the `bv` for block `bi`, falling back to `bv0` for unknown blocks.
    ///
    /// For files where every block has at least one pure-AP page, every block
    /// will be in `bv_map`.  For the rare blocks that lack one, `bv0` is used
    /// (an approximation that degrades gracefully).
    #[inline]
    pub fn bv_at(&self, bi: u64) -> u8 {
        self.bv_map.get(&bi).copied().unwrap_or(self.bv0)
    }

    /// Deobfuscate a full 4 KiB page.
    ///
    /// `pn` is the zero-based page index within the store.
    ///
    /// The page trailer (`0xFF0..0xFFC`) and CRC footer (`0xFFC..0x1000`) are
    /// copied verbatim; they are stored in plaintext and must not be modified.
    ///
    /// For blocks whose `bv` was not learned from a pure-AP page this falls
    /// back to `bv0`.  Use [`ApModel::deobfuscate_with_store`] to get the
    /// correct `bv` for every block.
    pub fn deobfuscate(&self, raw: &[u8], pn: u64) -> Vec<u8> {
        self.deobfuscate_with_bv(raw, pn, self.bv_at(pn / 16))
    }

    /// Number of blocks for which `bv` was directly learned from a pure-AP page.
    pub fn learned_block_count(&self) -> usize {
        self.bv_map.len()
    }

    /// Brute-force recover `bv` for a block that has no pure-AP page.
    ///
    /// For each candidate `bv` (0..=255), score it by computing the peak of the
    /// histogram of `(stored[i] - (pn + si - bias) - i*step) mod 256` for each
    /// candidate step, then summing the best-step peak across all sectors of up
    /// to 3 sample pages in the block.  The candidate with the highest total
    /// score is returned.
    ///
    /// The algorithm matches `APModel._recover_bv_for_block` in the Python
    /// reference implementation.  At ~2.7 M arithmetic ops per block it is fast
    /// in release mode (< 2 ms on modern hardware).
    pub fn recover_bv_for_block(&self, store: &PageStore, bi: u64) -> u8 {
        let page_start = bi * 16;
        let page_end = (page_start + 16).min(store.page_count());
        if page_start >= store.page_count() {
            return self.bv0;
        }

        let sample_end = page_end.min(page_start + 3);
        let mut bv_score = [0i64; 256];

        for pn in page_start..sample_end {
            let page = match store.page(pn) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let bytes = page.bytes();
            let p16 = (pn % 16) as u8;
            let bias = p16 / 2 * 4;

            // Sectors 0..7: sector 7 uses fewer data bytes, but its prefix
            // is still AP-filled.  Using the full 512-byte window (including
            // the trailer) would introduce noise; we use 0..7 (not 0..8) to
            // skip the sector-7 tail that overlaps the trailer.
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

        bv_score
            .iter()
            .enumerate()
            .max_by_key(|&(_, &v)| v)
            .map(|(i, _)| i as u8)
            .unwrap_or(self.bv0)
    }

    /// Deobfuscate a full 4 KiB page, recovering the block's `bv` from the
    /// store on demand if it was not learned from pure-AP pages.
    ///
    /// Use this variant when you need accurate deobfuscation for blocks that
    /// have no pure-AP pages (which is the common case for dense data blocks
    /// that consist entirely of 'E'-type pages).
    pub fn deobfuscate_with_store(&self, raw: &[u8], pn: u64, store: &PageStore) -> Vec<u8> {
        let bi = pn / 16;
        let bv = if self.bv_map.contains_key(&bi) {
            self.bv_at(bi)
        } else {
            self.recover_bv_for_block(store, bi)
        };
        self.deobfuscate_with_bv(raw, pn, bv)
    }

    /// Deobfuscate using an explicitly supplied `bv`.
    ///
    /// The caller is responsible for supplying the correct block `bv`; the
    /// model's internal `bv_map` is not consulted.
    pub fn deobfuscate_with_bv(&self, raw: &[u8], pn: u64, bv: u8) -> Vec<u8> {
        assert!(raw.len() >= PAGE_SIZE, "page buffer too small");

        let mut out = vec![0u8; PAGE_SIZE];

        for si in 0..SECTORS_PER_PAGE {
            let off = si * SECTOR_SIZE;
            let data_end = if si + 1 == SECTORS_PER_PAGE {
                TRAILER_START
            } else {
                off + SECTOR_SIZE
            };
            let sec = &raw[off..data_end];
            let base = ap_base(pn, si, bv);
            let (step, _) = recover_step_peak(sec, base);
            apply_stream(sec, base, step, &mut out[off..data_end]);
        }

        out[TRAILER_START..PAGE_SIZE].copy_from_slice(&raw[TRAILER_START..PAGE_SIZE]);
        out
    }
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
        let (recovered_step, _) = recover_step_peak(&stored, base);
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
}
