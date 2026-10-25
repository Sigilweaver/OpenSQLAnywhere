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
//! - `bv` - a calibration byte
//!
//! Neither `step` nor `bv` is stored anywhere. Both are recovered from the
//! bytes, and neither recovery is exact on its own:
//!
//! * `step` is the value that makes the most bytes of the sector equal.
//!   Sectors of mostly zero plaintext give a sharp peak; dense sectors do
//!   not, and a regular plaintext (a run of slot offsets, a counter) can
//!   pull the peak to a neighbouring step.
//! * `bv` is only defined up to the plaintext's most common byte. A page
//!   whose padding is `0x20` or `0xFF` instead of zero decodes shifted by a
//!   constant if padding is assumed to be zero.
//!
//! So a guess is accepted only when something independent confirms it. The
//! evidence, strongest first:
//!
//! 1. **Trailer row count.** The row count in a slotted page's prelude must
//!    equal the plaintext trailer's count byte ([`Evidence::TrailerRowCount`]).
//! 2. **Exact sectors.** At least two sectors of the page are exact AP
//!    progressions and agree on `bv`, and no exact sector disagrees
//!    ([`Evidence::ExactSectors`]).
//! 3. **Block anchor.** The page's best histogram `bv` equals the `bv` of a
//!    calibrated pure-AP page in the same 16-page block
//!    ([`Evidence::BlockAnchor`]).
//!
//! A page with none of these is [`Confidence::Unverified`] and is an error
//! unless the caller sets [`Leniency::KEYSTREAM`](crate::Leniency::KEYSTREAM).
//! Competing evidence is also an error, never a coin flip: ties resolve to
//! [`Error::AmbiguousCalibration`].
//!
//! Every choice is deterministic. Ties between equal scores resolve to the
//! lowest value, and no hash-ordered container decides an outcome.
//!
//! # References
//!
//! See `NOTES.md` section C.14 and C.19 for the empirical derivation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use crate::error::{Error, Result};
use crate::options::{Leniency, ReadOptions};
use crate::page::{PAGE_SIZE, Page};
use crate::store::PageStore;
use crate::verify::trailer_row_count_matches;
use crate::warning::{Warning, WarningKind};

/// Size of a single AP sector in bytes.
pub const SECTOR_SIZE: usize = 512;
/// Number of sectors per page (8 x 512 = 4096 bytes).
pub const SECTORS_PER_PAGE: usize = PAGE_SIZE / SECTOR_SIZE;
/// Byte offset at which the page trailer begins.
const TRAILER_START: usize = 0xFF0;

/// A step needs at least this many equal bytes to count as a peak. Random
/// 512-byte sectors reach 9 to 13 under the best of 256 steps (measured on
/// the 112-file corpus), so 24 is well clear of the noise.
const MIN_STEP_PEAK: usize = 24;
/// A step needs at least this many more equal bytes than the next best step.
const MIN_STEP_LEAD: usize = 12;
/// Exact sectors needed before they alone calibrate a page.
const MIN_EXACT_SECTORS: usize = 2;
/// Histogram candidates examined per page in addition to the exact ones.
const HISTOGRAM_CANDIDATES: usize = 4;

/// Page-type bytes whose bodies are dominated by AP fill: `'@'`, `'C'`,
/// `'H'`, `'M'`, in either case (the lowercase variant is `0x20` higher).
fn is_pure_ap_type(b: u8) -> bool {
    matches!(b, 0x40 | 0x43 | 0x48 | 0x4D | 0x60 | 0x63 | 0x68 | 0x6D)
}

/// Byte range of sector `si` within a page's obfuscated data.
fn sector_range(si: usize) -> (usize, usize) {
    let start = si * SECTOR_SIZE;
    let end = if si + 1 == SECTORS_PER_PAGE {
        TRAILER_START
    } else {
        start + SECTOR_SIZE
    };
    (start, end)
}

/// `base(pn, si)` without `bv`: `pn + si - 4 * floor((pn % 16) / 2)` mod 256.
#[inline]
fn ap_offset(pn: u64, si: usize) -> u8 {
    let bias = (pn % 16) as u8 / 2 * 4;
    (pn as u8).wrapping_add(si as u8).wrapping_sub(bias)
}

/// `(stored[i] - offset - i * step)`, which is `bv + plaintext[i]`.
#[inline]
fn shifted(b: u8, offset: u8, i: usize, step: u8) -> u8 {
    b.wrapping_sub(offset)
        .wrapping_sub((i as u8).wrapping_mul(step))
}

// ---------------------------------------------------------------------------
// Sector and page scans
// ---------------------------------------------------------------------------

/// What the byte histogram says about one sector.
struct SectorScan {
    step: u8,
    peak: usize,
    runner_up: usize,
    /// `bv + plaintext` under the chosen step, one byte per sector byte.
    m: Vec<u8>,
}

impl SectorScan {
    /// The sector is a pure AP progression: every byte of `m` is equal.
    fn is_exact(&self) -> bool {
        self.peak == self.m.len()
    }
}

/// Find the step that maximises the histogram peak of `bv + plaintext`.
///
/// Ties keep the lowest step. The runner-up is the best peak among all other
/// steps, so a lead of zero means the step is not determined.
fn scan_sector(sec: &[u8], offset: u8) -> SectorScan {
    let mut best_step = 0u8;
    let mut best = 0usize;
    let mut runner_up = 0usize;

    for step in 0u8..=255 {
        let mut hist = [0u16; 256];
        for (i, &b) in sec.iter().enumerate() {
            hist[shifted(b, offset, i, step) as usize] += 1;
        }
        let peak = hist.iter().copied().max().unwrap_or(0) as usize;
        if peak > best {
            runner_up = best;
            best = peak;
            best_step = step;
        } else if peak > runner_up {
            runner_up = peak;
        }
    }

    let m = sec
        .iter()
        .enumerate()
        .map(|(i, &b)| shifted(b, offset, i, best_step))
        .collect();
    SectorScan {
        step: best_step,
        peak: best,
        runner_up,
        m,
    }
}

/// The step and constant of `sec` if it is an exact AP progression.
///
/// An exact progression has a unique `(base, step)`, read from its first two
/// bytes, so this is a single pass.
fn exact_sector(sec: &[u8], offset: u8) -> Option<(u8, u8)> {
    if sec.len() < 2 {
        return None;
    }
    let step = sec[1].wrapping_sub(sec[0]);
    let m = shifted(sec[0], offset, 0, step);
    sec.iter()
        .enumerate()
        .all(|(i, &b)| shifted(b, offset, i, step) == m)
        .then_some((step, m))
}

struct PageScan {
    sectors: Vec<SectorScan>,
    /// How many data bytes have each value of `bv + plaintext`.
    counts: [u32; 256],
}

fn scan_page(raw: &[u8], pn: u64) -> PageScan {
    let sectors: Vec<SectorScan> = (0..SECTORS_PER_PAGE)
        .map(|si| {
            let (start, end) = sector_range(si);
            scan_sector(&raw[start..end], ap_offset(pn, si))
        })
        .collect();
    let mut counts = [0u32; 256];
    for s in &sectors {
        for &m in &s.m {
            counts[m as usize] += 1;
        }
    }
    PageScan { sectors, counts }
}

/// `bv` votes of the exact sectors of `raw` (`m` constant -> sector count).
fn exact_votes(raw: &[u8], pn: u64) -> BTreeMap<u8, usize> {
    let mut votes = BTreeMap::new();
    for si in 0..SECTORS_PER_PAGE {
        let (start, end) = sector_range(si);
        if let Some((_, m)) = exact_sector(&raw[start..end], ap_offset(pn, si)) {
            *votes.entry(m).or_default() += 1;
        }
    }
    votes
}

/// Plaintext of `scan` under `bv`, with the trailer and CRC copied from `raw`.
fn plaintext(scan: &PageScan, raw: &[u8], bv: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAGE_SIZE);
    for s in &scan.sectors {
        out.extend(s.m.iter().map(|&m| m.wrapping_sub(bv)));
    }
    out.extend_from_slice(&raw[TRAILER_START..PAGE_SIZE]);
    out
}

// ---------------------------------------------------------------------------
// Public results
// ---------------------------------------------------------------------------

/// How a page's `bv` was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BvSource {
    /// A structural check or an agreeing pure-AP page confirmed a candidate
    /// (see [`DeobfuscatedPage::evidence`]).
    Verified,
    /// Two or more exact AP sectors of the page agree.
    ExactSectors,
    /// The highest-scoring histogram candidate, with nothing confirming it.
    Histogram,
    /// The caller supplied `bv`.
    Supplied,
}

/// How far a page's `bv` can be trusted.
///
/// Variants are ordered from least to most trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Confidence {
    /// Nothing independent confirmed the guess. Only returned under
    /// [`Leniency::KEYSTREAM`](crate::Leniency::KEYSTREAM), with a
    /// [`WarningKind::UnverifiedKeystream`] warning.
    Unverified,
    /// The guess rests on evidence from the page's own sectors or from the
    /// calibration of other pages ([`Evidence::ExactSectors`],
    /// [`Evidence::BlockAnchor`]).
    Calibrated,
    /// The decoded page matched a structural check against plaintext that is
    /// not obfuscated ([`Evidence::TrailerRowCount`]).
    Verified,
}

/// One piece of evidence for a page's `bv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Evidence {
    /// The row count in the decoded page prelude equals the trailer's count
    /// byte. The trailer is not obfuscated, so this independently confirms
    /// `bv`.
    TrailerRowCount,
    /// Sectors that are exact AP progressions (all plaintext equal, taken to
    /// be zero) agree on `bv`.
    ExactSectors {
        /// Exact sectors voting for the chosen `bv`.
        count: usize,
        /// Exact sectors voting for another `bv`.
        dissent: usize,
    },
    /// A calibrated pure-AP page in the same 16-page block has the same `bv`.
    BlockAnchor,
    /// Histogram score: bytes that decode to zero under the chosen `bv`, and
    /// how many more than the best competing candidate.
    ZeroMass {
        /// Data bytes that decode to zero.
        zeros: usize,
        /// Lead over the next candidate (`zeros` when there is none).
        lead: usize,
    },
}

/// How well one 512-byte sector's step fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SectorFit {
    step: u8,
    peak: usize,
    runner_up: usize,
    exact: bool,
}

impl SectorFit {
    /// The step used to decode the sector.
    pub fn step(&self) -> u8 {
        self.step
    }

    /// Count of the most common plaintext-plus-`bv` byte under the chosen
    /// step.
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

    /// The sector is an exact AP progression, so its step is certain.
    pub fn exact(&self) -> bool {
        self.exact
    }

    /// `true` when the step stands clear of its runner-up (or is exact).
    pub fn confident(&self) -> bool {
        self.exact
            || (self.peak >= MIN_STEP_PEAK
                && self.peak >= self.runner_up.saturating_add(MIN_STEP_LEAD))
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
    confidence: Confidence,
    evidence: Vec<Evidence>,
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

    /// How [`Self::bv`] was determined.
    pub fn bv_source(&self) -> BvSource {
        self.bv_source
    }

    /// How far [`Self::bv`] can be trusted.
    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// The evidence behind [`Self::bv`].
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
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
    calibrated_pages: usize,
    ambiguous_pages: usize,
    warnings: Vec<Warning>,
}

impl LearnReport {
    /// Pure-AP pages examined (`'@'`, `'C'`, `'H'`, `'M'`, either case).
    pub fn pure_pages(&self) -> usize {
        self.pure_pages
    }

    /// Pure-AP pages whose exact sectors agree on one `bv`; these anchor
    /// their blocks.
    pub fn calibrated_pages(&self) -> usize {
        self.calibrated_pages
    }

    /// Pure-AP pages whose exact sectors disagree, or that have fewer than
    /// two. They do not anchor their blocks.
    pub fn ambiguous_pages(&self) -> usize {
        self.ambiguous_pages
    }

    /// Conditions accepted under lenient [`ReadOptions`].
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// AP deobfuscation model for a single SA17 page-store file.
///
/// [`ApModel::learn`] confirms that the store uses the AP cipher and records
/// which pure-AP pages calibrate which 16-page blocks.
/// [`ApModel::deobfuscate`] then decodes any page, choosing and verifying its
/// `bv` and steps per page (see the module documentation).
///
/// The model is cheap to clone.
#[derive(Debug, Clone)]
pub struct ApModel {
    /// Calibrated pure-AP pages: block index -> `(page, bv)`.
    anchors: BTreeMap<u64, Vec<(u64, u8)>>,
    /// Identifies the store the model was learned from.
    fingerprint: (u64, u32),
    /// Per-block calibrated pages from every page type, filled on demand.
    /// Shared between clones.
    blocks: BlockCache,
    report: LearnReport,
}

/// Calibrated pages per block: `(page, bv)`.
type BlockCache = Arc<Mutex<BTreeMap<u64, Arc<Vec<(u64, u8)>>>>>;

/// Cheap identity of a store: its page count and the CRC of page 0.
fn fingerprint(store: &PageStore) -> Result<(u64, u32)> {
    let page0 = store.page(0)?;
    Ok((store.page_count(), crc32fast::hash(page0.bytes())))
}

impl ApModel {
    /// Confirm that `store` is AP-obfuscated and calibrate its blocks.
    ///
    /// Pure-AP pages (`'@'`, `'C'`, `'H'`, `'M'`, either case) have bodies
    /// that are mostly zero, so most of their sectors are exact AP
    /// progressions. Where two or more of a page's sectors are exact and
    /// agree on `bv`, that page calibrates its 16-page block.
    ///
    /// # Errors
    ///
    /// * [`Error::NotObfuscated`] when the pure-AP pages read as plaintext
    ///   zero.
    /// * [`Error::NoCalibration`] when no pure-AP page calibrates.
    ///
    /// Both are accepted under [`Leniency::KEYSTREAM`], with a warning in the
    /// [`LearnReport`].
    pub fn learn(store: &PageStore, opts: &ReadOptions) -> Result<Self> {
        let mut anchors: BTreeMap<u64, Vec<(u64, u8)>> = BTreeMap::new();
        let mut report = LearnReport::default();
        let mut plaintext_pages = 0usize;

        for page in store.pages() {
            let page = page?;
            if !is_pure_ap_type(page.trailer().page_type_raw()) {
                continue;
            }
            report.pure_pages += 1;
            let pn = page.index();
            let raw = page.bytes();

            // Two or more all-zero stored sectors on one page are impossible
            // under the cipher (the offset changes with every sector) and are
            // exactly what a plaintext store looks like.
            let zero_sectors = (0..SECTORS_PER_PAGE)
                .filter(|&si| {
                    let (start, end) = sector_range(si);
                    raw[start..end].iter().all(|&b| b == 0)
                })
                .count();
            if zero_sectors >= 2 {
                plaintext_pages += 1;
            }

            let votes = exact_votes(raw, pn);
            match votes.iter().next() {
                Some((&bv, &n)) if votes.len() == 1 && n >= MIN_EXACT_SECTORS => {
                    report.calibrated_pages += 1;
                    anchors.entry(pn / 16).or_default().push((pn, bv));
                }
                _ => report.ambiguous_pages += 1,
            }
        }

        if report.calibrated_pages == 0 {
            let (err, code) = if report.pure_pages > 0 && plaintext_pages * 2 > report.pure_pages {
                (Error::NotObfuscated, "not-obfuscated")
            } else {
                (Error::NoCalibration, "no-calibration")
            };
            if !opts.leniency.contains(Leniency::KEYSTREAM) {
                return Err(err);
            }
            report.warnings.push(Warning::new(WarningKind::Other(code)));
        }

        Ok(ApModel {
            anchors,
            fingerprint: fingerprint(store)?,
            blocks: Arc::default(),
            report,
        })
    }

    /// What calibration found.
    pub fn report(&self) -> &LearnReport {
        &self.report
    }

    /// Number of 16-page blocks anchored by at least one calibrated pure-AP
    /// page.
    pub fn learned_block_count(&self) -> usize {
        self.anchors.len()
    }

    /// Deobfuscate page `pn` of `store`.
    ///
    /// `bv` and every sector's step are determined for this page alone,
    /// because `bv` is not constant per block on every file (some QuickBooks
    /// Enterprise 24.0 files show 6-8 distinct values inside one block,
    /// `opensqlany` issue #8). The module documentation lists the evidence a
    /// guess needs.
    ///
    /// The page trailer (`0xFF0..0xFFC`) and CRC footer (`0xFFC..0x1000`) are
    /// copied verbatim; they are stored in plaintext.
    ///
    /// # Errors
    ///
    /// * [`Error::PageOutOfRange`] when `pn` is not in `store`.
    /// * [`Error::AmbiguousCalibration`] when the evidence points at more
    ///   than one `bv`.
    /// * [`Error::KeystreamUnverified`] when nothing confirms the best guess.
    /// * [`Error::LowConfidenceKeystream`] when a sector's step is not
    ///   determined.
    ///
    /// The last three become [`Warning`]s on the result under
    /// [`Leniency::KEYSTREAM`].
    pub fn deobfuscate(
        &self,
        store: &PageStore,
        pn: u64,
        opts: &ReadOptions,
    ) -> Result<DeobfuscatedPage> {
        if fingerprint(store)? != self.fingerprint {
            return Err(Error::StoreMismatch);
        }
        let page = store.page(pn)?;
        let raw = page.bytes();
        let scan = scan_page(raw, pn);
        let anchors: BTreeSet<u8> = self
            .block_anchors(store, pn / 16)?
            .iter()
            .filter(|&&(apn, _)| apn != pn)
            .map(|&(_, bv)| bv)
            .collect();
        let mut warnings = Vec::new();
        let choice = choose_bv(&scan, raw, pn, &anchors, opts, &mut warnings)?;
        finish(page, &scan, choice, opts, warnings)
    }

    /// Pages of `block` whose `bv` is confirmed without help from other pages:
    /// a trailer row-count match, or two or more agreeing exact sectors.
    /// Computed once per block and cached.
    fn block_anchors(&self, store: &PageStore, block: u64) -> Result<Arc<Vec<(u64, u8)>>> {
        let cached = self
            .blocks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&block)
            .cloned();
        if let Some(found) = cached {
            return Ok(found);
        }
        let mut found = Vec::new();
        let end = ((block + 1) * 16).min(store.page_count());
        // Page 0 is the plaintext superblock.
        for pn in (block * 16).max(1)..end {
            let page = store.page(pn)?;
            let raw = page.bytes();
            let scan = scan_page(raw, pn);
            if let Some(bv) = calibrated_bv(&scan, raw) {
                found.push((pn, bv));
            }
        }
        let found = Arc::new(found);
        self.blocks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(block, Arc::clone(&found));
        Ok(found)
    }

    /// Deobfuscate using an explicitly supplied `bv`.
    ///
    /// The caller is responsible for `bv`; it is not chosen or checked
    /// against the model, but [`DeobfuscatedPage::confidence`] and
    /// [`DeobfuscatedPage::evidence`] report whether the decoded page
    /// supports it. Sector steps are still determined and checked.
    pub fn deobfuscate_with_bv(
        page: Page<'_>,
        bv: u8,
        opts: &ReadOptions,
    ) -> Result<DeobfuscatedPage> {
        let raw = page.bytes();
        if raw.len() != PAGE_SIZE {
            return Err(Error::WrongBufferLength {
                expected: PAGE_SIZE,
                got: raw.len(),
            });
        }
        let pn = page.index();
        let scan = scan_page(raw, pn);
        let votes = exact_votes(raw, pn);
        let mut evidence = Vec::new();
        let mut confidence = Confidence::Unverified;
        if trailer_row_count_matches(&plaintext(&scan, raw, bv)) {
            evidence.push(Evidence::TrailerRowCount);
            confidence = Confidence::Verified;
        }
        let count = votes.get(&bv).copied().unwrap_or(0);
        if count >= MIN_EXACT_SECTORS {
            let dissent = votes.values().sum::<usize>() - count;
            evidence.push(Evidence::ExactSectors { count, dissent });
            confidence = confidence.max(Confidence::Calibrated);
        }
        let choice = Choice {
            bv,
            source: BvSource::Supplied,
            confidence,
            evidence,
        };
        finish(page, &scan, choice, opts, Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Choosing bv
// ---------------------------------------------------------------------------

struct Choice {
    bv: u8,
    source: BvSource,
    confidence: Confidence,
    evidence: Vec<Evidence>,
}

struct Candidate {
    bv: u8,
    zeros: u32,
    exact: usize,
    trailer: bool,
    anchor: bool,
}

impl Candidate {
    /// Rank used only when the caller allows an ambiguous page through:
    /// more independent evidence first, then more zeros, then the lowest
    /// `bv`. Greater is better.
    fn rank(&self) -> (u8, usize, u32, std::cmp::Reverse<u8>) {
        (
            self.trailer as u8 * 2 + self.anchor as u8,
            self.exact,
            self.zeros,
            std::cmp::Reverse(self.bv),
        )
    }
}

/// Votes and candidates for one page.
struct Assessment {
    /// Exact-sector votes: constant -> sector count.
    votes: BTreeMap<u8, usize>,
    exact_total: usize,
    /// Best histogram value, if any byte decodes at all.
    top: Option<u8>,
    cands: Vec<Candidate>,
}

fn assess(scan: &PageScan, raw: &[u8], anchors: &BTreeSet<u8>) -> Assessment {
    // Exact sectors: each votes for the constant its bytes decode to.
    let mut votes: BTreeMap<u8, usize> = BTreeMap::new();
    for s in scan.sectors.iter().filter(|s| s.is_exact()) {
        *votes.entry(s.m[0]).or_default() += 1;
    }
    let exact_total: usize = votes.values().sum();

    // Candidates: every exact constant plus the best histogram values.
    let mut by_zeros: Vec<u8> = (0..=255u8)
        .filter(|&v| scan.counts[v as usize] > 0)
        .collect();
    by_zeros.sort_by(|&a, &b| {
        scan.counts[b as usize]
            .cmp(&scan.counts[a as usize])
            .then(a.cmp(&b))
    });
    let top = by_zeros.first().copied();
    let mut bvs: BTreeSet<u8> = votes.keys().copied().collect();
    bvs.extend(by_zeros.iter().take(HISTOGRAM_CANDIDATES).copied());

    let has_count = raw[TRAILER_START] != 0;
    let cands = bvs
        .iter()
        .map(|&bv| Candidate {
            bv,
            zeros: scan.counts[bv as usize],
            exact: votes.get(&bv).copied().unwrap_or(0),
            trailer: has_count && trailer_row_count_matches(&plaintext(scan, raw, bv)),
            anchor: anchors.contains(&bv),
        })
        .collect();
    Assessment {
        votes,
        exact_total,
        top,
        cands,
    }
}

/// The `bv` a page confirms on its own: a unique trailer match, else two or
/// more agreeing exact sectors with no dissent.
fn calibrated_bv(scan: &PageScan, raw: &[u8]) -> Option<u8> {
    let a = assess(scan, raw, &BTreeSet::new());
    let verified: Vec<u8> = a.cands.iter().filter(|c| c.trailer).map(|c| c.bv).collect();
    match verified.as_slice() {
        [bv] => return Some(*bv),
        [] => {}
        _ => return None,
    }
    match a.votes.iter().next() {
        Some((&bv, &n)) if a.votes.len() == 1 && n >= MIN_EXACT_SECTORS => Some(bv),
        _ => None,
    }
}

fn choose_bv(
    scan: &PageScan,
    raw: &[u8],
    pn: u64,
    anchors: &BTreeSet<u8>,
    opts: &ReadOptions,
    warnings: &mut Vec<Warning>,
) -> Result<Choice> {
    let lenient = opts.leniency.contains(Leniency::KEYSTREAM);
    let Assessment {
        votes,
        exact_total,
        top,
        cands,
    } = assess(scan, raw, anchors);

    let evidence_for = |c: &Candidate| -> Vec<Evidence> {
        let mut ev = Vec::new();
        if c.trailer {
            ev.push(Evidence::TrailerRowCount);
        }
        if c.exact > 0 {
            ev.push(Evidence::ExactSectors {
                count: c.exact,
                dissent: exact_total - c.exact,
            });
        }
        if c.anchor {
            ev.push(Evidence::BlockAnchor);
        }
        let next = cands
            .iter()
            .filter(|o| o.bv != c.bv)
            .map(|o| o.zeros)
            .max()
            .unwrap_or(0);
        ev.push(Evidence::ZeroMass {
            zeros: c.zeros as usize,
            lead: c.zeros.saturating_sub(next) as usize,
        });
        ev
    };
    let pick = |c: &Candidate, source: BvSource, confidence: Confidence| Choice {
        bv: c.bv,
        source,
        confidence,
        evidence: evidence_for(c),
    };
    // Competing evidence: an error in strict mode, the best-ranked candidate
    // plus a warning otherwise.
    let ambiguous = |group: Vec<&Candidate>, warnings: &mut Vec<Warning>| -> Result<Choice> {
        let mut bvs: Vec<u8> = group.iter().map(|c| c.bv).collect();
        bvs.sort_unstable();
        if !lenient {
            return Err(Error::AmbiguousCalibration {
                page: pn,
                candidates: bvs,
            });
        }
        let best = group
            .iter()
            .copied()
            .max_by_key(|c| c.rank())
            .expect("ambiguity group is never empty");
        warnings.push(
            Warning::new(WarningKind::AmbiguousCalibration {
                chosen: best.bv,
                others: bvs.into_iter().filter(|&b| b != best.bv).collect(),
            })
            .on_page(pn),
        );
        Ok(pick(best, BvSource::Histogram, Confidence::Unverified))
    };

    // 1. A structural check against the plaintext trailer.
    let verified: Vec<&Candidate> = cands.iter().filter(|c| c.trailer).collect();
    match verified.len() {
        0 => {}
        1 => return Ok(pick(verified[0], BvSource::Verified, Confidence::Verified)),
        _ => return ambiguous(verified, warnings),
    }

    // 2. Exact sectors agreeing with each other.
    if votes.len() == 1 {
        let (&bv, &n) = votes.iter().next().expect("one vote entry");
        if n >= MIN_EXACT_SECTORS {
            let c = cands
                .iter()
                .find(|c| c.bv == bv)
                .expect("voted bv is a candidate");
            return Ok(pick(c, BvSource::ExactSectors, Confidence::Calibrated));
        }
    } else if votes.len() > 1 {
        // Exact sectors disagree. Another page's calibration may break the tie.
        let anchored: Vec<&Candidate> = cands.iter().filter(|c| c.exact > 0 && c.anchor).collect();
        if anchored.len() == 1 {
            return Ok(pick(
                anchored[0],
                BvSource::Verified,
                Confidence::Calibrated,
            ));
        }
        let group: Vec<&Candidate> = cands.iter().filter(|c| c.exact > 0).collect();
        return ambiguous(group, warnings);
    }

    // 3. The best histogram candidate, confirmed by a calibrated page in the
    //    same block.
    let top_cand = top.and_then(|t| cands.iter().find(|c| c.bv == t));
    let anchored_top: Vec<&Candidate> = top_cand.into_iter().filter(|c| c.anchor).collect();
    let other_anchored: Vec<&Candidate> = cands
        .iter()
        .filter(|c| c.anchor && Some(c.bv) != top)
        .collect();
    if let Some(c) = anchored_top.first() {
        if other_anchored.is_empty() {
            return Ok(pick(c, BvSource::Verified, Confidence::Calibrated));
        }
    }
    if !other_anchored.is_empty() && cands.len() > 1 {
        // The histogram and the block calibration point at different values.
        let mut group = other_anchored;
        group.extend(top_cand);
        return ambiguous(group, warnings);
    }

    // 4. Nothing confirms the best histogram candidate.
    let Some(c) = top_cand else {
        // Every data byte decoded to a value that is not a candidate: cannot
        // happen, a page always has data bytes.
        return Err(Error::KeystreamUnverified { page: pn, bv: 0 });
    };
    if !lenient {
        return Err(Error::KeystreamUnverified { page: pn, bv: c.bv });
    }
    warnings.push(Warning::new(WarningKind::UnverifiedKeystream { bv: c.bv }).on_page(pn));
    Ok(pick(c, BvSource::Histogram, Confidence::Unverified))
}

// ---------------------------------------------------------------------------
// Assembling the result
// ---------------------------------------------------------------------------

fn finish(
    page: Page<'_>,
    scan: &PageScan,
    choice: Choice,
    opts: &ReadOptions,
    mut warnings: Vec<Warning>,
) -> Result<DeobfuscatedPage> {
    let pn = page.index();
    let lenient = opts.leniency.contains(Leniency::KEYSTREAM);

    let mut sectors = [SectorFit {
        step: 0,
        peak: 0,
        runner_up: 0,
        exact: false,
    }; SECTORS_PER_PAGE];
    for (si, (fit, s)) in sectors.iter_mut().zip(&scan.sectors).enumerate() {
        *fit = SectorFit {
            step: s.step,
            peak: s.peak,
            runner_up: s.runner_up,
            exact: s.is_exact(),
        };
        if !fit.confident() {
            if !lenient {
                return Err(Error::LowConfidenceKeystream {
                    page: pn,
                    sector: si,
                    peak: s.peak,
                    runner_up: s.runner_up,
                });
            }
            warnings.push(
                Warning::new(WarningKind::LowConfidenceSector {
                    peak: s.peak,
                    runner_up: s.runner_up,
                })
                .on_page(pn)
                .on_sector(si),
            );
        }
    }

    let bytes = plaintext(scan, page.bytes(), choice.bv);
    debug_assert_eq!(bytes.len(), PAGE_SIZE);
    Ok(DeobfuscatedPage {
        index: pn,
        bytes,
        bv: choice.bv,
        bv_source: choice.source,
        confidence: choice.confidence,
        evidence: choice.evidence,
        sectors,
        warnings,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::PageTrailer;

    /// Deterministic pseudo-random bytes (xorshift), so dense plaintext in
    /// tests is the same on every run.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Steps used by the test encoder: distinct per sector, as in real files.
    fn test_step(pn: u64, si: usize) -> u8 {
        (pn as u8).wrapping_mul(37).wrapping_add(si as u8 * 29) | 1
    }

    /// Encode the data region of a page under `bv` and per-sector steps.
    /// `plaintext` must be exactly `TRAILER_START` bytes. The page-type byte
    /// and the count byte go into the plaintext trailer.
    fn encode_page(pn: u64, ptype: u8, count: u8, bv: u8, plaintext: &[u8]) -> Vec<u8> {
        assert_eq!(plaintext.len(), TRAILER_START);
        let mut out = vec![0u8; PAGE_SIZE];
        for si in 0..SECTORS_PER_PAGE {
            let (start, end) = sector_range(si);
            let offset = ap_offset(pn, si);
            let step = test_step(pn, si);
            for (i, &p) in plaintext[start..end].iter().enumerate() {
                out[start + i] = bv
                    .wrapping_add(offset)
                    .wrapping_add((i as u8).wrapping_mul(step))
                    .wrapping_add(p);
            }
        }
        out[TRAILER_START] = count;
        out[TRAILER_START + 2] = ptype;
        out
    }

    fn store_of(pages: &[Vec<u8>]) -> PageStore {
        PageStore::from_bytes(pages.concat()).unwrap()
    }

    /// A pure-AP page: all-zero plaintext.
    fn pure_page(pn: u64, bv: u8) -> Vec<u8> {
        encode_page(pn, b'C', 0, bv, &vec![0u8; TRAILER_START])
    }

    /// A page with a slotted-page prelude, a descending slot array and the
    /// matching trailer count, over `fill` bytes elsewhere.
    fn slotted_plaintext(count: u8, fill: u8) -> Vec<u8> {
        let mut p = vec![fill; TRAILER_START];
        let array_start = 0x76;
        p[0x70..0x72].copy_from_slice(&(count as u16).to_le_bytes());
        p[0x72..0x74].copy_from_slice(&1u16.to_le_bytes());
        p[0x74..0x76].copy_from_slice(&0u16.to_le_bytes());
        for k in 0..count as usize {
            let off = 0xF00u16 - 0x21 * k as u16;
            p[array_start + 2 * k..array_start + 2 * k + 2].copy_from_slice(&off.to_le_bytes());
        }
        // Zeros after the array so that zero is a candidate even when the
        // page is mostly padding.
        for b in &mut p[0x200..0x300] {
            *b = 0;
        }
        p
    }

    fn lenient_keystream() -> ReadOptions {
        ReadOptions::default().with_leniency(Leniency::KEYSTREAM)
    }

    #[test]
    fn ap_base_formula() {
        // pn=10, si=2, bv=0xC0: p16=10, bias=(10/2)*4=20,
        // base = (0xC0 + 10 + 2 - 20) mod 256 = 0xB8.
        assert_eq!(0xC0u8.wrapping_add(ap_offset(10, 2)), 0xB8);
        assert_eq!(ap_offset(0, 0), 0x00);
        assert_eq!(0x10u8.wrapping_add(ap_offset(16, 3)), 0x23);
    }

    #[test]
    fn exact_sector_is_found_and_unique() {
        let sec: Vec<u8> = (0..SECTOR_SIZE)
            .map(|i| 0x71u8.wrapping_add((i as u8).wrapping_mul(7)))
            .collect();
        assert_eq!(exact_sector(&sec, 0x11), Some((7, 0x71 - 0x11)));
        let mut broken = sec.clone();
        broken[100] ^= 1;
        assert_eq!(exact_sector(&broken, 0x11), None);
    }

    #[test]
    fn scan_sector_recovers_step_with_a_clear_lead() {
        let mut plain = vec![0u8; SECTOR_SIZE];
        plain[..40].copy_from_slice(&noise(3, 40));
        let stored: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                0x55u8
                    .wrapping_add((i as u8).wrapping_mul(19))
                    .wrapping_add(p)
            })
            .collect();
        let scan = scan_sector(&stored, 0);
        assert_eq!(scan.step, 19);
        assert!(scan.peak >= 460);
        assert!(scan.peak > scan.runner_up + MIN_STEP_LEAD);
    }

    #[test]
    fn deobfuscate_uses_per_page_bv_not_block_bv() {
        // Block 0: page 0 calibrates with bv=10; page 1 is a pure page whose
        // true bv is 200. A block-level bv would decode page 1 wrongly.
        let store = store_of(&[pure_page(0, 10), pure_page(1, 200)]);
        let strict = ReadOptions::default();
        let model = ApModel::learn(&store, &strict).unwrap();
        assert_eq!(model.learned_block_count(), 1);
        assert_eq!(model.report().calibrated_pages(), 2);

        let page = model.deobfuscate(&store, 1, &strict).unwrap();
        assert_eq!(page.bv(), 200);
        assert_eq!(page.confidence(), Confidence::Calibrated);
        assert!(page.bytes()[..TRAILER_START].iter().all(|&b| b == 0));
        assert!(page.warnings().is_empty());
    }

    #[test]
    fn random_plaintext_is_low_confidence_not_garbage() {
        // Audit finding 1: with the correct bv, a page of random plaintext
        // decoded all 8 sectors wrongly and said nothing.
        let raw = encode_page(1, b'E', 0, 77, &noise(11, TRAILER_START));
        let page = Page::from_bytes(1, &raw).unwrap();

        let err = ApModel::deobfuscate_with_bv(page, 77, &ReadOptions::default()).unwrap_err();
        assert!(
            matches!(
                err,
                Error::LowConfidenceKeystream {
                    page: 1,
                    sector: 0,
                    ..
                }
            ),
            "{err:?}"
        );

        let lenient = ApModel::deobfuscate_with_bv(page, 77, &lenient_keystream()).unwrap();
        assert_eq!(lenient.warnings().len(), SECTORS_PER_PAGE);
        assert!(lenient.sectors().iter().all(|s| !s.confident()));
        assert!(
            lenient
                .warnings()
                .iter()
                .all(|w| matches!(w.kind, WarningKind::LowConfidenceSector { .. }))
        );
    }

    #[test]
    fn zero_padded_page_reports_clear_step_fits() {
        let mut plain = vec![0u8; TRAILER_START];
        plain[0x100..0x180].copy_from_slice(&noise(5, 0x80));
        let raw = encode_page(3, b'E', 0, 9, &plain);
        let page = Page::from_bytes(3, &raw).unwrap();
        let out = ApModel::deobfuscate_with_bv(page, 9, &ReadOptions::default()).unwrap();
        assert_eq!(&out.bytes()[..TRAILER_START], &plain[..]);
        for (si, fit) in out.sectors().iter().enumerate() {
            assert_eq!(fit.step(), test_step(3, si));
            assert!(fit.confident());
        }
    }

    #[test]
    fn space_padded_page_with_a_zero_region_is_ambiguous() {
        // Audit finding 2: two thirds of the bytes are 0x20, so the
        // histogram's best candidate is bv + 0x20 and every plaintext byte
        // came out shifted, silently.
        let mut plain = vec![0x20u8; TRAILER_START];
        for b in &mut plain[0x400..0x600] {
            *b = 0;
        }
        let raw = encode_page(1, b'E', 0, 77, &plain);
        let store = store_of(&[pure_page(0, 5), raw]);
        let model = ApModel::learn(&store, &ReadOptions::default()).unwrap();

        let err = model
            .deobfuscate(&store, 1, &ReadOptions::default())
            .unwrap_err();
        assert!(
            matches!(&err, Error::AmbiguousCalibration { page: 1, candidates } if candidates == &vec![77, 77 + 0x20]),
            "{err:?}"
        );

        let lenient = model.deobfuscate(&store, 1, &lenient_keystream()).unwrap();
        assert_eq!(lenient.confidence(), Confidence::Unverified);
        assert!(matches!(
            lenient.warnings()[0].kind,
            WarningKind::AmbiguousCalibration { .. }
        ));
    }

    #[test]
    fn space_padded_page_without_other_evidence_is_unverified() {
        let mut plain = vec![0x20u8; TRAILER_START];
        for si in 0..SECTORS_PER_PAGE {
            let (start, _) = sector_range(si);
            plain[start..start + 60].copy_from_slice(&noise(40 + si as u64, 60));
        }
        let raw = encode_page(1, b'E', 0, 77, &plain);
        let store = store_of(&[pure_page(0, 5), raw]);
        let model = ApModel::learn(&store, &ReadOptions::default()).unwrap();
        let err = model
            .deobfuscate(&store, 1, &ReadOptions::default())
            .unwrap_err();
        assert!(
            matches!(err, Error::KeystreamUnverified { page: 1, bv } if bv == 77 + 0x20),
            "{err:?}"
        );
        let lenient = model.deobfuscate(&store, 1, &lenient_keystream()).unwrap();
        assert!(matches!(
            lenient.warnings()[0].kind,
            WarningKind::UnverifiedKeystream { .. }
        ));
    }

    #[test]
    fn trailer_row_count_rescues_a_space_padded_page() {
        // The same kind of page, but with a slotted prelude whose count
        // matches the plaintext trailer: that confirms the true bv even
        // though the histogram prefers bv + 0x20.
        let plain = slotted_plaintext(12, 0x20);
        let raw = encode_page(1, b'E', 12, 77, &plain);
        let store = store_of(&[pure_page(0, 5), raw]);
        let model = ApModel::learn(&store, &ReadOptions::default()).unwrap();
        let out = model
            .deobfuscate(&store, 1, &ReadOptions::default())
            .unwrap();
        assert_eq!(out.bv(), 77);
        assert_eq!(out.confidence(), Confidence::Verified);
        assert!(out.evidence().contains(&Evidence::TrailerRowCount));
        assert_eq!(&out.bytes()[..TRAILER_START], &plain[..]);
    }

    #[test]
    fn disagreeing_exact_sectors_are_ambiguous_and_deterministic() {
        // Audit finding 3: sectors 0-3 decode to zero, sectors 4-7 to the
        // constant 0xEF. Both groups are exact AP progressions; the old code
        // broke the 4-4 tie by hash order, so repeated runs disagreed.
        let mut plain = vec![0u8; TRAILER_START];
        for b in &mut plain[4 * SECTOR_SIZE..] {
            *b = 0xEF;
        }
        let raw = encode_page(1, b'C', 0, 40, &plain);
        let store = store_of(&[pure_page(0, 5), raw]);
        let model = ApModel::learn(&store, &lenient_keystream()).unwrap();
        assert_eq!(model.report().ambiguous_pages(), 1);

        let strict = ReadOptions::default();
        for _ in 0..20 {
            let err = model.deobfuscate(&store, 1, &strict).unwrap_err();
            match err {
                Error::AmbiguousCalibration {
                    page: 1,
                    candidates,
                } => {
                    assert_eq!(candidates, vec![40u8.wrapping_add(0xEF), 40]);
                }
                other => panic!("expected AmbiguousCalibration, got {other:?}"),
            }
        }

        let first = model.deobfuscate(&store, 1, &lenient_keystream()).unwrap();
        for _ in 0..20 {
            let again = model.deobfuscate(&store, 1, &lenient_keystream()).unwrap();
            assert_eq!(again.bv(), first.bv());
            assert_eq!(again.bytes(), first.bytes());
        }
        assert!(matches!(
            first.warnings()[0].kind,
            WarningKind::AmbiguousCalibration { .. }
        ));
    }

    #[test]
    fn learn_without_pure_pages_is_no_calibration() {
        // Audit finding 4: learn always succeeded and fell back to bv 0.
        let dense = encode_page(1, b'E', 0, 3, &noise(2, TRAILER_START));
        let store = store_of(&[vec![7u8; PAGE_SIZE], dense]);
        let err = ApModel::learn(&store, &ReadOptions::default()).unwrap_err();
        assert!(matches!(err, Error::NoCalibration), "{err:?}");

        let model = ApModel::learn(&store, &lenient_keystream()).unwrap();
        assert_eq!(model.report().warnings().len(), 1);
    }

    #[test]
    fn learn_on_a_plaintext_store_is_not_obfuscated() {
        // Audit finding 4: a plaintext store passed through learn produced
        // garbage from an all-zero page.
        let mut page = vec![0u8; PAGE_SIZE];
        page[TRAILER_START + 2] = b'C';
        let store = store_of(&[page.clone(), page.clone(), page]);
        let err = ApModel::learn(&store, &ReadOptions::default()).unwrap_err();
        assert!(matches!(err, Error::NotObfuscated), "{err:?}");
    }

    #[test]
    fn lowercase_pure_pages_calibrate() {
        // Audit finding 17: calibration compared the raw type byte, so
        // lowercase pure pages were skipped without being counted.
        let raw = encode_page(1, b'c', 0, 9, &vec![0u8; TRAILER_START]);
        let store = store_of(&[pure_page(0, 9), raw]);
        let model = ApModel::learn(&store, &ReadOptions::default()).unwrap();
        assert_eq!(model.report().pure_pages(), 2);
        assert_eq!(model.report().calibrated_pages(), 2);
    }

    #[test]
    fn page_out_of_range_is_an_error_not_bv_zero() {
        // Audit finding 5: pn beyond the store silently used bv0.
        let store = store_of(&[pure_page(0, 9), pure_page(1, 9)]);
        let model = ApModel::learn(&store, &ReadOptions::default()).unwrap();
        let err = model
            .deobfuscate(&store, 99, &ReadOptions::default())
            .unwrap_err();
        assert!(matches!(err, Error::PageOutOfRange { page: 99, total: 2 }));
    }

    #[test]
    fn a_model_rejects_a_different_store() {
        // Audit finding 5: the bytes decoded and the store used for
        // calibration could differ without notice.
        let a = store_of(&[pure_page(0, 9), pure_page(1, 9)]);
        let b = store_of(&[pure_page(0, 9), pure_page(1, 10), pure_page(2, 9)]);
        let model = ApModel::learn(&a, &ReadOptions::default()).unwrap();
        assert!(matches!(
            model.deobfuscate(&b, 1, &lenient_keystream()),
            Err(Error::StoreMismatch)
        ));
    }

    #[test]
    fn block_anchor_confirms_a_page_with_no_other_evidence() {
        // Dense-ish pages (noise at the start of every sector, zeros after):
        // no exact sector, no prelude. One whose best histogram bv equals the
        // bv of a calibrated page in the same block is Calibrated; one that
        // disagrees stays Unverified.
        let mut plain = vec![0u8; TRAILER_START];
        for si in 0..SECTORS_PER_PAGE {
            let (start, _) = sector_range(si);
            plain[start..start + 100].copy_from_slice(&noise(9 + si as u64, 100));
        }
        let agree = encode_page(2, b'E', 0, 40, &plain);
        let disagree = encode_page(3, b'E', 0, 41, &plain);
        let store = store_of(&[pure_page(0, 5), pure_page(1, 40), agree, disagree]);
        let model = ApModel::learn(&store, &ReadOptions::default()).unwrap();

        let ok = model
            .deobfuscate(&store, 2, &ReadOptions::default())
            .unwrap();
        assert_eq!(ok.bv(), 40);
        assert!(ok.evidence().contains(&Evidence::BlockAnchor));
        assert_eq!(ok.confidence(), Confidence::Calibrated);

        let err = model
            .deobfuscate(&store, 3, &ReadOptions::default())
            .unwrap_err();
        assert!(matches!(
            err,
            Error::KeystreamUnverified { page: 3, bv: 41 }
        ));
        let other = model.deobfuscate(&store, 3, &lenient_keystream()).unwrap();
        assert_eq!(other.confidence(), Confidence::Unverified);
    }

    #[test]
    fn deobfuscation_is_deterministic() {
        let plain = slotted_plaintext(9, 0);
        let raw = encode_page(2, b'E', 9, 200, &plain);
        let store = store_of(&[pure_page(0, 3), pure_page(1, 4), raw]);
        let model = ApModel::learn(&store, &ReadOptions::default()).unwrap();
        let first = model
            .deobfuscate(&store, 2, &ReadOptions::default())
            .unwrap();
        for _ in 0..20 {
            let again = model
                .deobfuscate(&store, 2, &ReadOptions::default())
                .unwrap();
            assert_eq!(again.bytes(), first.bytes());
            assert_eq!(again.bv(), first.bv());
        }
    }

    #[test]
    fn supplied_bv_reports_its_support() {
        let plain = slotted_plaintext(12, 0);
        let raw = encode_page(2, b'E', 12, 77, &plain);
        let page = Page::from_bytes(2, &raw).unwrap();
        let right = ApModel::deobfuscate_with_bv(page, 77, &ReadOptions::default()).unwrap();
        assert_eq!(right.confidence(), Confidence::Verified);
        assert_eq!(right.bv_source(), BvSource::Supplied);
        let wrong = ApModel::deobfuscate_with_bv(page, 78, &ReadOptions::default()).unwrap();
        assert_eq!(wrong.confidence(), Confidence::Unverified);
    }

    #[test]
    fn trailer_view_is_untouched() {
        let raw = encode_page(1, b'E', 4, 9, &vec![0u8; TRAILER_START]);
        let page = Page::from_bytes(1, &raw).unwrap();
        let out = ApModel::deobfuscate_with_bv(page, 9, &ReadOptions::default()).unwrap();
        let t: PageTrailer = out.as_page().trailer();
        assert_eq!(t.raw(), page.trailer().raw());
        assert_eq!(&out.bytes()[TRAILER_START..], &raw[TRAILER_START..]);
    }
}
