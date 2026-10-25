# Changelog

All notable changes to this project will be documented here. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- AP deobfuscation no longer guesses. `bv` and each sector's step are chosen
  deterministically and accepted only with confirming evidence; otherwise
  `ApModel::deobfuscate` returns `Error::KeystreamUnverified`,
  `Error::AmbiguousCalibration` or `Error::LowConfidenceKeystream`, or under
  `Leniency::KEYSTREAM` flags the result with a `Warning`. Previously a
  tie between calibration votes was broken by hash order (the same page
  decoded two different ways in 10 of 20 runs), a page whose padding is not
  zero decoded shifted by a constant, and a sector with no dominant byte
  decoded to garbage, all without any signal.
- `ApModel::learn` returns `Error::NoCalibration` or `Error::NotObfuscated`
  instead of falling back to `bv = 0`, and counts lowercase pure-AP pages
  (`'c'`, `'h'`, `'m'`, `` '`' ``) as calibration input.
- `ApModel::deobfuscate` takes the page from the store it decodes, so
  `raw` and `pn` can no longer disagree, and returns `Error::PageOutOfRange`
  and `Error::StoreMismatch` instead of substituting `bv = 0`.

### Added

- `DeobfuscatedPage::confidence()` (`Confidence`), `evidence()` (`Evidence`)
  and `SectorFit::{exact, confident}`.
- `Evidence::TrailerRowCount`: the row count in a slotted page's prelude
  must equal the plaintext trailer's count byte (`0xFF0`). It is the
  independent check that confirms `bv` on pages whose padding is not zero.
  It needs a count of four or more, and a page where exact sectors or a
  block anchor point at another `bv` is `AmbiguousCalibration`.
- `DeobfuscatedPage::unallocated()`: an all-zero page was never written and
  is returned as it is, with `BvSource::Unallocated`, instead of being run
  through the keystream guesser.
- `ApModel::deobfuscate_with_bv` refuses a `bv` that the page does not
  support (`KeystreamUnverified`, or a warning under `Leniency::KEYSTREAM`).

### Behavior changes

- Strict decoding rejects pages that decoded silently before. On the
  112-file corpus, 82 % of `A` pages and 26 % of `E` pages decode in strict
  mode; the rest need `Leniency::KEYSTREAM`, which reports the affected
  sectors. A calibrated page elsewhere in the same 16-page block with the
  same `bv` is reported (`Evidence::BlockAnchor`) but is not confirmation:
  about a third of blocks hold more than one `bv`. See the pull request for
  the breakdown by error kind.
- `BvSource` is `TrailerRowCount`, `ExactSectors`, `Histogram`, `Supplied` or
  `Unallocated`; `Confidence::Verified` means only the trailer check (or an
  unallocated page).

### Changed

- **Breaking:** the API is reshaped so later fixes ship without another
  major release.
  - `Error` is `#[non_exhaustive]`, gains `Error::kind() -> ErrorKind` and
    `Error::page()`, and carries the variants the decoders report:
    `ShortRead`, `WrongBufferLength`, `UnsupportedVersion`, `NoCalibration`,
    `NotObfuscated`, `LowConfidenceKeystream`, `AmbiguousCalibration`,
    `KeystreamUnverified`, `SlotOffsetInDirectory`, `AmbiguousSlotDirectory`,
    `SlotDirectoryTruncated`, `UnknownPrelude` and `NoSlotDirectory`.
  - New `ReadOptions` (strict by default) with one extensible `Leniency`
    set, and new `Warning` / `WarningKind` for conditions a lenient read
    accepted.
  - `ApModel::learn`, `ApModel::deobfuscate` (formerly
    `deobfuscate_with_store`), `ApModel::deobfuscate_with_bv` and
    `SlottedPage::parse` take `&ReadOptions` and return `Result`.
    Deobfuscation returns a `DeobfuscatedPage` (plaintext, `bv`, per-sector
    `SectorFit`, warnings) instead of a bare `Vec<u8>`.
  - `SlottedPage::row_bytes` becomes `SlottedPage::rows`, returning `Row`
    values with an `exact` flag instead of `(u16, &[u8])` tuples.
  - `PageStore::pages` yields `Result<Page>`.
  - `Page::from_bytes` and `Superblock::parse` return `Result` instead of
    panicking on a wrong-length buffer, and `Page::from_bytes` no longer
    truncates a longer buffer.
  - `PageTrailer`, `Superblock`, `SlotDirectory` and `SlottedPage` have
    private fields with accessors (`PageTrailer::raw()` returns the 12
    trailer bytes). `PageTrailer::case_variant()` reports the lowercase
    page-type bit.
  - Struct-like variants of `Error` and `WarningKind` are
    `#[non_exhaustive]`: match them with `..`.
  - `WarningKind` has a typed variant for every condition the crate reports;
    `WarningKind::Other` is for dependent crates. `Warning::new`, `on_page`
    and `on_sector` are public.
  - `ReadOptions::lenient()` relaxes exactly `KEYSTREAM`, `DIRECTORY`,
    `INTEGRITY` and `FORMAT`; a flag added later is not added to it.
    `ReadOptions::widest()` and `Leniency::every_known()` widen with each
    release.
  - `WrongBufferLength` and `PageOutOfRange` have kind `ErrorKind::Usage`.
  - `PageType` is `#[non_exhaustive]`; `PageType::UnknownG` is removed and
    `'G'` classifies as `PageType::Other(b'G')`.
  - New `Superblock::format() -> FormatVersion`.
  - The calibration helpers `ApModel::bv_at`, `deobfuscate` (block
    level), `recover_bv_for_block` and `recover_bv_for_page` are removed,
    along with `Default for ApModel`; they guessed a key silently.
  - `SlottedPage::overflow_prefix` is removed: it returned the page prelude
    as if it were record data.

## [0.2.0] - 2026-09-09

### Changed

- **Breaking:** the page trailer's `0xFF4..0xFF8` region is a 32-bit
  little-endian log sequence number, not two loose metadata bytes
  followed by six reserved-zero bytes. `PageTrailer::meta_ff4`,
  `meta_ff5` and `zero_ff6` are replaced by `PageTrailer::lsn: u32` and
  `PageTrailer::zero_ff8: [u8; 4]`, and `Superblock::file_id_lo` is
  renamed `Superblock::current_lsn` - it is the file's current LSN, not
  the low half of a per-file identifier. Three in-file relationships
  support the reading: the highest per-page LSN is exactly ten less than
  the superblock value on every file measured, superblock `0x0C` (which a
  64-bit identifier would need) is always zero, and pages carrying the
  `0x20` case bit have a substantially newer LSN distribution. Documented
  in `SPECIFICATION.md` §2.2a and §3.1a. Fixes #7, reported with the
  supporting measurements by @pete-green.
- `opensqlany inspect` prints the superblock LSN in place of `file_id`,
  and `dump-page` prints the page LSN in place of the two `meta` bytes.

### Added

- `Page::lsn()`, shorthand for `page.trailer().lsn`.

### Fixed

- `verify_trailer` rejected valid pages once a file's LSN passed 65 535,
  because bytes `0xFF6..0xFF7` - the high half of the LSN - were checked
  as reserved-zero. They read as zero across the original 112-file
  corpus only because none of those files had an LSN that large. The
  reserved regions checked are now `0xFF3` and `0xFF8..0xFFB`.

## [0.1.1] - 2026-08-12

### Added

- `Superblock::flags_06_variant_bits` and `FLAGS_06_BASE`. `flags_06`
  (superblock offset `0x06`) was documented as one of two magic values
  (`0x09`/`0x49`); a QuickBooks Enterprise 24.0 file adds a third, `0x29`,
  which is `0x09 | 0x20` - the same bit-6 relationship the original
  `0x49 = 0x09 | 0x40` already had. Exposes it as a bitfield over
  `FLAGS_06_BASE` instead, so a future edition setting another bit doesn't
  need a new literal-match arm. What each bit means is still unknown.
  Reported against [openqbw#16](https://github.com/Sigilweaver/OpenQBW/issues/16)
  by @pete-green.

### Fixed

- `PageType::from_byte` only classified uppercase page-type bytes. A
  QuickBooks Desktop Enterprise 24.0 file carries the same page types in
  **lowercase** (`'e'` 0x65 instead of `'E'` 0x45) on otherwise-ordinary
  extent/data pages; every consumer filtering on `PageType::Extent` (e.g.
  `openqbw`'s SYSTABLE walk) silently skipped the entire data population
  since they all landed in `PageType::Other(0x65)` instead. Classification
  is now case-insensitive; the raw byte (case included) is still preserved
  in `Other(_)` since the case bit itself may be meaningful. Fixes #8
  (finding 1). Reported by @pete-green.
- `ApModel::deobfuscate_with_store` trusted a single `bv` learned per
  16-page block, applying it to every page in the block. That assumption
  doesn't hold on the same Enterprise 24.0 file: across 2,920 sampled
  pages, 394/439 blocks showed 6-8 distinct per-page `bv` values, so a
  block's learned value (from whichever pure-AP page happened to be in
  it) was silently wrong for most of the block's dense data pages. Added
  `ApModel::recover_bv_for_page` (the same histogram-peak brute-force
  search as `recover_bv_for_block`, scoped to one page) and switched
  `deobfuscate_with_store` to resolve `bv` per page unconditionally
  instead of trusting the block-level value. `recover_bv_for_block` and
  the rest of the block-level API are unchanged, for callers that
  specifically want the cheaper approximation. Fixes #8 (finding 2).
  Reported by @pete-green.

## [0.1.0] - 2026-05-22

First publication-ready release.

### Added

- `opensqlany` library: `PageStore`, `Superblock`, `Page`, slotted-page
  parsing, CRC verification, and `ApModel` for the additive-progression
  deobfuscation layer used by QuickBooks `.QBW` files.
- `opensqlany` CLI binary: `inspect`, `dump-page`, `slots` subcommands
  against a page-store file.
- `SPECIFICATION.md` covering the SA17 (build 2182, 2015) on-disk
  page-store format derived from clean-room observation and SAP public
  documentation.
- Workspace metadata, MSRV 1.87, `unsafe_code = "forbid"`.
- CI matrix (Linux + macOS + Windows): `cargo fmt`, `cargo clippy
  --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Tag-triggered crates.io release workflow (`opensqlany` then
  `opensqlany-cli`) via trusted publishing.
- `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`.
- Documentation site at <https://sigilweaver.app/opensqlanywhere/docs/>.

[Unreleased]: https://github.com/Sigilweaver/OpenSQLAnywhere/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Sigilweaver/OpenSQLAnywhere/releases/tag/v0.2.0
[0.1.1]: https://github.com/Sigilweaver/OpenSQLAnywhere/releases/tag/v0.1.1
[0.1.0]: https://github.com/Sigilweaver/OpenSQLAnywhere/releases/tag/v0.1.0
