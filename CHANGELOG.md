# Changelog

All notable changes to this project will be documented here. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Sigilweaver/OpenSQLAnywhere/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Sigilweaver/OpenSQLAnywhere/releases/tag/v0.1.1
[0.1.0]: https://github.com/Sigilweaver/OpenSQLAnywhere/releases/tag/v0.1.0
