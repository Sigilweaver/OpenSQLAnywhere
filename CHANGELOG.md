# Changelog

All notable changes to this project will be documented here. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Sigilweaver/OpenSQLAnywhere/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Sigilweaver/OpenSQLAnywhere/releases/tag/v0.1.0
