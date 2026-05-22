# Contributing to OpenSQLAnywhere

Thanks for your interest. OpenSQLAnywhere is a clean-room Rust reader
for SAP SQL Anywhere database files, focused on the format variants
that QuickBooks Desktop embeds.

## Scope

We only accept contributions that target the **on-disk file format**
of databases that the lawful owner can already open. We do **not**
accept:

- Code or assets derived from disassembled SAP binaries.
- Password recovery or DRM bypass tools.
- Anything that ships SAP trademarks or copyrighted content.

## Workflow

1. Open an issue describing what you want to change.
2. Fork and branch from `main`.
3. Run `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
   and `cargo test --workspace` before pushing.
4. Open a pull request.

## Licensing

By submitting a contribution, you agree it is licensed under the
Apache License, Version 2.0 (the same license as the rest of the
project). See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
