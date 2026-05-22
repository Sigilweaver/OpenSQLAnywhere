# OpenSQLAnywhere

[![CI](https://github.com/Sigilweaver/OpenSQLAnywhere/actions/workflows/ci.yml/badge.svg)](https://github.com/Sigilweaver/OpenSQLAnywhere/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust MSRV](https://img.shields.io/badge/rust-1.87%2B-orange.svg)](https://www.rust-lang.org)
[![Docs](https://img.shields.io/badge/docs-sigilweaver.app-blue.svg)](https://sigilweaver.app/opensqlanywhere/docs/)

A reader and open specification for the SAP SQL Anywhere on-disk
page-store format.

The current implementation targets SA17 (build 2182, 2015 release).
The goal is to make it possible to read an SQL Anywhere database
file without the SAP server being present or installed.

OpenSQLAnywhere is clean-room: it is derived from observation of the
on-disk bytes of SQL Anywhere files and from SAP's own public
documentation. It ships with no SAP code or binaries.

```
OpenSQLAnywhere/
├── Cargo.toml              workspace manifest
├── SPECIFICATION.md        format specification
├── crates/
│   ├── opensqlany/         the library crate
│   └── opensqlany-cli/     the `opensqlany` command-line tool
└── LICENSE
```

## Layout

```toml
[dependencies]
opensqlany = "0.1"
```

```rust
use opensqlany::PageStore;

let store = PageStore::open("database.db")?;
let sb = store.superblock()?;
println!("format {}.{}.{}", sb.format_major, sb.version_a, sb.version_b);

for page in store.pages().skip(1) {
    page.verify_crc()?;
    let t = page.trailer();
    println!("page {} type {:?}", page.index(), t.page_type());
}
# Ok::<(), opensqlany::Error>(())
```

## Using the CLI

```console
$ opensqlany inspect database.db --verify-crc
file              : database.db
size              : 14282752 B (3487 pages of 4096)
superblock magic  : 0xDA7ABA5E  OK
format triple     : 3.201.12
page_count_hint   : 3359 (total - hint = 128)
...
page-type histogram:
  0x41 'A'  alloc           1858   53.3%
  0x45 'E'  extent          1531   43.9%
  0x43 'C'  catalog           66    1.9%
  ...

$ opensqlany dump-page database.db 0
$ opensqlany slots database.db 2
```

## Relationship to OpenQBW

Intuit QuickBooks `.QBW` company files are SA17 page stores with a
deterministic additive-progression obfuscation applied on top. This crate
includes an [`ApModel`] that removes that obfuscation before handing
plaintext pages to the rest of the API. The companion project **OpenQBW**
builds on top of this crate to expose the QuickBooks-specific business-object
layer.

## License

[Apache-2.0](LICENSE).
