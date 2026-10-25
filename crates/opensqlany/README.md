# opensqlany

A Rust library for reading SAP SQL Anywhere on-disk page-store files.

Targets SA17 (build 2182, 2015 release). The implementation is based on
clean-room observation of the on-disk format and SAP's public documentation.
No SAP code or binaries are included.

```toml
[dependencies]
opensqlany = "0.2"
```

## What it does

- Open any SA17 `.db` or `.qbw` file
- Iterate over 4 KiB pages
- Validate per-page CRC-32 footers
- Classify pages by type (`'E'` extent, `'A'` alloc, `'I'` index, ...)
- Parse the superblock (magic, format version triple)
- Parse slotted-page row directories (`'E'` and `'C'` pages)
- Remove the additive-progression (AP) fill obfuscation used in QuickBooks `.qbw` files

## Quick start

```rust
use opensqlany::{ApModel, PageStore, ReadOptions};

let store = PageStore::open("company.qbw")?;
let opts = ReadOptions::default(); // strict: errors on anything unconfirmed
let model = ApModel::learn(&store, &opts)?;

for page in store.pages().skip(1) {
    let page = page?;
    page.verify_crc()?;
    let plain = model.deobfuscate(&store, page.index(), &opts)?;
    println!("page {} type {:?}", page.index(), plain.as_page().trailer().page_type());
}
# Ok::<(), opensqlany::Error>(())
```

## Scope

This crate covers the **page-store layer**: opening, iterating, CRC validation,
page-type classification, slotted-page directory parsing, and AP
deobfuscation.

System catalog parsing (`SYSTABLE` / `SYSCOLUMN` / `SYSINDEX`),
B-tree traversal, and typed row decoding are planned for a later release.

## License

[Apache-2.0](../../LICENSE).
