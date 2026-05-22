---
title: Rust quickstart
sidebar_label: Rust quickstart
---

# Rust quickstart

Open a page-store file and walk every page, verifying CRC trailers:

```rust
use opensqlany::PageStore;

fn main() -> Result<(), opensqlany::Error> {
    let store = PageStore::open("database.db")?;

    let sb = store.superblock()?;
    println!("format {}.{}.{}", sb.format_major, sb.version_a, sb.version_b);

    for page in store.pages().skip(1) {
        page.verify_crc()?;
        let t = page.trailer();
        println!("page {} type {:?}", page.index(), t.page_type());
    }

    Ok(())
}
```

## Working with deobfuscated input

If your input is a QuickBooks `.QBW` file, peel the additive-progression
layer off first:

```rust
use opensqlany::{ApModel, PageStore};

let raw = std::fs::read("Company.QBW")?;
let model = ApModel::detect(&raw)?;
let plaintext = model.deobfuscate(raw);
let store = PageStore::from_bytes(plaintext)?;
// ...same iteration as above
# Ok::<(), opensqlany::Error>(())
```

See [AP deobfuscation](./ap-deobfuscation.md) for the format details.
