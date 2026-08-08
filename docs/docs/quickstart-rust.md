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
layer off per page before parsing it:

```rust
use opensqlany::{ApModel, PageStore};

let store = PageStore::open("Company.QBW")?;
let model = ApModel::learn(&store);

for page in store.pages().skip(1) {
    let plain = model.deobfuscate_with_store(page.bytes(), page.index(), &store);
    let page_type = opensqlany::PageType::from_byte(plain[0xFF2]);
    println!("page {} type {:?}", page.index(), page_type);
    // ...pass `plain` to opensqlany::Page::from_bytes / SlottedPage::parse
}
# Ok::<(), opensqlany::Error>(())
```

See [AP deobfuscation](./ap-deobfuscation.md) for the format details.
