---
title: AP deobfuscation
sidebar_label: AP deobfuscation
---

# Additive-progression deobfuscation

Some SA17-derived stores ship with an extra obfuscation pass on top
of the page-store layer. The most prominent example is the Intuit
QuickBooks Desktop `.QBW` format, which is an SA17 page store with
a deterministic additive-progression keystream XORed across each
page.

`opensqlany::ApModel` is the in-memory adapter that peels this
layer off. It does not commit the result to disk and does not break
any DRM - the obfuscation is a public, deterministic byte
transformation that the lawful owner of the file can already
reverse via the QuickBooks application.

## Peeling the AP layer off

```rust
use opensqlany::{ApModel, PageStore};

let store = PageStore::open("Company.QBW")?;
let model = ApModel::learn(&store);

let page = store.page(1)?;
let plain = model.deobfuscate_with_store(page.bytes(), page.index(), &store);
// `plain` is now SA17 plaintext for this page; proceed as for a
// plaintext SA17 file (e.g. feed it to `SlottedPage::parse` via
// `Page::from_bytes`).
# Ok::<(), opensqlany::Error>(())
```

`ApModel::learn` scans every "pure-AP" page in the store (page types
`'@'`, `'C'`, `'H'`, `'M'`) to calibrate the per-block `bv` value used
by the keystream formula below. It always succeeds - there is no
separate detection step. Use the CLI's `ap-info` subcommand to check
how many blocks were calibrated directly (`learned_block_count`) versus
falling back to on-demand recovery (`deobfuscate_with_store`) or the
block-0 approximation (`deobfuscate`).

`bv` is constant per 16-page block on the original corpus, but not on
every file - some QuickBooks Enterprise 24.0 files vary `bv` from page
to page within a block. `deobfuscate_with_store` always resolves `bv`
for the specific page being decoded rather than trusting its block's
learned value, so it stays correct either way; only the cheaper
block-only `deobfuscate` is affected by this.

## Companion: OpenQBW

[OpenQBW](https://sigilweaver.app/openqbw/docs/) is the companion
project that builds the QuickBooks business-object layer on top.
It uses `ApModel` for the obfuscation peel, then drives
`opensqlany` for the page walk, then layers Intuit's schema on
top of the resulting catalog rows.

## Full algorithm

See [Specification](./specification.md), section "AP keystream",
for the byte-level derivation of the keystream from the file header.
