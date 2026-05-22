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

## Detecting an AP-obfuscated file

```rust
use opensqlany::{ApModel, PageStore};

let raw = std::fs::read("Company.QBW")?;

match ApModel::detect(&raw) {
    Ok(model) => {
        let plain = model.deobfuscate(raw);
        let store = PageStore::from_bytes(plain)?;
        // proceed as for a plaintext SA17 file
    }
    Err(_) => {
        // not AP-obfuscated; try as plaintext
        let store = PageStore::from_bytes(raw)?;
    }
}
# Ok::<(), opensqlany::Error>(())
```

`ApModel::detect` returns an error if no plausible keystream is
found in the first few hundred bytes (specifically, if the
superblock magic `0xDA7ABA5E` doesn't reappear under any of the
candidate additive progressions).

## Companion: OpenQBW

[OpenQBW](https://sigilweaver.app/openqbw/docs/) is the companion
project that builds the QuickBooks business-object layer on top.
It uses `ApModel` for the obfuscation peel, then drives
`opensqlany` for the page walk, then layers Intuit's schema on
top of the resulting catalog rows.

## Full algorithm

See [Specification](./specification.md), section "AP keystream",
for the byte-level derivation of the keystream from the file header.
