---
title: Install
sidebar_label: Install
---

# Install

## Rust library

Add to your `Cargo.toml`:

```toml
[dependencies]
opensqlany = "0.1"
```

MSRV: Rust 1.87.

## Command-line tool

From source:

```sh
cargo install opensqlany-cli
```

This installs an `opensqlany` binary on your `PATH`.

## From source (development)

```sh
git clone https://github.com/Sigilweaver/OpenSQLAnywhere
cd OpenSQLAnywhere
cargo build --release
./target/release/opensqlany --help
```
