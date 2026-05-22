---
title: Introduction
sidebar_label: Intro
slug: /
---

# OpenSQLAnywhere

**Pure-Rust reader and open specification for the SAP SQL Anywhere
on-disk page-store format.**

The current implementation targets SA17 (build 2182, 2015 release).
The goal is to make it possible to read an SQL Anywhere database
file without the SAP server being present or installed.

OpenSQLAnywhere is clean-room: it is derived from observation of the
on-disk bytes of SQL Anywhere files and from SAP's own public
documentation. It ships with no SAP code or binaries.

## What you can do today

- Open an `.db` page-store file and walk every page.
- Verify per-page CRC trailers.
- Parse the superblock (format triple, magic, page-count hint).
- Parse slotted-page row directories on SA catalog pages.
- Peel an additive-progression obfuscation layer off the file in
  memory (used in particular by Intuit QuickBooks `.QBW` files,
  which are SA17 stores with an extra obfuscation pass) via
  [`ApModel`](./ap-deobfuscation.md).

## What you can't do (yet)

- Decode arbitrary user-table rows. Column-level decoding is the
  v0.2 milestone.
- Write or modify page-store files. OpenSQLAnywhere is read-only.

## Companion projects

- **[OpenQBW](https://sigilweaver.app/openqbw/docs/)** - reader for
  Intuit QuickBooks Desktop `.QBW` files, built on top of
  OpenSQLAnywhere. The `ApModel` deobfuscation layer is the bridge.

## Get started

- [Install](./install.md)
- [Rust quickstart](./quickstart-rust.md)
- [CLI quickstart](./quickstart-cli.md)
- [Specification](./specification.md)
