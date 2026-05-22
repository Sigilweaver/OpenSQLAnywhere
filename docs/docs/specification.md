---
title: Specification
sidebar_label: Specification
sidebar_position: 1
---

# OpenSQLAnywhere - Page-Store Format Specification

**Status:** v0.1 draft. Covers the page-store layer only.
Catalog-row decoding is deferred to v0.2.

This document describes the on-disk format of SAP SQL Anywhere 17
(build 2182, 2015 release) database files as it is actually observed
on disk. Every non-trivial claim is tagged either **observed** (directly
verified by reading raw bytes) or **inferred** (consistent with SAP's
public documentation but not yet directly validated).

## 0. Conventions

- Multi-byte integers are denoted `u16_LE` / `u32_LE` etc., and are
  little-endian unless stated.
- Offsets are in **bytes from start-of-file** unless noted.
- Hex literals use the `0x` prefix.

## 1. File shape

An SA17 page-store file is a sequence of fixed-size 4 KiB pages.

| Fact | Value |
| --- | --- |
| Page size | 4096 bytes (4 KiB) |
| File size | Exact multiple of page size |
| Page 0 | Superblock (see §3) |
| Pages 1..N | Data / metadata / index / catalog pages |

**observed** — 112 files, 456 521 pages, 100 % page-aligned.

## 2. Universal per-page invariants

Every page, including page 0, is subject to the following structural
invariants.

### 2.1 CRC-32 footer at 0xFFC

**observed** (456 521 / 456 521 pages):

```
page[0xFFC..0x1000] == u32_LE( crc32( page[0x0000..0x0FFC] ) )
```

The CRC polynomial is the standard zlib / IEEE 802.3 CRC-32 (same as
`crc32fast::hash` in Rust). The CRC is computed over the raw on-disk
bytes — for obfuscated variants such as QBW this means the footer can
be validated without peeling the obfuscation layer first.

### 2.2 Twelve-byte page trailer at 0xFF0..0xFFB

**observed** (456 409 non-zero pages, zero invariant failures):

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0xFF0  | 1 | `flag_ff0` | per-type variable byte |
| 0xFF1  | 1 | `flag_ff1` | almost always `0x00` |
| 0xFF2  | 1 | **`page_type`** | ASCII letter; see §2.3 |
| 0xFF3  | 1 | `zero_ff3` | always `0x00` |
| 0xFF4  | 1 | `meta_ff4` | per-type variable byte |
| 0xFF5  | 1 | `meta_ff5` | per-type variable byte |
| 0xFF6  | 6 | `zero_ff6` | always six zero bytes |
| 0xFFC  | 4 | `crc32_le` | see §2.1 |

### 2.3 Page-type alphabet

**observed** (corpus-wide frequency, pages 1..N):

| Byte | ASCII | Count | % | Working name |
|-----:|------:|------:|------:|--------------|
| 0x45 | `'E'` | 242 460 | 53.1 % | extent / data page |
| 0x41 | `'A'` | 208 783 | 45.7 % | allocation / free-space map |
| 0x4D | `'M'` | 3 159 | 0.69 % | map / metadata |
| 0x48 | `'H'` | 550 | 0.12 % | header block |
| 0x43 | `'C'` | 492 | 0.11 % | catalog |
| 0x40 | `'@'` | 448 | 0.10 % | reserved / bootstrap |
| 0x49 | `'I'` | 421 | 0.09 % | index |
| 0x47 | `'G'` | 96 | 0.02 % | unknown |

Names are working hypotheses consistent with SA's published storage
design; the type-byte value itself is **observed**, the semantic
interpretation is **inferred**.

## 3. Page-0 superblock

Page 0 is the only page with extensive plaintext structure. The first
64 bytes follow a fixed layout; the rest of the page contains a
collation block (§3.3) and a rolling copyright fingerprint (§3.4).

### 3.1 Fixed header at 0x00..0x2F

**observed** invariants (112 files):

| Offset | Size | Type | Name | Notes |
|-------:|-----:|------|------|-------|
| 0x00 | 6 | zeros | `reserved_0` | always `00 00 00 00 00 00` |
| 0x06 | 1 | u8 flag | `flags_06` | `0x09` or `0x49` |
| 0x07 | 1 | zero | `reserved_07` | always `0x00` |
| 0x08 | 4 | u32_LE | `file_id_lo` | unique per file |
| 0x0C | 4 | zeros | `reserved_0C` | always `00 00 00 00` |
| 0x10 | 4 | u32_LE | `format_major` | always `3` |
| 0x14 | 4 | u32_LE | **`magic`** | always `0xDA7ABA5E` |
| 0x18 | 2 | u16_LE | `version_a` | always `201` (`0x00C9`) |
| 0x1A | 2 | u16_LE | `version_b` | always `12` (`0x000C`) |
| 0x1C | 4 | u32_LE | `page_count_hint` | typically `total_pages - 128` |
| 0x2D | 3 | const | `const_2D` | always `0D 04 00` |
| 0x30 | 16 | zeros | `reserved_30` | always 16 zero bytes |

### 3.2 Page-count hint

**observed**: `page_count_hint == total_pages - 128` in 112 / 112 files
when `total_pages >= 128`. **Inferred**: the first 128 pages are
reserved metadata and the hint counts data pages after them.

### 3.3 Collation / codepage block (~0x162..0x1FF)

**observed** substrings in every file in this region, in this order:

- `1252LATIN1` — CHAR collation
- `windows-1252` — CHAR codepage label
- `UCA` — Unicode Collation Algorithm (NCHAR collation)
- `UTF-8` — NCHAR codepage label

These are standard SA17 collation record strings and their invariant
presence is one of the strongest pieces of evidence that the payload is
a genuine SAP SQL Anywhere database image.

### 3.4 Engine fingerprint (0x400..0xFFC)

**observed** in 112 / 112 files: offsets `0x400..0xFFC` contain the
38-byte ASCII string

```
"2182 SAP SE, Copyright (c)2015 17.0.4."
```

repeated as a rolling cycle. The final four bytes `0xFFC..0x1000` are
the CRC-32 footer per §2.1. The fingerprint pins the engine to
**SAP SQL Anywhere 17.0.4 build 2182**.

## 4. Pages 1..N — body layout

### 4.1 Trailer and CRC apply universally

Every page 1..N has the trailer (§2.2) and CRC (§2.1). No exceptions in
the observed corpus.

### 4.2 Slotted-page directory (catalog and data pages)

Pages with real row data use the classic slotted-page layout:

- a header region at the start of the page,
- row bodies grown downward from near the page end,
- a descending array of `u16_LE` row-offset entries.

**observed** quirks:

- the slot array may start on an odd byte boundary,
- a `0x0000` sentinel word may immediately precede the first entry,
- deleted slots appear as interior zero words,
- the array bytes immediately before the array contain the minimum row
  offset and the slot count, though the exact field layout varies by
  page type.

**observed** worked examples on a Rock Castle sample:

| Page | Type | Array start | Slots | Min offset |
|-----:|-----:|:-----------:|------:|-----------:|
| 2 | `A` | 0x06B | 39 | 0x076 |
| 11 | `E` | 0x071 | 124 | 0x1C2 |
| 340 | `E` | 0x09D | 44 (2 deleted) | 0x1F8 |

### 4.3 SYSTABLE row tag

**observed**: SYSTABLE rows carry an 8-byte invariant tag immediately
before the `table_name` column:

```
05 00 00 00                    row marker
<table_id u32_LE> 00 00 00 00  32-bit id, zero-padded to 8 bytes
b1 0d 19 0d 00 00 00 00        fixed record tag
<name_len u8> <name ASCII>
```

The trailer after the name contains monotone sequences that correspond
to SA `object_id` space, but the exact variable-field layout is not yet
decoded. Deferred to v0.2.

### 4.4 Other page types

Index (`I`), allocation (`A`) bitmap, map (`M`), and header (`H`) page
bodies are outside the scope of v0.1. Their trailers (§2.2) and CRC
footers (§2.1) are validated; their bodies are opaque to this spec.

## 5. What is deliberately out of scope for v0.1

| Item | Status |
|------|--------|
| SYSCOLUMN, SYSINDEX, SYSUSER row formats | v0.2 |
| Typed column decoding (DECIMAL, VARCHAR, DATE, …) | v0.2+ |
| `first_page` / `primary_root` pointers from SYSTABLE | v0.2 |
| Multi-dbspace database (13-file) layout | later |
| Write support | out of scope indefinitely |
| Encryption (the SA strong-encryption option) | not encountered in corpus |

## 6. Open questions

- Interpretation of `flags_06` (`0x09` vs `0x49`).
- Field layout of the SYSTABLE row trailer past the name column.
- Meaning of the prelude fields before the slot array
  (`0x0404`, `0x30C6`, `0x0304`, `0x022C`, `0x0001`, `0x05B4`, ...).
- Interior structure of `I`, `A`, `M`, `H` pages.

## 7. References

- SAP SQL Anywhere 17.0.01 product documentation:
  [https://help.sap.com/docs/SAP_SQL_Anywhere](https://help.sap.com/docs/SAP_SQL_Anywhere)
- `crc32fast` Rust crate (IEEE 802.3 / zlib polynomial):
  [https://crates.io/crates/crc32fast](https://crates.io/crates/crc32fast)
