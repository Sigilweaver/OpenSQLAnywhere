---
title: CLI quickstart
sidebar_label: CLI quickstart
---

# CLI quickstart

The `opensqlany` binary is a thin inspector around the library API.

## inspect

Show file shape and a per-page-type histogram. `--verify-crc`
recomputes each page's CRC trailer.

```console
$ opensqlany inspect database.db --verify-crc
file              : database.db
size              : 14282752 B (3487 pages of 4096)
superblock magic  : 0xDA7ABA5E  OK
format triple     : 3.201.12
page_count_hint   : 3359 (total - hint = 128)

page-type histogram:
  0x41 'A'  alloc           1858   53.3%
  0x45 'E'  extent          1531   43.9%
  0x43 'C'  catalog           66    1.9%
  ...
```

## dump-page

Hex-dump a single page by index.

```console
$ opensqlany dump-page database.db 0
```

## slots

Parse the slotted-page row directory on a catalog page and print
`(slot_id, offset, length)` triples plus any deleted entries.

```console
$ opensqlany slots database.db 2
```
