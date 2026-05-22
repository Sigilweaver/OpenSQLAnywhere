use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use opensqlany::{ApModel, PageStore, PageType, SlottedPage};

#[derive(Parser)]
#[command(
    name = "opensqlany",
    about = "Inspect SAP SQL Anywhere page-store files",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Summarise a page store: superblock, page count, type histogram.
    Inspect {
        /// Path to the page-store file (typically a `.db`).
        file: PathBuf,
        /// Validate the CRC footer of every page.
        #[arg(long)]
        verify_crc: bool,
    },
    /// Dump a single page as a hex+ASCII listing.
    DumpPage {
        /// Path to the page-store file.
        file: PathBuf,
        /// Zero-based page number.
        page: u64,
    },
    /// Decode a slotted page's row directory.
    Slots {
        /// Path to the page-store file.
        file: PathBuf,
        /// Zero-based page number.
        page: u64,
    },
    /// Summarise the AP deobfuscation model learned from a page store.
    ApInfo {
        /// Path to the page-store file.
        file: PathBuf,
    },
    /// Deobfuscate and dump a single page.
    Deob {
        /// Path to the page-store file.
        file: PathBuf,
        /// Zero-based page number.
        page: u64,
        /// Print the raw (obfuscated) page instead of the plaintext.
        #[arg(long)]
        raw: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Inspect { file, verify_crc } => inspect(&file, verify_crc),
        Cmd::DumpPage { file, page } => dump_page(&file, page),
        Cmd::Slots { file, page } => slots(&file, page),
        Cmd::ApInfo { file } => ap_info(&file),
        Cmd::Deob { file, page, raw } => deob(&file, page, raw),
    }
}

fn inspect(path: &std::path::Path, verify_crc: bool) -> Result<()> {
    let store = PageStore::open(path).with_context(|| format!("opening {path:?}"))?;
    let sb = store.try_superblock()?;
    let total = store.page_count();

    println!("file              : {}", path.display());
    println!(
        "size              : {} B ({} pages of 4096)",
        store.size_bytes(),
        total
    );
    println!(
        "superblock magic  : 0x{:08X}  {}",
        sb.magic,
        if sb.magic_ok() { "OK" } else { "MISMATCH" },
    );
    println!(
        "format triple     : {}.{}.{}",
        sb.format_major, sb.version_a, sb.version_b
    );
    println!(
        "flags_06 / file_id: 0x{:02X} / 0x{:08X}",
        sb.flags_06, sb.file_id_lo
    );
    println!(
        "page_count_hint   : {} (total - hint = {})",
        sb.page_count_hint,
        total as i64 - sb.page_count_hint as i64
    );
    println!(
        "SAP SA 17.0.4.2182: {}",
        if sb.sa_marker_present {
            "marker present"
        } else {
            "NOT present"
        }
    );

    let mut histogram: BTreeMap<u8, u64> = BTreeMap::new();
    let mut crc_failures: Vec<u64> = Vec::new();
    let mut trailer_failures: Vec<u64> = Vec::new();

    for page in store.pages().skip(1) {
        let t = page.trailer();
        *histogram.entry(t.page_type_raw).or_insert(0) += 1;
        if page.verify_trailer().is_err() {
            trailer_failures.push(page.index());
        }
        if verify_crc && page.verify_crc().is_err() {
            crc_failures.push(page.index());
        }
    }

    println!();
    println!("pages inspected   : {}", total.saturating_sub(1));
    if verify_crc {
        println!("crc failures      : {}", crc_failures.len());
        for pn in crc_failures.iter().take(10) {
            println!("  - page {pn}");
        }
    } else {
        println!("crc verification  : skipped (--verify-crc to enable)");
    }
    println!("trailer failures  : {}", trailer_failures.len());
    for pn in trailer_failures.iter().take(10) {
        println!("  - page {pn}");
    }

    println!();
    println!("page-type histogram:");
    let mut items: Vec<_> = histogram.into_iter().collect();
    items.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    let denom = total.saturating_sub(1).max(1) as f64;
    for (byte, count) in items {
        let pt = PageType::from_byte(byte);
        let ch = if (0x20..0x7F).contains(&byte) {
            byte as char
        } else {
            '?'
        };
        println!(
            "  0x{byte:02X} {ch:?}  {name:<10}  {count:>8}  {pct:>5.1}%",
            name = pt.name(),
            pct = 100.0 * count as f64 / denom,
        );
    }
    Ok(())
}

fn dump_page(path: &std::path::Path, pn: u64) -> Result<()> {
    let store = PageStore::open(path)?;
    let page = store.page(pn)?;
    let t = page.trailer();

    println!(
        "page {pn}  type {:?}  (0x{:02X})  flags_ff0/1 = {:02X}/{:02X}  meta = {:02X}/{:02X}",
        t.page_type(),
        t.page_type_raw,
        t.flag_ff0,
        t.flag_ff1,
        t.meta_ff4,
        t.meta_ff5,
    );
    println!(
        "crc stored = 0x{:08X}  computed = 0x{:08X}  {}",
        page.stored_crc(),
        page.computed_crc(),
        if page.stored_crc() == page.computed_crc() {
            "OK"
        } else {
            "MISMATCH"
        },
    );
    println!();

    hexdump(page.bytes(), 0);
    Ok(())
}

fn slots(path: &std::path::Path, pn: u64) -> Result<()> {
    let store = PageStore::open(path)?;
    let page = store.page(pn)?;
    let slotted = SlottedPage::parse(page);
    let t = page.trailer();

    println!("page {pn}  type {:?}", t.page_type());
    match &slotted.directory {
        None => {
            println!("no plausible slot directory found");
            println!("(note: QBW-obfuscated files must be deobfuscated first)");
        }
        Some(dir) => {
            println!(
                "directory: scan=0x{:03X}  array=0x{:03X}..0x{:03X}  slots={} live={} deleted={} leading_zero={}",
                dir.scan_start,
                dir.array_start,
                dir.end,
                dir.slots.len(),
                dir.live_count(),
                dir.deleted_count(),
                dir.leading_zero,
            );
            if let Some(min) = dir.min_offset() {
                println!("min row offset: 0x{:04X}", min);
            }
            println!();
            for (i, (off, bytes)) in slotted.row_bytes().iter().enumerate().take(16) {
                let preview = bytes.iter().take(32).copied().collect::<Vec<_>>();
                let hex = preview
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join("");
                let asc = preview
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7F).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect::<String>();
                println!(
                    "  slot {i:>3}  @0x{off:04X}  len={:>4}  {hex} |{asc}|",
                    bytes.len()
                );
            }
        }
    }
    Ok(())
}

fn ap_info(path: &std::path::Path) -> Result<()> {
    let store = PageStore::open(path).with_context(|| format!("opening {path:?}"))?;
    print!("Learning AP model from {}... ", path.display());
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let model = ApModel::learn(&store);
    println!("done.");
    println!("  learned blocks : {}", model.learned_block_count());
    println!("  total blocks   : {}", (store.page_count() + 15) / 16);
    println!(
        "  coverage       : {:.1}%",
        100.0 * model.learned_block_count() as f64 / ((store.page_count() + 15) / 16).max(1) as f64
    );
    println!("  bv(block 0)    : 0x{:02X}", model.bv_at(0));
    Ok(())
}

fn deob(path: &std::path::Path, pn: u64, raw: bool) -> Result<()> {
    let store = PageStore::open(path).with_context(|| format!("opening {path:?}"))?;
    let page = store.page(pn)?;
    let t = page.trailer();

    if raw {
        println!(
            "page {pn} (raw)  type 0x{:02X}  flags {:02X}/{:02X}",
            t.page_type_raw, t.flag_ff0, t.flag_ff1,
        );
        hexdump(page.bytes(), 0);
        return Ok(());
    }

    let model = ApModel::learn(&store);
    let plain = model.deobfuscate_with_store(page.bytes(), pn, &store);
    let pt = PageType::from_byte(plain[0xFF2]);

    println!(
        "page {pn} (deobfuscated)  type {:?} (0x{:02X})  flags {:02X}/{:02X}",
        pt, plain[0xFF2], plain[0xFF0], plain[0xFF1],
    );
    hexdump(&plain, 0);
    Ok(())
}

fn hexdump(buf: &[u8], base: usize) {
    for (row, chunk) in buf.chunks(16).enumerate() {
        let off = base + row * 16;
        print!("{:08x}  ", off);
        for (i, b) in chunk.iter().enumerate() {
            print!("{:02x}{}", b, if i == 7 { "  " } else { " " });
        }
        for _ in chunk.len()..16 {
            print!("   ");
        }
        print!(" |");
        for &b in chunk {
            let c = if (0x20..0x7F).contains(&b) {
                b as char
            } else {
                '.'
            };
            print!("{c}");
        }
        println!("|");
    }
}
