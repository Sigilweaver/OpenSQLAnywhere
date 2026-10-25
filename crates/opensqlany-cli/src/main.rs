use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use opensqlany::{ApModel, PageStore, PageType, ReadOptions, SlottedPage};

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
        /// Show directories the page prelude does not confirm.
        #[arg(long)]
        lenient: bool,
    },
    /// Summarise the AP deobfuscation model learned from a page store.
    ApInfo {
        /// Path to the page-store file.
        file: PathBuf,
        /// Accept stores that no pure-AP page calibrates.
        #[arg(long)]
        lenient: bool,
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
        /// Decode pages whose keystream is unverified, ambiguous or low
        /// confidence; each is reported as a warning.
        #[arg(long)]
        lenient: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Inspect { file, verify_crc } => inspect(&file, verify_crc),
        Cmd::DumpPage { file, page } => dump_page(&file, page),
        Cmd::Slots {
            file,
            page,
            lenient,
        } => slots(&file, page, lenient),
        Cmd::ApInfo { file, lenient } => ap_info(&file, lenient),
        Cmd::Deob {
            file,
            page,
            raw,
            lenient,
        } => deob(&file, page, raw, lenient),
    }
}

fn inspect(path: &std::path::Path, verify_crc: bool) -> Result<()> {
    let store = PageStore::open_unchecked(path).with_context(|| format!("opening {path:?}"))?;
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
        sb.magic(),
        if sb.magic_ok() { "OK" } else { "MISMATCH" },
    );
    println!(
        "format triple     : {}.{}.{}",
        sb.format_major(),
        sb.version_a(),
        sb.version_b()
    );
    println!(
        "flags_06 / cur LSN: 0x{:02X} / {} (0x{:08X})",
        sb.flags_06(),
        sb.current_lsn(),
        sb.current_lsn()
    );
    println!(
        "page_count_hint   : {} (total - hint = {})",
        sb.page_count_hint(),
        total as i64 - sb.page_count_hint() as i64
    );
    println!(
        "SAP SA 17.0.4.2182: {}",
        if sb.sa_marker_present() {
            "marker present"
        } else {
            "NOT present"
        }
    );

    let mut histogram: BTreeMap<u8, u64> = BTreeMap::new();
    let mut problems: Vec<String> = Vec::new();
    if !sb.magic_ok() {
        problems.push("superblock magic mismatch".to_string());
    }
    if sb.format() != opensqlany::FormatVersion::SA17 {
        problems.push(format!("unsupported format version {}", sb.format()));
    }
    let mut crc_failures: Vec<u64> = Vec::new();
    let mut trailer_failures: Vec<u64> = Vec::new();

    for page in store.pages().skip(1) {
        let page = page?;
        let t = page.trailer();
        *histogram.entry(t.page_type_raw()).or_insert(0) += 1;
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

    if !crc_failures.is_empty() {
        problems.push(format!("{} pages fail their CRC", crc_failures.len()));
    }
    if !trailer_failures.is_empty() {
        problems.push(format!(
            "{} pages fail the trailer check",
            trailer_failures.len()
        ));
    }
    if sb.magic_ok() {
        let c = store.consistency()?;
        println!(
            "consistency       : {} pages, hint {} ({}); max page LSN {}, superblock LSN {} ({})",
            c.page_count(),
            c.page_count_hint(),
            if c.page_count_matches() {
                "matches"
            } else {
                "differs"
            },
            c.max_page_lsn(),
            c.current_lsn(),
            match c.lsn_gap() {
                Some(gap) => format!("gap {gap}"),
                None => "page LSN is higher".to_string(),
            },
        );
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
    if !problems.is_empty() {
        anyhow::bail!("{}: {}", path.display(), problems.join("; "));
    }
    Ok(())
}

fn dump_page(path: &std::path::Path, pn: u64) -> Result<()> {
    let store = PageStore::open_unchecked(path)?;
    let page = store.page(pn)?;
    let t = page.trailer();

    println!(
        "page {pn}  type {:?}  (0x{:02X})  flags_ff0/1 = {:02X}/{:02X}  lsn = {} (0x{:08X})",
        t.page_type(),
        t.page_type_raw(),
        t.raw()[0],
        t.raw()[1],
        t.lsn(),
        t.lsn(),
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
    if page.stored_crc() != page.computed_crc() && !page.is_unallocated() {
        anyhow::bail!("page {pn}: stored CRC does not match");
    }
    Ok(())
}

fn slots(path: &std::path::Path, pn: u64, lenient: bool) -> Result<()> {
    let store = PageStore::open_with(path, &read_options(lenient))?;
    print_store_warnings(&store);
    let page = store.page(pn)?;
    let slotted = SlottedPage::parse(page, &read_options(lenient))?;
    let t = page.trailer();

    println!("page {pn}  type {:?}", t.page_type());
    match slotted.directory() {
        None => {
            println!("no plausible slot directory found");
            println!("(note: QBW-obfuscated files must be deobfuscated first)");
        }
        Some(dir) => {
            println!(
                "directory: array=0x{:03X}..0x{:03X}  slots={} live={} deleted={}",
                dir.array_start(),
                dir.end(),
                dir.slots().len(),
                dir.live_count(),
                dir.deleted_count(),
            );
            match dir.declared_count() {
                Some(n) => println!("declared count: {n} (confirmed by the trailer)"),
                None => println!("declared count: none (directory found by scanning)"),
            }
            for w in slotted.warnings() {
                println!("warning: {w}");
            }
            if let Some(min) = dir.min_offset() {
                println!("min row offset: 0x{:04X}", min);
            }
            println!();
            for (i, row) in slotted.rows().iter().enumerate().take(16) {
                let (off, bytes) = (row.offset(), row.bytes());
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

fn print_store_warnings(store: &PageStore) {
    for w in store.warnings() {
        println!("warning: {w}");
    }
}

fn read_options(lenient: bool) -> ReadOptions {
    if lenient {
        ReadOptions::lenient()
    } else {
        ReadOptions::strict()
    }
}

fn ap_info(path: &std::path::Path, lenient: bool) -> Result<()> {
    let store = PageStore::open_with(path, &read_options(lenient))
        .with_context(|| format!("opening {path:?}"))?;
    print_store_warnings(&store);
    print!("Learning AP model from {}... ", path.display());
    std::io::Write::flush(&mut std::io::stdout())?;
    let model = ApModel::learn(&store, &read_options(lenient))?;
    println!("done.");
    let report = model.report();
    println!("  pure-AP pages  : {}", report.pure_pages());
    println!("  calibrated     : {}", report.calibrated_pages());
    println!("  not calibrated : {}", report.ambiguous_pages());
    for w in report.warnings() {
        println!("  warning        : {w}");
    }
    println!("  learned blocks : {}", model.learned_block_count());
    println!("  total blocks   : {}", store.page_count().div_ceil(16));
    println!(
        "  coverage       : {:.1}%",
        100.0 * model.learned_block_count() as f64 / store.page_count().div_ceil(16).max(1) as f64
    );
    Ok(())
}

fn deob(path: &std::path::Path, pn: u64, raw: bool, lenient: bool) -> Result<()> {
    let store = if raw {
        PageStore::open_unchecked(path)
    } else {
        PageStore::open_with(path, &read_options(lenient))
    }
    .with_context(|| format!("opening {path:?}"))?;
    print_store_warnings(&store);
    let page = store.page(pn)?;
    let t = page.trailer();

    if raw {
        println!(
            "page {pn} (raw)  type 0x{:02X}  flags {:02X}/{:02X}",
            t.page_type_raw(),
            t.raw()[0],
            t.raw()[1],
        );
        hexdump(page.bytes(), 0);
        return Ok(());
    }

    let opts = read_options(lenient);
    let model = ApModel::learn(&store, &opts)?;
    let dec = model.deobfuscate(&store, pn, &opts)?;
    let plain = dec.bytes();
    let pt = PageType::from_byte(plain[0xFF2]);

    println!(
        "page {pn} (deobfuscated)  type {:?} (0x{:02X})  flags {:02X}/{:02X}",
        pt, plain[0xFF2], plain[0xFF0], plain[0xFF1],
    );
    println!(
        "bv {}  source {:?}  confidence {:?}",
        dec.bv()
            .map_or_else(|| "none".to_string(), |b| format!("0x{b:02X}")),
        dec.bv_source(),
        dec.confidence()
    );
    println!("evidence: {:?}", dec.evidence());
    for (si, fit) in dec.sectors().iter().enumerate() {
        println!(
            "  sector {si}: step {:>3}  peak {:>3}  runner-up {:>3}{}{}",
            fit.step(),
            fit.peak(),
            fit.runner_up(),
            if fit.exact() { "  exact" } else { "" },
            if fit.confident() {
                ""
            } else {
                "  LOW CONFIDENCE"
            },
        );
    }
    for w in dec.warnings() {
        println!("warning: {w}");
    }
    hexdump(plain, 0);
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
