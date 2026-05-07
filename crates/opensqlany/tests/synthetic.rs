//! Round-trip tests built from synthetic pages that match the observed
//! SA17 on-disk invariants (CRC footer, 12-byte trailer, magic, etc.).
//! These do not require any real `.db` or `.qbw` corpus.

use opensqlany::{PAGE_SIZE, PageStore, PageType, SA_MAGIC, Superblock};

const PAGE_SZ: usize = 4096;

/// Build a page with the requested page type and fill byte, then stamp
/// a valid CRC-32 footer.
fn make_page(page_type: u8, fill: u8) -> [u8; PAGE_SZ] {
    let mut page = [fill; PAGE_SZ];
    // trailer
    page[0xFF0] = 0x00; // flag_ff0
    page[0xFF1] = 0x00; // flag_ff1
    page[0xFF2] = page_type;
    page[0xFF3] = 0x00; // reserved
    page[0xFF4] = 0x00;
    page[0xFF5] = 0x00;
    for b in &mut page[0xFF6..0xFFC] {
        *b = 0;
    }
    // CRC footer
    let crc = crc32fast::hash(&page[..0xFFC]);
    page[0xFFC..0x1000].copy_from_slice(&crc.to_le_bytes());
    page
}

fn make_superblock() -> [u8; PAGE_SZ] {
    let mut page = [0u8; PAGE_SZ];
    page[0x06] = 0x09;
    page[0x08..0x0C].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    page[0x10..0x14].copy_from_slice(&3u32.to_le_bytes());
    page[0x14..0x18].copy_from_slice(&SA_MAGIC.to_le_bytes());
    page[0x18..0x1A].copy_from_slice(&201u16.to_le_bytes());
    page[0x1A..0x1C].copy_from_slice(&12u16.to_le_bytes());
    page[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
    // Embed the SA marker at the canonical offset.
    let marker = b"SAP SE, Copyright (c)2015 17.0.4.";
    page[0x401..0x401 + marker.len()].copy_from_slice(marker);
    // Stamp a valid CRC so trailer checks are clean.
    let crc = crc32fast::hash(&page[..0xFFC]);
    page[0xFFC..0x1000].copy_from_slice(&crc.to_le_bytes());
    page
}

#[test]
fn page_size_is_4096() {
    assert_eq!(PAGE_SIZE, 4096);
}

#[test]
fn superblock_detects_magic_and_marker() {
    let page0 = make_superblock();
    let sb = Superblock::parse(&page0);
    assert!(sb.magic_ok());
    assert_eq!(sb.format_major, 3);
    assert_eq!(sb.version_a, 201);
    assert_eq!(sb.version_b, 12);
    assert!(sb.sa_marker_present);
}

#[test]
fn page_store_iterates_and_validates_crc() {
    let mut bytes = Vec::with_capacity(PAGE_SZ * 3);
    bytes.extend_from_slice(&make_superblock());
    bytes.extend_from_slice(&make_page(b'E', 0));
    bytes.extend_from_slice(&make_page(b'A', 0));

    let store = PageStore::from_bytes(bytes).expect("store opens");
    assert_eq!(store.page_count(), 3);

    let sb = store.superblock().expect("superblock parses");
    assert!(sb.magic_ok());

    let mut types = Vec::new();
    for page in store.pages().skip(1) {
        page.verify_crc().expect("crc matches");
        page.verify_trailer().expect("trailer ok");
        types.push(page.trailer().page_type());
    }
    assert_eq!(types, vec![PageType::Extent, PageType::Alloc]);
}

#[test]
fn crc_mismatch_is_detected() {
    let mut bytes = Vec::with_capacity(PAGE_SZ * 2);
    bytes.extend_from_slice(&make_superblock());
    let mut p = make_page(b'E', 0);
    p[0xFFC] ^= 0xFF; // corrupt the CRC footer
    bytes.extend_from_slice(&p);

    let store = PageStore::from_bytes(bytes).unwrap();
    let page = store.page(1).unwrap();
    assert!(page.verify_crc().is_err());
}

#[test]
fn non_page_aligned_input_is_rejected() {
    let bytes = vec![0u8; PAGE_SZ + 10];
    let err = PageStore::from_bytes(bytes).unwrap_err();
    assert!(matches!(err, opensqlany::Error::NotPageAligned { .. }));
}

#[test]
fn too_small_input_is_rejected() {
    let bytes = vec![0u8; 128];
    let err = PageStore::from_bytes(bytes).unwrap_err();
    assert!(matches!(err, opensqlany::Error::TooSmall { .. }));
}

#[test]
fn page_type_roundtrip() {
    for &b in b"EAMHC@IGZ" {
        let pt = PageType::from_byte(b);
        assert_eq!(pt.as_byte(), b);
    }
}
