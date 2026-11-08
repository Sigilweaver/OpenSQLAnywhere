//! Candidate recovery for one sparse sector of a terminal ISYSTAB bitmap chunk.
//! The catalog supplies the expected population and table owner. The varying
//! stored row length in the missing sector is withheld until the payload is unique.
use super::{PageBitmapError, TablePageBitmap};
use crate::catalog::recovery::sparse_row_template;
use crate::row::sector::visit_sector_candidates;
use crate::row::tail::STASH_START;
use crate::{LongDescriptor, PageStore, RowSectorReader, SECTOR_SIZE};

/// Called only when the ordinary domain-31 chunk resolver has already checked
/// the descriptor form, owner-1 blob-page header and requested slot, but its
/// reader could not recover the entire row.
pub(super) fn recover(
    store: &PageStore,
    descriptor: &LongDescriptor<'_>,
    declared_pages: u32,
    owner_id: u32,
) -> Result<TablePageBitmap, PageBitmapError> {
    let page = store.page(u64::from(descriptor.first_page))?;
    let reader = RowSectorReader::new(page).map_err(|source| PageBitmapError::Header {
        page: descriptor.first_page,
        source,
    })?;
    let header = reader.header();
    let rows = header
        .physical_rows()
        .ok_or(PageBitmapError::SparseBounds)?;
    let target = rows
        .iter()
        .find(|r| r.slot() == descriptor.slot)
        .ok_or(PageBitmapError::SparseBounds)?;
    if target.length() < 3 || target.length() - 3 != descriptor.total_len as usize {
        return Err(PageBitmapError::SparseBounds);
    }
    let span = target.start()..target.end();
    let (mut record, gap) = sparse_row_template(page, &reader, span.clone())
        .map_err(|_| PageBitmapError::SparseBounds)?;
    let sector_start = gap * SECTOR_SIZE;
    let sector_end = (sector_start + SECTOR_SIZE).min(STASH_START);
    let missing = span.start.max(sector_start)..span.end.min(sector_end);

    // No stored length byte is used for model selection. Require at least one
    // complete length word *in the missing body*, so bytes already known from
    // a different sector or the stash cannot masquerade as a held-out check.
    let witness = rows
        .iter()
        .find(|r| r.start() >= sector_start && r.start() + 2 <= sector_end)
        .ok_or(PageBitmapError::NoBitmapWitness)?
        .start()
        - sector_start;
    let mut length_bytes = Vec::new();
    for row in &rows {
        if row.length() < 2 {
            return Err(PageBitmapError::SparseBounds);
        }
        for (i, byte) in (row.length() as u16).to_le_bytes().into_iter().enumerate() {
            let at = row.start() + i;
            if (sector_start..sector_end).contains(&at) {
                length_bytes.push((at - sector_start, byte));
            }
        }
    }
    let mut first_word = None;
    let mut varies = false;
    let mut matched: Option<(Vec<u8>, TablePageBitmap)> = None;
    let mut lengths_agree = true;
    visit_sector_candidates(page, header, gap, |decode| {
        let actual = [decode(witness), decode(witness + 1)];
        if first_word.get_or_insert(actual) != &actual {
            varies = true;
        }
        for at in missing.clone() {
            record[at - span.start] = decode(at - sector_start);
        }
        let payload = &record[3..];
        if record[2] != 0 || !payload.starts_with(descriptor.prefix) {
            return Ok(());
        }
        if matched.as_ref().is_none_or(|(prior, _)| prior != payload) {
            let Ok(bitmap) = TablePageBitmap::decode(payload, store.page_count(), declared_pages)
            else {
                return Ok(());
            };
            if bitmap.verify_owner(store, owner_id).is_err() {
                return Ok(());
            }
            if matched.is_some() {
                return Err(PageBitmapError::AmbiguousSparseMap);
            }
            matched = Some((payload.to_vec(), bitmap));
        }
        // This check never chooses between payloads. Every key producing the
        // accepted payload must agree with the remaining physical evidence.
        lengths_agree &= record[..2] == (target.length() as u16).to_le_bytes()
            && length_bytes.iter().all(|&(at, want)| decode(at) == want);
        Ok(())
    })?;
    let (_, bitmap) = matched.ok_or(PageBitmapError::NoSparseMap)?;
    if !varies || !lengths_agree {
        return Err(PageBitmapError::NoBitmapWitness);
    }
    Ok(bitmap)
}
