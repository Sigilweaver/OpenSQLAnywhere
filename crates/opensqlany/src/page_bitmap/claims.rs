//! Exclude a rival zero-word bitmap only when it names a data page proved
//! to belong to another owner by an independently verified catalog map.

use std::collections::BTreeMap;

use super::{PageBitmapError, TableMapRead, TablePageBitmap, regions};
use crate::{CalibratedStore, LongDescriptor, PhysicalValue, RowPageHeader};

/// A data page that made a candidate payload impossible. Its stored header
/// and a previously checked, separate catalog map both attest its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitmapConflictWitness {
    /// Physical data page named by the rejected candidate.
    pub page: u32,
    /// Owner confirmed on the data page and by the independent map.
    pub owner: u32,
    /// Chunk page containing the independent map.
    pub source_page: u32,
    /// Zero-based physical slot containing that map.
    pub source_slot: u16,
}

/// Physical memberships established without consulting this registry.
/// Only the ordinary store map path can register evidence; a map recovered
/// using a conflict witness cannot contribute evidence to another retry.
pub struct CatalogPageClaims<'reader, 'store> {
    store: &'reader CalibratedStore<'store>,
    pages: BTreeMap<u32, BitmapConflictWitness>,
}

impl<'reader, 'store> CatalogPageClaims<'reader, 'store> {
    /// Start an empty registry for one immutable calibrated store.
    pub fn new(store: &'reader CalibratedStore<'store>) -> Self {
        Self {
            store,
            pages: BTreeMap::new(),
        }
    }

    /// Verify a positive table-map field from an independently decoded,
    /// unique catalog definition. A failed map registers no page claims.
    pub fn observe_positive_map(
        &mut self,
        field: &PhysicalValue<'_>,
        declared: u32,
        owner: u32,
    ) -> Result<(), PageBitmapError> {
        let PhysicalValue::OutOfRow(d) = field else {
            return Err(PageBitmapError::UnsupportedField);
        };
        if declared == 0 || d.domain != 31 {
            return Err(PageBitmapError::UnsupportedField);
        }
        let map = self.store.table_page_map(field, declared, owner)?;
        for page in map.bitmap.pages() {
            self.pages.entry(page).or_insert(BitmapConflictWitness {
                page,
                owner,
                source_page: d.first_page,
                source_slot: d.slot,
            });
        }
        Ok(())
    }

    /// First use ordinary map recovery. Only a positive, structurally
    /// ambiguous result may be retried. Every discarded byte sequence
    /// requires an independent impossible member. The survivor still needs
    /// all original length, membership and per-sector literal checks.
    pub fn table_page_map(
        &self,
        field: &PhysicalValue<'_>,
        declared: u32,
        owner: u32,
    ) -> Result<TableMapRead, PageBitmapError> {
        match (self.store.table_page_map(field, declared, owner), field) {
            (Err(prior @ PageBitmapError::AmbiguousSparseMap), PhysicalValue::OutOfRow(d))
                if declared != 0 && d.domain == 31 =>
            {
                regions::recover(self.store, d, declared, owner, prior, Some(self))
            }
            (result, _) => result,
        }
    }

    pub(super) fn select(
        &self,
        payloads: Vec<Vec<u8>>,
        descriptor: &LongDescriptor<'_>,
        declared: u32,
        owner: u32,
    ) -> Result<(Vec<u8>, Vec<BitmapConflictWitness>), PageBitmapError> {
        let store = self.store.store();
        let mut survivor = None;
        let mut rejected = Vec::new();
        for payload in payloads {
            let bitmap = TablePageBitmap::decode(&payload, store.page_count(), declared)?;
            let conflict = bitmap.pages().find_map(|page| {
                let claim = *self.pages.get(&page)?;
                if claim.owner == owner
                    || (claim.source_page, claim.source_slot)
                        == (descriptor.first_page, descriptor.slot)
                {
                    return None;
                }
                // An unreadable page or uncorroborated header cannot exclude
                // any candidate, including when a neighboring page is known.
                let header = RowPageHeader::recover(store.page(u64::from(page)).ok()?).ok()?;
                (header.owner_id() == claim.owner && header.page_kind() <= 4).then_some(claim)
            });
            if let Some(conflict) = conflict {
                rejected.push(conflict);
            } else if survivor.replace(payload).is_some() {
                return Err(PageBitmapError::AmbiguousSparseMap);
            }
        }
        let payload = survivor.ok_or(PageBitmapError::NoSparseMap)?;
        Ok((payload, rejected))
    }
}
