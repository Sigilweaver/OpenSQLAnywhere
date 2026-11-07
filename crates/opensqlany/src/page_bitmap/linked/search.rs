//! Exhaustive, bounded joint grammar proof for all zero-anchor linked-map regions.
//! Candidate selection uses neither physical row owners nor literal witnesses.
use std::collections::BTreeSet;
use std::ops::Range;

use super::{LinkedBitmapSearch, LinkedMapChunk, ModeledRegion};
use crate::page_bitmap::{PageBitmapError, words};
use crate::row::sector::visit_sector_candidates;
use crate::{PageStore, RowPageHeader};

const MAX_PREFIXES: usize = 32;
const MAX_TRIALS: usize = 200_000;
type Part = (Range<usize>, BTreeSet<Vec<u8>>);

pub(super) fn verify(
    store: &PageStore,
    predicted: &[u8],
    declared: u32,
    chunks: &[LinkedMapChunk],
    regions: &[Vec<ModeledRegion>],
) -> Result<LinkedBitmapSearch, PageBitmapError> {
    let mut parts = Vec::new();
    for (chunk, regions) in chunks.iter().zip(regions) {
        let page = store.page(u64::from(chunk.page))?;
        let header = RowPageHeader::recover(page).map_err(|source| PageBitmapError::Header {
            page: chunk.page,
            source,
        })?;
        for region in regions {
            let mut choices = BTreeSet::new();
            // Include every supported local key, without filtering by row
            // lengths, predicted bytes, page ownership or literal membership.
            visit_sector_candidates(page, &header, usize::from(region.sector), |decode| {
                choices.insert(
                    (0..region.bitmap.len())
                        .map(|i| decode(region.sector_offset + i))
                        .collect(),
                );
                Ok::<(), PageBitmapError>(())
            })?;
            parts.push((region.bitmap.clone(), choices));
        }
    }
    search(predicted, declared, store.page_count(), parts)
}

fn search(
    predicted: &[u8],
    declared: u32,
    physical: u64,
    mut parts: Vec<Part>,
) -> Result<LinkedBitmapSearch, PageBitmapError> {
    parts.sort_by_key(|(span, _)| span.start);
    if parts.is_empty() {
        return Err(PageBitmapError::LinkedWitness);
    }
    let mut stats = LinkedBitmapSearch {
        regions: parts.len(),
        trials: 0,
        peak_prefixes: 1,
        index_pages: Vec::new(),
    };
    let mut frontier = BTreeSet::from([Vec::new()]);
    let mut at = 0;
    for (span, choices) in parts {
        if span.start < at
            || span.start >= span.end
            || span.end > predicted.len()
            || !choices.contains(&predicted[span.clone()])
            || choices.iter().any(|c| c.len() != span.len())
        {
            return Err(PageBitmapError::LinkedWitness);
        }
        let mut next = BTreeSet::new();
        for mut prefix in frontier {
            prefix.extend_from_slice(&predicted[at..span.start]);
            if words::walk(&prefix, predicted.len(), physical, |_, _| Ok(())).is_err() {
                continue;
            }
            let start = prefix.len();
            for choice in &choices {
                stats.trials += 1;
                if stats.trials > MAX_TRIALS {
                    return Err(PageBitmapError::SparseSearchLimit);
                }
                prefix.extend_from_slice(choice);
                if words::walk(&prefix, predicted.len(), physical, |_, _| Ok(())).is_ok_and(
                    |bits| bits <= declared && (prefix.len() < predicted.len() || bits == declared),
                ) {
                    next.insert(prefix.clone());
                    if next.len() > MAX_PREFIXES {
                        return Err(PageBitmapError::SparseSearchLimit);
                    }
                }
                prefix.truncate(start);
            }
        }
        if next.is_empty() {
            return Err(PageBitmapError::LinkedWitness);
        }
        stats.peak_prefixes = stats.peak_prefixes.max(next.len());
        frontier = next;
        at = span.end;
    }
    let mut survivors = BTreeSet::new();
    for mut prefix in frontier {
        prefix.extend_from_slice(&predicted[at..]);
        if words::walk(&prefix, predicted.len(), physical, |_, _| Ok(()))
            .is_ok_and(|n| n == declared)
        {
            survivors.insert(prefix);
        }
    }
    if survivors.len() != 1 || !survivors.contains(predicted) {
        return Err(PageBitmapError::LinkedWitness);
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn payload(a: u32, b: u32) -> Vec<u8> {
        [64u32, 2, a, b]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect()
    }
    fn part(span: Range<usize>, words: &[u32]) -> Part {
        (
            span,
            words.iter().map(|n| n.to_le_bytes().to_vec()).collect(),
        )
    }
    #[test]
    fn coupled_changes_cannot_be_dismissed_by_testing_one_region_at_a_time() {
        let bytes = payload(16, 48);
        // Each single mutation breaks the count; changing both restores it.
        let parts = vec![part(8..12, &[16, 48]), part(12..16, &[48, 16])];
        assert!(matches!(
            search(&bytes, 3, 65, parts),
            Err(PageBitmapError::LinkedWitness)
        ));
    }
    #[test]
    fn complete_known_suffix_can_disambiguate_an_earlier_region() {
        let bytes = payload(16, 48);
        let proof = search(&bytes, 3, 65, vec![part(8..12, &[16, 48])]).unwrap();
        assert_eq!(
            (proof.regions, proof.trials, proof.peak_prefixes),
            (1, 2, 2)
        );
        let proof = search(
            &bytes,
            3,
            65,
            vec![(9..11, BTreeSet::from([vec![0, 0], vec![1, 0]]))],
        )
        .unwrap();
        assert_eq!(proof.trials, 2);
    }
    #[test]
    fn bounds_model_membership_and_search_limits_remain_fail_closed() {
        let bytes = payload(16, 48);
        for parts in [
            vec![part(8..12, &[32])],
            vec![part(8..12, &[16]), part(10..14, &[48])],
        ] {
            assert!(search(&bytes, 3, 65, parts).is_err());
        }
        let mut choices = BTreeSet::from([16u32.to_le_bytes().to_vec()]);
        for n in 2..35 {
            choices.insert(
                ((1u32 << 1) | (1u32 << (n % 29 + 2)))
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        // Add enough distinct low-count literals to exceed the bounded frontier.
        for n in 3..20 {
            choices.insert(((1u32 << 2) | (1u32 << n)).to_le_bytes().to_vec());
        }
        assert!(matches!(
            search(&bytes, 3, 65, vec![(8..12, choices)]),
            Err(PageBitmapError::SparseSearchLimit)
        ));
    }
}
