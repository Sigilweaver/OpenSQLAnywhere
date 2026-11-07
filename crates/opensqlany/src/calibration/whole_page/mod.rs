//! Store-bound full-page key equation, checked on entire excluded blocks.

use std::collections::BTreeSet;

use super::{CalibrationGap, Fit, HeaderWitness, bucket, consensus, header_witness};
use crate::{Page, RowPageHeader, RowSectorReader, RowSectorRecovery, RowTail, SECTOR_SIZE};

mod cycle;

const MASK: u32 = (1 << 25) - 1;
const MAX_TRIALS: usize = 262_144;

/// Which physical record-boundary checks establish the reconstructed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WholePageFraming {
    /// Every stored row length equals its complete directory allocation span.
    ExactRows,
    /// Referenced LOB records use their stored length within the allocation.
    /// Kind-20 frames may leave an unused suffix outside that length.
    LobRecords,
}

/// Complete row-data reconstruction with its selection evidence.
/// Sector zero retains the strict row reader's header representation. The
/// twelve displaced row bytes are restored at 4080..4092. Reserved trailer
/// bytes and the CRC remain the encoded source bytes, not a new page CRC.
#[derive(Debug, PartialEq, Eq)]
pub struct WholePageRecovery {
    /// Source physical page number.
    pub page: u32,
    /// A representative of the equivalent signed cycle-key family.
    pub signed_key: i32,
    /// Checked logical row bytes, including the restored header stash.
    pub bytes: Box<[u8; crate::PAGE_SIZE]>,
    /// Excluded 32-page-block fold, in 0..5.
    pub fold: u8,
    /// All retained models agreed; no held-out model was removed.
    pub retained_models: usize,
    /// Training pages supplying independent full-sector witnesses.
    pub training_pages: usize,
    /// Held-out pages with independently recovered full sectors.
    pub heldout_full_pages: usize,
    /// Held-out pages with independently recovered final sectors.
    pub heldout_tail_pages: usize,
    /// Framing policy used by the explicit recovery entry point.
    pub framing: WholePageFraming,
}

fn normalized(key: i32) -> u32 {
    if key < 0 {
        key.unsigned_abs() & MASK
    } else {
        (!(key as u32)) & MASK
    }
}
fn header_keys(h: &HeaderWitness, phase: u8) -> Vec<i32> {
    let increment = 0u8.wrapping_sub(h.header_increment);
    if increment & 1 == 0 {
        return Vec::new();
    }
    let seed = 0u8
        .wrapping_sub(h.header_base)
        .wrapping_sub(h.header_increment);
    cycle::keys(usize::from(h.header_rotation), increment, seed)
        .into_iter()
        .filter(|&key| (key < 0) == (phase == 16))
        .collect()
}
fn compatible(h: &HeaderWitness, key: i32) -> bool {
    h.keys.iter().all(|witness| {
        let tail = if witness.sector == 7 { 16 } else { 0 };
        let Some((rotation, increment, seed)) =
            cycle::params(key.wrapping_sub(i32::from(witness.sector)), tail)
        else {
            return false;
        };
        if rotation != usize::from(witness.rotation) {
            return false;
        }
        if witness.sector == 7 && h.tail_phase.is_none() {
            return true;
        }
        let observed = witness.step.wrapping_mul(witness.rotation as u8);
        let phase = h.tail_phase.filter(|_| witness.sector == 7).unwrap_or(0);
        let expected = 0u8
            .wrapping_sub(witness.base)
            .wrapping_sub(observed.wrapping_mul(phase.wrapping_add(1)));
        increment == 0u8.wrapping_sub(observed) && seed == expected
    })
}
struct Witness<'a> {
    header: &'a HeaderWitness,
    words: BTreeSet<u32>,
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Model {
    low_xor: u16,
    low_add: u16,
    high_xor: u16,
    high_add: u16,
}
impl Model {
    fn word(self, page: u32) -> u32 {
        let low = u32::from((page as u16) ^ self.low_xor) + u32::from(self.low_add);
        let high =
            (((page >> 16) ^ u32::from(self.high_xor)) + u32::from(self.high_add) + (low >> 16))
                & 511;
        (high << 16) | (low & 65535)
    }
}

pub(super) struct WholeFit {
    models: BTreeSet<Model>,
    phase: u8,
    fold: u8,
    training_pages: usize,
    heldout_full_pages: usize,
    heldout_tail_pages: usize,
}
impl WholeFit {
    pub(super) fn train(
        data: &[HeaderWitness],
        ordinary: &Fit,
        fold: u8,
    ) -> Result<Self, CalibrationGap> {
        if !matches!(ordinary.phase, 0 | 16) {
            return Err(CalibrationGap::OutsideLocalModel);
        }
        let witnesses = data
            .iter()
            .map(|h| {
                let words = header_keys(h, ordinary.phase)
                    .into_iter()
                    .filter(|&key| compatible(h, key))
                    .map(normalized)
                    .collect::<BTreeSet<_>>();
                if words.is_empty() {
                    return Err(CalibrationGap::OutsideLocalModel);
                }
                Ok(Witness { header: h, words })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let train: Vec<_> = witnesses
            .iter()
            .filter(|w| bucket(w.header.page) != fold)
            .collect();
        let heldout: Vec<_> = witnesses
            .iter()
            .filter(|w| bucket(w.header.page) == fold)
            .collect();
        let training_pages = train
            .iter()
            .filter(|w| w.header.keys.iter().any(|k| k.sector != 7))
            .count();
        let heldout_full_pages = heldout
            .iter()
            .filter(|w| w.header.keys.iter().any(|k| k.sector != 7))
            .count();
        let heldout_tail_pages = heldout
            .iter()
            .filter(|w| {
                w.header.tail_phase.is_some() && w.header.keys.iter().any(|k| k.sector == 7)
            })
            .count();
        if training_pages < 64 || heldout_full_pages < 32 || heldout_tail_pages < 32 {
            return Err(CalibrationGap::InsufficientHoldout);
        }
        let first = train.first().ok_or(CalibrationGap::Training)?;
        let lower: BTreeSet<_> = ordinary
            .rotations
            .iter()
            .map(|m| (m.xor_mask, m.addend))
            .collect();
        let mut models = BTreeSet::new();
        let mut trials = 0;
        // Every low-word model is already frozen by the ordinary training
        // fold. Exhaust all 512 high XOR values. The first training witness
        // then enumerates every possible high addend, including its carry.
        for (low_xor, low_add) in lower {
            let partial = u32::from((first.header.page as u16) ^ low_xor) + u32::from(low_add);
            let highs: BTreeSet<_> = first
                .words
                .iter()
                .filter(|&&word| word & 65535 == partial & 65535)
                .map(|word| (word >> 16) as u16)
                .collect();
            for high_xor in 0u16..512 {
                for &high in &highs {
                    trials += 1;
                    if trials > MAX_TRIALS {
                        return Err(CalibrationGap::Training);
                    }
                    let high_add = ((i32::from(high)
                        - ((first.header.page >> 16) ^ u32::from(high_xor)) as i32
                        - (partial >> 16) as i32)
                        & 511) as u16;
                    let model = Model {
                        low_xor,
                        low_add,
                        high_xor,
                        high_add,
                    };
                    if train
                        .iter()
                        .all(|w| w.words.contains(&model.word(w.header.page)))
                    {
                        models.insert(model);
                    }
                }
            }
        }
        if models.is_empty() {
            return Err(CalibrationGap::Training);
        }
        // Validate every retained model on every excluded header and every
        // independently recovered sector. A counterexample rejects the fit;
        // it never prunes an inconvenient model using held-out evidence.
        if heldout.iter().any(|w| {
            models
                .iter()
                .any(|m| !w.words.contains(&m.word(w.header.page)))
        }) {
            return Err(CalibrationGap::HoldoutConflict);
        }
        Ok(Self {
            models,
            phase: ordinary.phase,
            fold,
            training_pages,
            heldout_full_pages,
            heldout_tail_pages,
        })
    }
    pub(super) fn recover(
        &self,
        page: Page<'_>,
        header: &RowPageHeader,
    ) -> Result<WholePageRecovery, CalibrationGap> {
        self.recover_framing(page, header, WholePageFraming::ExactRows)
    }

    pub(super) fn recover_lob(
        &self,
        page: Page<'_>,
        header: &RowPageHeader,
    ) -> Result<WholePageRecovery, CalibrationGap> {
        if !(0x11..=0x14).contains(&header.page_kind()) {
            return Err(CalibrationGap::LocalConflict);
        }
        self.recover_framing(page, header, WholePageFraming::LobRecords)
    }

    fn recover_framing(
        &self,
        page: Page<'_>,
        header: &RowPageHeader,
        framing: WholePageFraming,
    ) -> Result<WholePageRecovery, CalibrationGap> {
        page.verify_crc().map_err(|_| CalibrationGap::Integrity)?;
        page.verify_trailer()
            .map_err(|_| CalibrationGap::Integrity)?;
        if page.index() != u64::from(header.page_number())
            || bucket(header.page_number()) != self.fold
        {
            return Err(CalibrationGap::Integrity);
        }
        let has_directory = header.complete_slot_starts().is_some();
        if !has_directory && framing != WholePageFraming::LobRecords {
            return Err(CalibrationGap::NoAnchor);
        }
        let h = header_witness(header);
        let word = consensus(self.models.iter().map(|m| m.word(h.page)))
            .ok_or(CalibrationGap::Disagreement)?;
        let mut known = Vec::new();
        // The ordinary sector constraints assume stored length == allocation.
        // They cannot supply independent evidence for bounded LOB frames.
        if framing == WholePageFraming::ExactRows {
            let reader = RowSectorReader::from_header(page, header.clone());
            for sector in 1..7 {
                let bytes = match reader.recover(sector) {
                    Some(RowSectorRecovery::Unique(key)) => key.candidate_bytes().to_vec(),
                    Some(RowSectorRecovery::Equivalent { bytes, .. }) => bytes.to_vec(),
                    Some(
                        RowSectorRecovery::InsufficientLengths { .. }
                        | RowSectorRecovery::Ambiguous { .. },
                    ) => continue,
                    _ => return Err(CalibrationGap::LocalConflict),
                };
                known.push((sector * SECTOR_SIZE, bytes));
            }
            match RowTail::recover_from_header(page, header) {
                Ok(tail) => known.push((7 * SECTOR_SIZE, tail.bytes().to_vec())),
                Err(
                    crate::RowTailError::InsufficientAnchors { .. }
                    | crate::RowTailError::Ambiguous { .. },
                ) => {}
                Err(_) => return Err(CalibrationGap::LocalConflict),
            }
        }
        let mut found: Option<(i32, Vec<u8>)> = None;
        for key in header_keys(&h, self.phase)
            .into_iter()
            .filter(|&key| normalized(key) == word)
        {
            let bytes = cycle::materialize(page.bytes(), key);
            if bytes[..SECTOR_SIZE] != header.sector0()[..]
                || known
                    .iter()
                    .any(|(start, expected)| bytes[*start..*start + expected.len()] != expected[..])
            {
                continue;
            }
            let completed;
            let selected_header = if has_directory {
                header
            } else {
                let Some(proposed) = header.lob_directory_from_materialized(&bytes) else {
                    continue;
                };
                completed = proposed;
                &completed
            };
            let rows = selected_header
                .physical_rows()
                .ok_or(CalibrationGap::NoAnchor)?;
            if rows.iter().any(|row| {
                if row.length() < 2 {
                    return true;
                }
                let stored =
                    u16::from_le_bytes([bytes[row.start()], bytes[row.start() + 1]]) as usize;
                if framing == WholePageFraming::LobRecords && header.page_kind() == 0x14 {
                    stored < 3 || stored > row.length()
                } else {
                    stored != row.length() || framing == WholePageFraming::LobRecords && stored < 3
                }
            }) {
                continue;
            }
            if let Some((_, prior)) = &found {
                if prior != &bytes {
                    return Err(CalibrationGap::Disagreement);
                }
            } else {
                found = Some((key, bytes));
            }
        }
        let (signed_key, bytes) = found.ok_or(CalibrationGap::LocalConflict)?;
        Ok(WholePageRecovery {
            page: h.page,
            signed_key,
            bytes: bytes
                .into_boxed_slice()
                .try_into()
                .map_err(|_| CalibrationGap::Integrity)?,
            fold: self.fold,
            retained_models: self.models.len(),
            training_pages: self.training_pages,
            heldout_full_pages: self.heldout_full_pages,
            heldout_tail_pages: self.heldout_tail_pages,
            framing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibration::rotation::{RotationModel, SectorWitness};
    use crate::row::sector::inverse_odd;
    use crate::{CalibratedStore, PageStore, RowSlotRecovery, RowSlotSector};
    use std::sync::Arc;

    const BASE: Model = Model {
        low_xor: 0x449a,
        low_add: 0x9107,
        high_xor: 77,
        high_add: 139,
    };
    fn ordinary(phase: u8) -> Fit {
        Fit {
            rotations: vec![RotationModel {
                xor_mask: BASE.low_xor,
                addend: BASE.low_add,
                polarity: 0,
                carry_sign: 1,
                phase,
            }],
            joint: Vec::new(),
            phase,
        }
    }
    fn witness(page: u32, word: u32, phase: u8) -> HeaderWitness {
        let key = if phase == 16 {
            -(word as i32)
        } else {
            ((!word) & MASK) as i32
        };
        let (rotation, increment, seed) = cycle::params(key, 0).unwrap();
        let internal = 0u8.wrapping_sub(increment);
        let mut h = HeaderWitness {
            page,
            header_rotation: rotation as u16,
            header_base: 0u8.wrapping_sub(seed).wrapping_sub(internal),
            header_increment: internal,
            keys: Vec::new(),
            tail_phase: Some(phase),
        };
        for sector in 1..8 {
            let (rotation, increment, seed) =
                cycle::params(key.wrapping_sub(sector), if sector == 7 { 16 } else { 0 }).unwrap();
            let internal = 0u8.wrapping_sub(increment);
            let start = if sector == 7 { phase + 1 } else { 1 };
            h.keys.push(SectorWitness {
                sector: sector as u8,
                rotation: rotation as u16,
                step: internal.wrapping_mul(inverse_odd(rotation as u8)),
                base: 0u8
                    .wrapping_sub(seed)
                    .wrapping_sub(internal.wrapping_mul(start)),
            });
        }
        h
    }
    fn corpus(phase: u8) -> Vec<HeaderWitness> {
        (1..1025)
            .map(|n| {
                let page = n * 30_011;
                witness(page, BASE.word(page), phase)
            })
            .collect()
    }
    #[test]
    fn whole_word_models_predict_both_signs_across_all_excluded_folds() {
        for phase in [0, 16] {
            let data = corpus(phase);
            for fold in 0..5 {
                let fit = WholeFit::train(&data, &ordinary(phase), fold).unwrap();
                for page in [1, 255, 256, 65535, 65536, 123456, MASK] {
                    assert_eq!(
                        consensus(fit.models.iter().map(|m| m.word(page))),
                        Some(BASE.word(page))
                    );
                }
            }
        }
    }
    #[test]
    fn a_heldout_counterexample_rejects_instead_of_pruning_models() {
        let mut data = corpus(16);
        let fold = bucket(data[0].page);
        let page = data[0].page;
        data[0] = witness(page, BASE.word(page) ^ (1 << 22), 16);
        assert!(matches!(
            WholeFit::train(&data, &ordinary(16), fold),
            Err(CalibrationGap::HoldoutConflict)
        ));
        assert!(matches!(
            WholeFit::train(&data[..20], &ordinary(16), fold),
            Err(CalibrationGap::InsufficientHoldout)
        ));
    }
    fn opaque_page(page: u32, phase: u8, wrong_length: bool) -> ([u8; 4096], Vec<u8>) {
        opaque_frame(page, phase, 1, 3996 + u16::from(wrong_length))
    }
    fn opaque_frame(page: u32, phase: u8, kind: u8, length: u16) -> ([u8; 4096], Vec<u8>) {
        let (raw, logical) = framed_page(page, phase, kind, &[(96, length)]);
        (raw, logical[96..4092].to_vec())
    }
    fn framed_page(page: u32, phase: u8, kind: u8, rows: &[(usize, u16)]) -> ([u8; 4096], Vec<u8>) {
        let mut state = 0x87654321u32;
        let mut logical: Vec<_> = (0..4096)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect();
        logical[..4].copy_from_slice(&page.to_le_bytes());
        logical[16] = 4;
        logical[17] = kind;
        logical[20..22].copy_from_slice(&((rows[0].0 - 28) as u16).to_le_bytes());
        logical[22..24].copy_from_slice(&(rows.len() as u16).to_le_bytes());
        logical[24..28].copy_from_slice(&77u32.to_le_bytes());
        for (slot, &(start, length)) in rows.iter().enumerate() {
            logical[28 + 2 * slot..30 + 2 * slot]
                .copy_from_slice(&((start - 28) as u16).to_le_bytes());
            logical[start..start + 2].copy_from_slice(&length.to_le_bytes());
            logical[start + 2] = 0;
        }
        let raw = store_logical(page, phase, 1, &mut logical);
        (raw, logical)
    }

    fn store_logical(page: u32, phase: u8, prefix: u16, logical: &mut [u8]) -> [u8; 4096] {
        let key = if phase == 16 {
            -(BASE.word(page) as i32)
        } else {
            ((!BASE.word(page)) & MASK) as i32
        };
        let stash = logical[4080..4092].to_vec();
        logical[18..20].copy_from_slice(&stash[..2]);
        logical[6..16].copy_from_slice(&stash[2..]);
        let mut raw = [0u8; 4096];
        for sector in 0..8 {
            raw[sector * 512..(sector + 1) * 512].copy_from_slice(&cycle::decode(
                &logical[sector * 512..(sector + 1) * 512],
                key.wrapping_sub(sector as i32).wrapping_neg(),
                if sector == 7 { 16 } else { 0 },
            ));
        }
        raw[4080..4082].copy_from_slice(&prefix.to_le_bytes());
        raw[4082] = b'E';
        raw[4083] = 0;
        raw[4088..4092].fill(0);
        let crc = crc32fast::hash(&raw[..4092]);
        raw[4092..].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    fn sparse_lob_page(number: u32, phase: u8, kind: u8) -> ([u8; 4096], Vec<u8>) {
        let mut logical = vec![0x35; 4096];
        logical[..4].copy_from_slice(&number.to_le_bytes());
        logical[16..18].copy_from_slice(&[4, kind]);
        logical[20..22].copy_from_slice(&3974u16.to_le_bytes());
        logical[22..24].copy_from_slice(&249u16.to_le_bytes());
        logical[24..28].copy_from_slice(&77u32.to_le_bytes());
        logical[28..526].fill(0);
        for (i, slot) in (0..9).chain([248]).enumerate() {
            let start = 4002 + 9 * i;
            logical[28 + 2 * slot..30 + 2 * slot]
                .copy_from_slice(&((start - 28) as u16).to_le_bytes());
            logical[start..start + 3].copy_from_slice(&[9, 0, 0]);
            for j in 0..6 {
                logical[start + 3 + j] = (i + j) as u8;
            }
        }
        let raw = store_logical(number, phase, 9, &mut logical);
        (raw, logical)
    }

    #[test]
    fn sparse_lob_directory_uses_only_the_frozen_complete_page_family() {
        for phase in [0, 16] {
            let number = 108;
            let data = corpus(phase);
            for kind in [0x11, 0x13, 0x14] {
                let (raw, logical) = sparse_lob_page(number, phase, kind);
                let page = Page::from_bytes(u64::from(number), &raw).unwrap();
                let header = RowPageHeader::recover(page).unwrap();
                assert_eq!(header.directory_prefix_count(), 9);
                assert!(header.complete_slot_starts().is_none());
                let mut fit = WholeFit::train(&data, &ordinary(phase), bucket(number)).unwrap();
                assert!(matches!(
                    fit.recover(page, &header),
                    Err(CalibrationGap::NoAnchor)
                ));
                let recovered = fit.recover_lob(page, &header).unwrap();
                assert_eq!(&recovered.bytes[..4092], &logical[..4092]);
                let full = header
                    .lob_directory_from_materialized(&recovered.bytes[..])
                    .unwrap();
                assert_eq!(full.complete_slot_starts().unwrap()[248], Some(4083));
                assert_eq!(full.physical_rows().unwrap().len(), 10);
                assert!(header.complete_slot_starts().is_none());

                let mut source = vec![0; (number as usize + 1) * 4096];
                source[number as usize * 4096..].copy_from_slice(&raw);
                let store = PageStore::from_bytes_unchecked(source).unwrap();
                let reader = CalibratedStore::new(&store);
                reader.whole_folds[usize::from(bucket(number))]
                    .set(Ok(fit))
                    .ok()
                    .unwrap();
                let mut descriptor = crate::LongDescriptor {
                    domain: 28,
                    tag: 0,
                    prefix: &[],
                    total_len: 2,
                    first_page: number,
                    unknown: 0,
                    slot: 248,
                };
                let chain = reader.resolve_stored_byte_chain(77, &descriptor).unwrap();
                assert_eq!(chain.bytes, logical[4086..4088]);
                assert_eq!(chain.surplus, logical[4088..4092]);
                assert_eq!(chain.chunks[0].slot, 248);
                assert_eq!(chain.chunks[0].record, logical[4083..4092]);
                assert_eq!(chain.pages.len(), 1);
                descriptor.slot = 247;
                assert!(matches!(
                    reader.resolve_stored_byte_chain(77, &descriptor),
                    Err(crate::ByteChainError::Slot)
                ));
                descriptor.slot = 248;
                assert!(matches!(
                    reader.resolve_stored_byte_chain(78, &descriptor),
                    Err(crate::ByteChainError::Owner)
                ));
                assert_eq!(store.page(u64::from(number)).unwrap().bytes(), raw);

                fit = WholeFit::train(&data, &ordinary(phase), bucket(number)).unwrap();
                let mut dissent = *fit.models.first().unwrap();
                dissent.high_add ^= 1;
                fit.models.insert(dissent);
                assert!(matches!(
                    fit.recover_lob(page, &header),
                    Err(CalibrationGap::Disagreement)
                ));
            }
        }
    }

    #[test]
    fn sparse_lob_directory_rejects_invalid_suffix_prefix_and_stored_frames() {
        let number = 108;
        let data = corpus(16);
        let fit = WholeFit::train(&data, &ordinary(16), bucket(number)).unwrap();
        for mutation in 0..6 {
            let (_, mut logical) = sparse_lob_page(number, 16, 0x13);
            let mut prefix = 9;
            match mutation {
                0 => logical[524..526].copy_from_slice(&0u16.to_le_bytes()),
                1 => logical[524..526].copy_from_slice(&3974u16.to_le_bytes()),
                2 => logical[524..526].copy_from_slice(&482u16.to_le_bytes()),
                3 => logical[524..526].copy_from_slice(&3971u16.to_le_bytes()),
                4 => logical[4083..4085].copy_from_slice(&2u16.to_le_bytes()),
                _ => prefix = 10,
            }
            let raw = store_logical(number, 16, prefix, &mut logical);
            let page = Page::from_bytes(u64::from(number), &raw).unwrap();
            let header = RowPageHeader::recover(page).unwrap();
            assert!(
                matches!(
                    fit.recover_lob(page, &header),
                    Err(CalibrationGap::LocalConflict)
                ),
                "mutation {mutation}"
            );
        }
    }
    #[test]
    fn opaque_row_uses_unanimous_models_and_preserves_stashed_tail_bytes() {
        for phase in [0, 16] {
            let number = 123456;
            let data = corpus(phase);
            let mut fit = WholeFit::train(&data, &ordinary(phase), bucket(number)).unwrap();
            let (raw, expected) = opaque_page(number, phase, false);
            let page = Page::from_bytes(u64::from(number), &raw).unwrap();
            let header = RowPageHeader::recover(page).unwrap();
            let recovered = fit.recover(page, &header).unwrap();
            assert_eq!(&recovered.bytes[96..4092], expected);
            assert_eq!(page.bytes(), raw);
            let mut conflicting = *fit.models.first().unwrap();
            conflicting.high_add ^= 1;
            fit.models.insert(conflicting);
            assert!(matches!(
                fit.recover(page, &header),
                Err(CalibrationGap::Disagreement)
            ));
        }
    }
    #[test]
    fn target_row_lengths_and_source_crc_cannot_be_overridden() {
        let number = 123456;
        let data = corpus(16);
        let fit = WholeFit::train(&data, &ordinary(16), bucket(number)).unwrap();
        let (mut raw, _) = opaque_page(number, 16, true);
        let page = Page::from_bytes(u64::from(number), &raw).unwrap();
        let header = RowPageHeader::recover(page).unwrap();
        assert!(matches!(
            fit.recover(page, &header),
            Err(CalibrationGap::LocalConflict)
        ));
        raw[2000] ^= 1;
        let page = Page::from_bytes(u64::from(number), &raw).unwrap();
        assert!(matches!(
            fit.recover(page, &header),
            Err(CalibrationGap::Integrity)
        ));
    }

    #[test]
    fn bounded_lob_frames_require_explicit_policy_and_keep_the_frozen_key_checks() {
        let number = 123456;
        let data = corpus(16);
        let mut fit = WholeFit::train(&data, &ordinary(16), bucket(number)).unwrap();
        let (raw, expected) = opaque_frame(number, 16, 0x14, 1000);
        let page = Page::from_bytes(u64::from(number), &raw).unwrap();
        let header = RowPageHeader::recover(page).unwrap();
        assert!(matches!(
            fit.recover(page, &header),
            Err(CalibrationGap::LocalConflict)
        ));
        let lob = fit.recover_lob(page, &header).unwrap();
        assert_eq!(lob.framing, WholePageFraming::LobRecords);
        assert_eq!(&lob.bytes[96..4092], expected);
        let mut conflict = *fit.models.first().unwrap();
        conflict.high_add ^= 1;
        fit.models.insert(conflict);
        assert!(matches!(
            fit.recover_lob(page, &header),
            Err(CalibrationGap::Disagreement)
        ));
    }

    #[test]
    fn lob_policy_keeps_kind_length_and_integrity_bounds() {
        let number = 123456;
        let data = corpus(16);
        let fit = WholeFit::train(&data, &ordinary(16), bucket(number)).unwrap();
        for (kind, length) in [(1, 3996), (0x11, 1000), (0x14, 2), (0x14, 3997)] {
            let (raw, _) = opaque_frame(number, 16, kind, length);
            let page = Page::from_bytes(u64::from(number), &raw).unwrap();
            let header = RowPageHeader::recover(page).unwrap();
            assert!(matches!(
                fit.recover_lob(page, &header),
                Err(CalibrationGap::LocalConflict)
            ));
        }
        let (mut raw, _) = opaque_frame(number, 16, 0x14, 1000);
        let header =
            RowPageHeader::recover(Page::from_bytes(u64::from(number), &raw).unwrap()).unwrap();
        raw[2000] ^= 1;
        assert!(matches!(
            fit.recover_lob(Page::from_bytes(u64::from(number), &raw).unwrap(), &header),
            Err(CalibrationGap::Integrity)
        ));
    }

    #[test]
    fn ambiguous_slots_can_use_only_the_unanimous_complete_page_family() {
        for phase in [0, 16] {
            let number = 108;
            let starts = [
                (2048, 128),
                (2176, 128),
                (2304, 128),
                (2432, 128),
                (2560, 1532),
            ];
            let (raw, logical) = framed_page(number, phase, 1, &starts);
            let mut bytes = vec![0; (number as usize + 1) * 4096];
            bytes[number as usize * 4096..].copy_from_slice(&raw);
            let store = PageStore::from_bytes_unchecked(bytes).unwrap();
            let ordinary_page =
                RowSectorReader::new(store.page(u64::from(number)).unwrap()).unwrap();
            assert!(matches!(
                ordinary_page.recover(4),
                Some(RowSectorRecovery::Ambiguous { .. })
            ));
            let data = corpus(phase);
            for conflict in [false, true] {
                let mut whole = WholeFit::train(&data, &ordinary(phase), bucket(number)).unwrap();
                if conflict {
                    let mut dissent = *whole.models.first().unwrap();
                    dissent.high_add ^= 1;
                    whole.models.insert(dissent);
                }
                let reader = CalibratedStore::new(&store);
                // Retain competing ordinary stream selectors instead of picking
                // whichever yields parseable rows. The complete-word family has
                // independently passed its training and held-out controls.
                let mut fit = ordinary(phase);
                fit.joint = vec![(fit.rotations[0], 0), (fit.rotations[0], 1)];
                reader.folds[usize::from(bucket(number))]
                    .set(Ok(fit))
                    .ok()
                    .unwrap();
                reader.whole_folds[usize::from(bucket(number))]
                    .set(Ok(whole))
                    .ok()
                    .unwrap();
                assert!(matches!(
                    reader.page(number).unwrap().read_slot(0),
                    Some(RowSlotRecovery::Unavailable { .. })
                ));
                let reader = reader.with_whole_pages();
                let page = reader.page(number).unwrap();
                assert!(matches!(
                    page.predict_sector(4, 2),
                    Err(CalibrationGap::Disagreement)
                ));
                if conflict {
                    assert!(matches!(
                        page.read_slot(0),
                        Some(RowSlotRecovery::Unavailable { .. })
                    ));
                    assert_eq!(store.page(u64::from(number)).unwrap().bytes(), raw);
                    continue;
                }
                let Some(RowSlotRecovery::Candidate { bytes, sectors, .. }) = page.read_slot(0)
                else {
                    panic!("missing complete-page ambiguity proof");
                };
                assert_eq!(bytes, logical[2048..2176]);
                assert!(matches!(
                    sectors.as_slice(),
                    [RowSlotSector::WholePage { index: 4, .. }]
                ));
                assert_eq!(store.page(u64::from(number)).unwrap().bytes(), raw);
            }
        }
    }

    #[test]
    fn slot_reads_require_opt_in_and_retain_the_same_complete_page_evidence() {
        let number = 3;
        let (raw, expected) = opaque_page(number, 16, false);
        let mut bytes = vec![0; 4 * 4096];
        bytes[3 * 4096..].copy_from_slice(&raw);
        let store = PageStore::from_bytes_unchecked(bytes).unwrap();
        let reader = CalibratedStore::new(&store);
        assert!(matches!(
            reader.page(number).unwrap().read_slot(0),
            Some(RowSlotRecovery::Unavailable { .. })
        ));
        let data = corpus(16);
        let fit = WholeFit::train(&data, &ordinary(16), bucket(number)).unwrap();
        assert!(
            reader.whole_folds[usize::from(bucket(number))]
                .set(Ok(fit))
                .is_ok()
        );
        let reader = reader.with_whole_pages();
        let page = reader.page(number).unwrap();
        let Some(RowSlotRecovery::Candidate { bytes, sectors, .. }) = page.read_slot(0) else {
            panic!("missing checked row");
        };
        assert_eq!(bytes, expected);
        let proofs: Vec<_> = sectors
            .iter()
            .filter_map(|s| match s {
                RowSlotSector::WholePage { evidence, .. } => Some(evidence),
                _ => None,
            })
            .collect();
        assert_eq!(proofs.len(), 7);
        assert!(proofs.iter().all(|proof| Arc::ptr_eq(proofs[0], proof)));
        assert_eq!(store.page(u64::from(number)).unwrap().bytes(), raw);
    }
}
