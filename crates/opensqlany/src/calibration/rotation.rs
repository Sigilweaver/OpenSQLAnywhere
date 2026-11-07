//! Fit the page-number word equation using independent witnesses from
//! other physical blocks.
//!
//! The low word has the form `(page ^ xor_mask) + addend`. Its low byte,
//! carry and pairing phase constrain a finite family of sector rotations.
//! Training excludes the target's 32-page block fold. The caller checks the
//! retained models on held-out witnesses and requires unanimous predictions.
//! No model is selected by a row value in the target page.

#[derive(Clone, Copy)]
pub(crate) struct SectorWitness {
    pub(crate) sector: u8,
    pub(crate) rotation: u16,
    pub(crate) step: u8,
    pub(crate) base: u8,
}
pub(crate) struct HeaderWitness {
    pub(crate) page: u32,
    pub(crate) header_rotation: u16,
    pub(crate) header_base: u8,
    pub(crate) header_increment: u8,
    pub(crate) keys: Vec<SectorWitness>,
    pub(crate) tail_phase: Option<u8>,
}
impl HeaderWitness {
    pub(crate) fn low_byte(&self, phase: u8) -> u8 {
        if phase == 0 {
            self.header_base
                .wrapping_add(self.header_increment)
                .wrapping_sub(1)
        } else {
            self.header_base
        }
    }
    fn pairing_phase(&self, phase: u8) -> Option<u8> {
        let u = self.low_byte(phase);
        let mut q = None;
        for k in &self.keys {
            if k.sector % 2 == 0 || u.checked_add(k.sector).is_none() {
                continue;
            }
            let diff = (self.header_rotation as u8).wrapping_sub(k.rotation as u8);
            let bit = if diff == k.sector - 1 {
                0
            } else if diff == k.sector + 1 {
                1
            } else {
                return None;
            };
            if q.is_some_and(|old| old != bit) {
                return None;
            }
            q = Some(bit);
        }
        q
    }
}
pub(crate) fn bucket(n: u32) -> u8 {
    let x = n / 32;
    let x = (x ^ 61) ^ (x >> 16);
    let x = x.wrapping_add(x << 3);
    let x = x ^ (x >> 4);
    let x = x.wrapping_mul(0x27d4eb2d);
    ((x ^ (x >> 15)) % 5) as u8
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RotationModel {
    pub(crate) xor_mask: u16,
    pub(crate) addend: u16,
    pub(crate) polarity: u8,
    pub(crate) carry_sign: i32,
    pub(crate) phase: u8,
}
impl RotationModel {
    pub(crate) fn word(self, n: u32) -> u32 {
        u32::from((n as u16) ^ self.xor_mask) + u32::from(self.addend)
    }
    pub(crate) fn rotate(self, h: &HeaderWitness, s: u8, control: u8) -> u16 {
        let v = self.word(h.page);
        let u = v as u8;
        let mut q = (u
            .wrapping_add(u8::from(self.phase == 0))
            .wrapping_add((h.page >> 16) as u8)
            .wrapping_add((v >> 16) as u8)
            .wrapping_add(self.polarity))
            & 1;
        let c8 = if control == 1 {
            0
        } else {
            (u32::from(u) + u32::from(s)) >> 8
        };
        let c16 = if control == 2 {
            0
        } else {
            (u32::from(v as u16) + u32::from(s)) >> 16
        };
        if control == 3 {
            q ^= 1;
        }
        ((i32::from(h.header_rotation)
            - 2 * (i32::from(s) + i32::from(q) + self.carry_sign * c16 as i32).div_euclid(2)
            + 256 * c8 as i32)
            & 511) as u16
    }
    pub(crate) fn stream(self, h: &HeaderWitness, s: u8, select: u8) -> (u8, u8) {
        let v = self.word(h.page);
        let carry = (v as u8).checked_add(s).is_none();
        let x1 = (v >> 8) & 1;
        let x2 = ((h.page >> 16) + (v >> 16)) & 1;
        let pred = match select {
            0 => false,
            1 => true,
            2 => x1 == 0,
            3 => x1 == 1,
            4 => (x1 ^ x2) == 0,
            5 => (x1 ^ x2) == 1,
            _ => false,
        };
        let alt = carry && pred;
        let d = if !alt {
            h.header_increment
        } else if self.phase == 0 {
            h.header_increment.wrapping_add(2)
        } else {
            h.header_increment.wrapping_sub(2)
        };
        let mut b = h.header_base.wrapping_add(s);
        if alt && self.phase == 0 {
            b = b.wrapping_sub(2);
        }
        (d, b)
    }
}
// Every calibration input below comes from training blocks, including the
// low-byte equation, pairing phase, 16-bit carry threshold and carry sign.
pub(crate) fn models(
    data: &[HeaderWitness],
    phase: u8,
    fold: u8,
) -> Result<Vec<RotationModel>, &'static str> {
    let train: Vec<_> = data.iter().filter(|h| bucket(h.page) != fold).collect();
    let qrows: Vec<_> = train
        .iter()
        .filter_map(|h| Some((*h, h.pairing_phase(phase)?)))
        .collect();
    if qrows.len() < 64 {
        return Err("insufficient_pair_witnesses");
    }
    let mut attempts = 0usize;
    let mut result = Vec::new();
    for k0 in 0u16..=255 {
        let h = train[0];
        let a0 = h.low_byte(phase).wrapping_sub((h.page as u8) ^ (k0 as u8));
        if !train
            .iter()
            .all(|h| ((h.page as u8) ^ (k0 as u8)).wrapping_add(a0) == h.low_byte(phase))
        {
            continue;
        }
        for high in 0u16..=255 {
            let k = (high << 8) | k0;
            for pol in 0u8..=1 {
                let mut mx = -1i32;
                let mut mn = 65536i32;
                for &(h, q) in &qrows {
                    let x = i32::from((h.page as u16) ^ k);
                    let positive = (q
                        ^ h.low_byte(phase).wrapping_add(u8::from(phase == 0))
                        ^ (h.page >> 16) as u8
                        ^ pol)
                        & 1
                        == 1;
                    if positive {
                        mn = mn.min(x);
                    } else {
                        mx = mx.max(x);
                    }
                    if mx >= mn {
                        break;
                    }
                }
                for a in (u32::from(a0)..=65535).step_by(256) {
                    let cut = 65536 - a as i32;
                    if !(mx < cut && cut <= mn) {
                        continue;
                    }
                    // Underconstrained corpora must abstain rather than select an
                    // arbitrary first solution or scan an unbounded parameter family.
                    attempts += 2;
                    if attempts > 256 {
                        return Err("underdetermined_calibration");
                    }
                    for sign in [-1, 1] {
                        let m = RotationModel {
                            xor_mask: k,
                            addend: a as u16,
                            polarity: pol,
                            carry_sign: sign,
                            phase,
                        };
                        if train.iter().all(|h| {
                            h.keys
                                .iter()
                                .all(|key| m.rotate(h, key.sector, 0) == key.rotation)
                        }) {
                            result.push(m);
                        }
                    }
                }
            }
        }
    }
    Ok(result)
}
pub(crate) fn consensus<T: Copy + Eq>(items: impl IntoIterator<Item = T>) -> Option<T> {
    let mut it = items.into_iter();
    let first = it.next()?;
    it.all(|v| v == first).then_some(first)
}
