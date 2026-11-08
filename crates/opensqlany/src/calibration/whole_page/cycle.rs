//! SA17 whole-page cycle and the complete finite header-key family.
//!
//! The published cycle is described in Balaxxe/opensqlanywhere's
//! page_permutation.rs at 371ca4dee7fc4a376a2b40525d85a1b1a717caaf.
//! These primitives do not select a key or establish current row visibility.
use std::collections::BTreeSet;

pub(super) fn params(key: i32, tail: usize) -> Option<(usize, u8, u8)> {
    if key == 0 {
        return None;
    }
    let magnitude = key.unsigned_abs();
    let increment = ((magnitude >> 8) as u8) | 1;
    let low = magnitude as u8;
    let stride = (((magnitude >> 16) as usize + usize::from(low)) | 1) & 511;
    let stride = if key < 0 {
        (512 - stride) & 511
    } else {
        stride
    };
    let seed = if key < 0 {
        increment.wrapping_mul((tail + 1) as u8).wrapping_sub(low)
    } else {
        low
    };
    Some((stride, increment, seed))
}
pub(super) fn decode(raw: &[u8], key: i32, tail: usize) -> Vec<u8> {
    assert_eq!(raw.len(), 512);
    let Some((stride, increment, mut seed)) = params(key, tail) else {
        return raw.to_vec();
    };
    let mut output = raw.to_vec();
    let mut current = 0;
    for _ in 0..512 - tail {
        let mut next = (current + stride) & 511;
        while next >= 512 - tail {
            next = (next + stride) & 511;
        }
        output[current] = raw[next].wrapping_add(seed);
        seed = seed.wrapping_add(increment);
        current = next;
    }
    assert_eq!(current, 0);
    output
}
pub(super) fn keys(rotation: usize, increment: u8, seed: u8) -> Vec<i32> {
    let mut result = BTreeSet::new();
    for negative in [false, true] {
        let low = if negative {
            increment.wrapping_sub(seed)
        } else {
            seed
        };
        let stride = if negative {
            (512 - rotation) & 511
        } else {
            rotation
        };
        for byte_one in [increment & !1, increment] {
            for before_or in [stride, (stride + 511) & 511] {
                let high = before_or.wrapping_sub(usize::from(low)) & 511;
                for representative in [high, high + 512, high + 32256] {
                    let magnitude = ((representative as u32) << 16)
                        | (u32::from(byte_one) << 8)
                        | u32::from(low);
                    if magnitude <= i32::MAX as u32 {
                        result.insert(if negative {
                            -(magnitude as i32)
                        } else {
                            magnitude as i32
                        });
                    }
                }
                if negative && high == 0 && byte_one == 0 && low == 0 {
                    result.insert(i32::MIN);
                }
            }
        }
    }
    result.into_iter().collect()
}
pub(super) fn materialize(raw: &[u8], key: i32) -> Vec<u8> {
    let mut plain = Vec::with_capacity(4096);
    for sector in 0..8 {
        plain.extend_from_slice(&decode(
            &raw[sector * 512..(sector + 1) * 512],
            key.wrapping_sub(sector as i32),
            if sector == 7 { 16 } else { 0 },
        ));
    }
    let stash = [
        plain[18], plain[19], plain[6], plain[7], plain[8], plain[9], plain[10], plain[11],
        plain[12], plain[13], plain[14], plain[15],
    ];
    plain[4080..4092].copy_from_slice(&stash);
    plain
}
#[cfg(test)]
mod tests {
    use super::*;
    fn bytes() -> Vec<u8> {
        let mut n = 0x12345678u32;
        (0..512)
            .map(|_| {
                n = n.wrapping_mul(1664525).wrapping_add(1013904223);
                (n >> 24) as u8
            })
            .collect()
    }
    #[test]
    fn opposite_keys_roundtrip_full_and_tail_except_self_inverse_minimum() {
        for key in [
            1,
            2,
            7,
            8,
            255,
            256,
            257,
            65535,
            65536,
            65537,
            0x12345678,
            i32::MAX,
            -1,
            -7,
            -255,
            -256,
            -65536,
            -0x12345678,
        ] {
            for tail in [0, 16] {
                let raw = bytes();
                assert_eq!(decode(&decode(&raw, key, tail), -key, tail), raw);
            }
        }
    }
    #[test]
    fn header_aliases_include_all_distinct_whole_page_boundary_behaviors() {
        let mut cases = vec![
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            255,
            256,
            257,
            65535,
            65536,
            65537,
            i32::MAX,
            i32::MIN,
            i32::MIN + 1,
            i32::MIN + 7,
            i32::MIN + 8,
        ];
        cases.extend((0..512).map(|high| (high << 16) | 256));
        cases.extend((0..512).map(|high| (high << 16) | 0xfffc));
        let mut state = 1234567u32;
        for _ in 0..1000 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            cases.push(state as i32);
        }
        let original = cases.clone();
        cases.extend(original.into_iter().filter(|&k| k != i32::MIN).map(|k| -k));
        let raw = bytes();
        for key in cases {
            if key == 0 {
                continue;
            }
            let (r, inc, seed) = params(key, 0).unwrap();
            let possible = keys(r, inc, seed);
            assert!(
                possible.iter().any(|&candidate| (0..8).all(|s| decode(
                    &raw,
                    key.wrapping_sub(s),
                    if s == 7 { 16 } else { 0 }
                ) == decode(
                    &raw,
                    candidate.wrapping_sub(s),
                    if s == 7 { 16 } else { 0 }
                ))),
                "header family lost a boundary behavior"
            );
        }
    }
}
