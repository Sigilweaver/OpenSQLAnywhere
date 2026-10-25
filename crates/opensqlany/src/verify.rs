//! Plaintext structure checks used to confirm a deobfuscation guess.
//!
//! A guessed keystream is only trusted when something in the file itself,
//! independent of the histogram that produced the guess, agrees with it.

use crate::page::PAGE_SIZE;
use crate::slotted::find_slot_directory;

/// `true` when the page prelude's row count equals the trailer's count byte.
///
/// Slotted pages store their row count twice: in the plaintext trailer
/// (byte `0xFF0`) and in the prelude immediately before the slot array, as a
/// little-endian u16 four or six bytes before the array. The trailer is not
/// obfuscated and the prelude is, so the two agree only when the guessed
/// keystream recovers the prelude exactly. A keystream that is off by any
/// constant moves the prelude count off the trailer value.
///
/// The check is sufficient evidence, not necessary: pages without a slot
/// directory, or whose prelude uses another layout, return `false`.
pub(crate) fn trailer_row_count_matches(plain: &[u8]) -> bool {
    if plain.len() != PAGE_SIZE {
        return false;
    }
    let count = plain[0xFF0];
    if count == 0 {
        return false;
    }
    let Some(dir) = find_slot_directory(plain) else {
        return false;
    };
    let start = dir.array_start();
    [6usize, 4].iter().any(|&back| {
        start >= back + 2 && plain[start - back] == count && plain[start - back + 1] == 0
    })
}
