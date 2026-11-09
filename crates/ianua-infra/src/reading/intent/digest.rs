//! The fingerprint of an intent statement.
//!
//! It is a 256-bit SimHash of the statement's words: each word's SHA-256
//! votes on every bit, and a bit is set where more words voted for it than
//! against. Two statements sharing most of their words share most of their
//! bits, so a drift monitor can measure how far a purpose moved by counting
//! the bits that differ. A statement with no words fingerprints as zeros.

use ianua_domain::domains::agents::authority::intent::{IntentDigest, IntentStatement};
use sha2::{Digest as _, Sha256};

/// How many bits the fingerprint holds.
const BITS: usize = 256;

/// One bit of a word's hash: whether it votes for the fingerprint's bit or
/// against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Vote {
    For,
    Against,
}

/// The fingerprint of `intent`.
pub(crate) fn fingerprint(intent: &IntentStatement) -> IntentDigest {
    let mut tally = [0i32; BITS];
    for word in words(intent.as_str()) {
        let hash = Sha256::digest(word.as_bytes());
        for (count, vote) in tally.iter_mut().zip(votes(&hash)) {
            *count = counted(*count, vote);
        }
    }
    IntentDigest::new(packed(&tally))
}

/// The statement's words, lower-cased: runs of letters and digits.
fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
}

/// The votes of a hash's bits, highest bit of the first byte first.
fn votes(hash: &[u8]) -> impl Iterator<Item = Vote> + '_ {
    hash.iter().flat_map(|byte| {
        (0..8u32).rev().map(move |shift| {
            let bit = byte.checked_shr(shift).unwrap_or(0) & 1;
            match bit {
                0 => Vote::Against,
                _ => Vote::For,
            }
        })
    })
}

/// `count` after one more `vote`.
fn counted(count: i32, vote: Vote) -> i32 {
    match vote {
        Vote::For => count.saturating_add(1),
        Vote::Against => count.saturating_sub(1),
    }
}

/// The fingerprint a tally sets: a bit for every count above zero, eight to
/// a byte, highest bit first.
fn packed(tally: &[i32; BITS]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (byte, counts) in out.iter_mut().zip(tally.chunks(8)) {
        *byte = counts.iter().fold(0u8, |bits, count| {
            bits.checked_shl(1).unwrap_or(0) | u8::from(*count > 0)
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(text: &str) -> IntentDigest {
        fingerprint(&IntentStatement::new(text).unwrap())
    }

    fn bits_apart(a: &IntentDigest, b: &IntentDigest) -> u32 {
        a.as_bytes()
            .iter()
            .zip(b.as_bytes())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum()
    }

    /// The same statement always gets the same fingerprint, whatever its
    /// case and spacing, so a binding made twice for one purpose matches.
    #[test]
    fn the_same_words_give_the_same_fingerprint() {
        let first = digest_of("Read the orders ledger and summarize it");
        let again = digest_of("read  the ORDERS ledger, and summarize it");

        assert_eq!(first, again);
    }

    /// A reworded purpose stays close to the original and a different one
    /// lands far away, which is what the drift monitor measures.
    #[test]
    fn a_small_rewording_moves_fewer_bits_than_a_new_purpose() {
        let original = digest_of("read the orders ledger and summarize it for finance");
        let reworded = digest_of("read the orders ledger and summarize it for accounting");
        let unrelated = digest_of("delete every user account and rotate the admin keys");

        assert!(bits_apart(&original, &reworded) < bits_apart(&original, &unrelated));
    }

    /// A statement with no words at all fingerprints as zeros rather than
    /// as the bits of nothing.
    #[test]
    fn a_statement_without_words_fingerprints_as_zeros() {
        assert_eq!(digest_of("!!! ... ???").as_bytes(), &[0u8; 32]);
    }
}
