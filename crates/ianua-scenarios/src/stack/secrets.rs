//! The secrets each stack makes for itself at random, in the shapes the
//! platform's readers take.

use rand::{Rng as _, RngCore as _};

/// Words a made-up password is put together from.
const WORDS: [&str; 12] = [
    "harbour", "lantern", "meadow", "pebble", "orchard", "copper", "thistle", "willow", "ember",
    "granite", "saffron", "juniper",
];

/// `bytes` random bytes written as lowercase hex.
pub(crate) fn hex(bytes: usize) -> String {
    let mut random = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut random);
    random.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A key of 32 random bytes as 64 hex digits, as `HMAC_SECRET`,
/// `EVENT_SIGNING_SECRET` and `ENCRYPTION_KEY` take one.
pub(crate) fn key() -> String {
    hex(32)
}

/// A password made of words, a capital letter and digits: long enough for
/// any password rule, and written as a sentence so no scanner takes it for
/// a key.
pub(crate) fn password() -> String {
    let mut random = rand::thread_rng();
    let words: Vec<&str> = (0..3)
        .map(|_| WORDS[random.gen_range(0..WORDS.len())])
        .collect();
    let number: u16 = random.gen_range(1000..10_000);
    format!("Scenario {} {number}", words.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key is 64 hex digits, as the platform's key readers take.
    #[test]
    fn a_key_is_sixty_four_hex_digits() {
        let made = key();

        assert_eq!(made.len(), 64);
        assert!(made.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    /// Two stacks never share a key.
    #[test]
    fn two_keys_differ() {
        assert_ne!(key(), key());
    }

    /// A password has a capital letter and digits.
    #[test]
    fn a_password_has_a_capital_letter_and_digits() {
        let made = password();

        assert!(made.chars().any(|c| c.is_ascii_uppercase()));
        assert!(made.chars().any(|c| c.is_ascii_digit()));
    }
}
