//! Comparing secrets without telling the caller how much of a guess was right.
//!
//! An ordinary `==` stops at the first byte that differs, so how long it takes
//! says how many leading bytes matched. Someone who can time many guesses can
//! then find a secret one byte at a time. Every comparison of a secret, or of a
//! digest a presented secret is checked against, goes through [`same_secret`].

use subtle::ConstantTimeEq;

/// Whether `left` and `right` hold the same bytes, in a time that depends only
/// on their lengths.
///
/// The lengths themselves are not hidden: every secret and digest of one kind
/// has the same length, so they say nothing about its content.
#[must_use]
pub(crate) fn same_secret(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two copies of the same 16-byte value compare as the same secret.
    #[test]
    fn equal_bytes_are_the_same_secret() {
        assert!(same_secret(b"0123456789abcdef", b"0123456789abcdef"));
    }

    /// A guess wrong only in its first byte, or only in its last, does not
    /// match. Both ends are checked, not only a leading part.
    #[test]
    fn a_difference_anywhere_is_a_different_secret() {
        assert!(!same_secret(b"0123456789abcdef", b"x123456789abcdef"));
        assert!(!same_secret(b"0123456789abcdef", b"0123456789abcdex"));
    }

    /// A truncated prefix and an empty guess both differ from the complete
    /// secret, even when every supplied byte matches.
    #[test]
    fn a_prefix_is_a_different_secret() {
        assert!(!same_secret(b"0123456789abcdef", b"0123456789abcde"));
        assert!(!same_secret(b"", b"0"));
    }

    /// Two empty byte strings compare equal, as plain equality would say.
    #[test]
    fn two_empty_values_are_the_same() {
        assert!(same_secret(b"", b""));
    }
}
