//! Names a program reads: tool names, attribute keys, topic names,
//! parameter names.

use std::ops::RangeInclusive;

use crate::shared::validation::charset::CharsetUnion;
use crate::shared::validation::validator::Validator;

impl Validator<'_> {
    /// Checks a name made only of the characters `allowed` lists.
    ///
    /// The rules:
    /// - not empty, ASCII only
    /// - length within `length`
    /// - every character in `allowed`, so the name holds no space, quote,
    ///   slash or anything else a reader could take as its end
    #[must_use]
    pub fn identifier(self, length: RangeInclusive<usize>, allowed: CharsetUnion) -> Self {
        self.not_empty()
            .ascii_only()
            .length(length)
            .charset(allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::validation::Charset;

    fn name(value: &str) -> bool {
        Validator::new("name", value)
            .identifier(1..=16, Charset::LOWERCASE | Charset::UNDERSCORE)
            .validate_first()
            .is_ok()
    }

    /// `order_id` uses only lowercase letters and `_`, which the rule allows.
    #[test]
    fn a_name_of_allowed_characters_is_accepted() {
        assert!(name("order_id"));
    }

    /// An uppercase letter, a space, a hyphen, a slash or an accented letter
    /// is refused when only lowercase and `_` are allowed. An empty name and
    /// one over 16 characters are refused too.
    #[test]
    fn a_name_with_any_other_character_is_refused() {
        for value in [
            "",
            "Order",
            "order id",
            "order-id",
            "order/id",
            "ordér",
            "a_very_long_name_x",
        ] {
            assert!(!name(value), "{value} was accepted");
        }
    }
}
