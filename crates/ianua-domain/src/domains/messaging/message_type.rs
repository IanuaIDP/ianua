//! What kind of message a message is, and the filter a subscription reads
//! some kinds through.
//!
//! A type is lowercase segments separated by dots, such as `order.created`
//! or `order.refund.requested`. A filter names whole leading segments: the
//! filter `order` lets `order.created` and `order.refund.requested`
//! through, never `orders.created`.

use crate::shared::validation::{Boundary, Charset, TextValue, Validator, text_value};

/// The rules a type, a filter and a topic's name share: segments of
/// lowercase letters, digits and hyphens, separated by single dots.
pub(super) fn segments(check: Validator<'_>) -> Validator<'_> {
    check
        .identifier(
            1..=128,
            Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN | Charset::DOT,
        )
        .boundaries(Boundary::LowercaseAlphanumeric)
        .no_consecutive(b'.')
}

text_value! {
    /// A checked message type.
    ///
    /// Rules:
    /// - 1 to 128 characters.
    /// - Only lowercase ASCII letters, digits, hyphens and dots.
    /// - Starts and ends with a letter or digit.
    /// - No two dots in a row.
    pub struct MessageType;
}

impl TextValue for MessageType {
    const FIELD: &'static str = "message_type";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        segments(check)
    }
}

text_value! {
    /// A filter on message types: the leading segments a message's type
    /// must start with. Its rules are a type's.
    pub struct MessageFilter;
}

impl TextValue for MessageFilter {
    const FIELD: &'static str = "filter";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        segments(check)
    }
}

impl MessageFilter {
    /// Whether a message of `message_type` passes the filter. A message
    /// without a type never does.
    #[must_use]
    pub fn admits(&self, message_type: Option<&MessageType>) -> bool {
        let Some(message_type) = message_type else {
            return false;
        };
        let Some(rest) = message_type.as_str().strip_prefix(self.as_str()) else {
            return false;
        };
        rest.is_empty() || rest.starts_with('.')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(value: &str) -> MessageFilter {
        MessageFilter::new(value).unwrap()
    }

    fn of_type(value: &str) -> MessageType {
        MessageType::new(value).unwrap()
    }

    /// `order.created` and `order.refund.requested` are types.
    #[test]
    fn a_dotted_type_is_accepted() {
        for value in ["order.created", "order.refund.requested", "v2"] {
            assert!(MessageType::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// Types and filters reject empty text, wildcards, spaces, empty
    /// segments, a trailing dot and uppercase letters.
    #[test]
    fn a_type_or_filter_that_would_match_more_is_refused() {
        for value in [
            "",
            "order.*",
            "order.>",
            "order created",
            "order..created",
            "order.",
            "Order",
        ] {
            assert!(MessageType::new(value).is_err(), "{value:?} was a type");
            assert!(MessageFilter::new(value).is_err(), "{value:?} was a filter");
        }
    }

    /// The filter `order` lets through `order` itself and every type under
    /// it.
    #[test]
    fn a_filter_admits_its_type_and_those_under_it() {
        assert!(filter("order").admits(Some(&of_type("order"))));
        assert!(filter("order").admits(Some(&of_type("order.created"))));
        assert!(filter("order.refund").admits(Some(&of_type("order.refund.requested"))));
    }

    /// The `order` filter rejects `orders.created`, and `order.created`
    /// rejects its parent `order` type.
    #[test]
    fn a_filter_admits_whole_segments_only() {
        assert!(!filter("order").admits(Some(&of_type("orders.created"))));
        assert!(!filter("order.created").admits(Some(&of_type("order"))));
    }

    /// A message without a type passes no filter.
    #[test]
    fn a_message_without_a_type_passes_no_filter() {
        assert!(!filter("order").admits(None));
    }
}
