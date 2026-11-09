//! The name of a messaging topic.
//!
//! A name is lowercase segments separated by dots, such as `orders.created`,
//! `payments.completed` or `inventory.low-stock`.

use crate::shared::validation::{TextValue, Validator, text_value};

text_value! {
    /// A checked topic name.
    ///
    /// Rules:
    /// - 1 to 128 characters.
    /// - Only lowercase ASCII letters, digits, hyphens and dots.
    /// - Starts and ends with a letter or digit.
    /// - No two dots in a row.
    pub struct TopicName;
}

impl TextValue for TopicName {
    const FIELD: &'static str = "topic_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        crate::domains::messaging::message_type::segments(check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-word name such as `orders` is allowed. Dots are optional.
    #[test]
    fn valid_simple_name() {
        assert!(TopicName::new("orders").is_ok());
    }

    /// `orders.created` is allowed. A single dot separates two segments.
    #[test]
    fn valid_dotted_name() {
        assert!(TopicName::new("orders.created").is_ok());
    }

    /// `inventory.low-stock` is allowed. A hyphen inside a segment is fine.
    #[test]
    fn valid_with_hyphens() {
        assert!(TopicName::new("inventory.low-stock").is_ok());
    }

    /// `api-v2.events` is allowed. Digits may appear in a segment.
    #[test]
    fn valid_with_digits() {
        assert!(TopicName::new("api-v2.events").is_ok());
    }

    /// An empty name is refused. A topic always has a name to publish to.
    #[test]
    fn an_empty_topic_name_is_refused() {
        assert!(TopicName::new("").is_err());
    }

    /// A name of 129 characters is refused, one past the limit of 128.
    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(129);
        assert!(TopicName::new(long).is_err());
    }

    /// `Orders.Created` is refused. Names are lowercase only, so
    /// `orders.created` and `Orders.Created` can never be two topics.
    #[test]
    fn uppercase_topic_names_are_refused() {
        assert!(TopicName::new("Orders.Created").is_err());
    }

    /// `orders created` is refused, since a space is not an allowed
    /// character.
    #[test]
    fn spaces_in_topic_names_are_refused() {
        assert!(TopicName::new("orders created").is_err());
    }

    /// `.orders` is refused. A name must start with a letter or digit.
    #[test]
    fn rejects_starting_with_dot() {
        assert!(TopicName::new(".orders").is_err());
    }

    /// `orders.` is refused. A name must end with a letter or digit.
    #[test]
    fn rejects_ending_with_dot() {
        assert!(TopicName::new("orders.").is_err());
    }

    /// `orders..created` is refused, since it has an empty segment between
    /// the two dots.
    #[test]
    fn rejects_consecutive_dots() {
        assert!(TopicName::new("orders..created").is_err());
    }

    /// `-orders` is refused. A hyphen is allowed inside a name but not as
    /// its first character.
    #[test]
    fn rejects_starting_with_hyphen() {
        assert!(TopicName::new("-orders").is_err());
    }

    /// A name of exactly 128 characters is allowed, so the limit is not
    /// off by one.
    #[test]
    fn max_length_accepted() {
        let name = "a".repeat(128);
        assert!(TopicName::new(name).is_ok());
    }

    /// `orders.created` prints as `orders.created`, with nothing added or
    /// changed.
    #[test]
    fn display_returns_inner() {
        let name = TopicName::new("orders.created").unwrap();
        assert_eq!(name.to_string(), "orders.created");
    }

    /// JSON holding `payments.completed` reads into a name. JSON holding
    /// `Payments..Completed` is refused, so reading from JSON cannot skip
    /// the rules.
    #[cfg(feature = "serde")]
    #[test]
    fn a_topic_name_read_from_json_is_validated() {
        assert!(serde_json::from_str::<TopicName>("\"payments.completed\"").is_ok());
        assert!(serde_json::from_str::<TopicName>("\"Payments..Completed\"").is_err());
    }
}
