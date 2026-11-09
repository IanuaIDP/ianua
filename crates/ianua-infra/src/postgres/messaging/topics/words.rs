//! The words a topic's choices are stored as.

use ianua_domain::domains::messaging::topic::TopicStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    TopicStatus as "topic status" {
        Active => "active",
        Paused => "paused",
        Archived => "archived",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::messaging::TopicSortField;
    use ianua_domain::domains::messaging::topic::{Topic, TopicRow};
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::messaging::topic_row;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [
            TopicStatus::Active,
            TopicStatus::Paused,
            TopicStatus::Archived,
        ] {
            let topic: Topic<ResolvedTenant> = Topic::reconstitute(TopicRow {
                status,
                ..topic_row("orders.created")
            })
            .unwrap();

            assert_eq!(
                topic.sort_key(TopicSortField::Status),
                SortKey::Text(status.word().to_owned())
            );
            assert_eq!(TopicStatus::from_word(status.word()), Some(status));
        }
    }
}
