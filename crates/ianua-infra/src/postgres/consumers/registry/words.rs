//! The words a consumer's choices are stored as.

use ianua_domain::domains::consumers::consumer::ConsumerStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ConsumerStatus as "consumer status" {
        Active => "active",
        Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::consumers::ConsumerSortField;
    use ianua_domain::domains::consumers::consumer::{Consumer, ConsumerRow};
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::consumers::consumer_row;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [ConsumerStatus::Active, ConsumerStatus::Disabled] {
            let consumer: Consumer<ResolvedTenant> = Consumer::reconstitute(ConsumerRow {
                status,
                ..consumer_row("billing-sync")
            })
            .unwrap();

            assert_eq!(
                consumer.sort_key(ConsumerSortField::Status),
                SortKey::Text(status.word().to_owned())
            );
            assert_eq!(ConsumerStatus::from_word(status.word()), Some(status));
        }
    }
}
