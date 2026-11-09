//! The words an operator's choices are stored as.

use ianua_domain::domains::operator::status::OperatorStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    OperatorStatus as "operator status" {
        Active => "active",
        Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::operator::OperatorSortField;
    use ianua_domain::domains::operator::identity::Operator;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::operator::operator_row;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [OperatorStatus::Active, OperatorStatus::Disabled] {
            let operator = Operator::reconstitute(operator_row("ops@ianua.dev", status)).unwrap();

            assert_eq!(
                operator.sort_key(OperatorSortField::Status),
                SortKey::Text(status.word().to_owned())
            );
            assert_eq!(OperatorStatus::from_word(status.word()), Some(status));
        }
    }
}
