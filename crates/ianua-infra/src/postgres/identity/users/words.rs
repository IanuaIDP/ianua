//! The words a user's choices are stored as.

use ianua_domain::domains::identity::account::user_status::UserStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    UserStatus as "user status" {
        Invited => "invited",
        PendingVerification => "pending_verification",
        Active => "active",
        Locked => "locked",
        Deactivated => "deactivated",
        Closing => "closing",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::identity::UserSortField;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::identity::user_row_standing;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [
            UserStatus::Invited,
            UserStatus::PendingVerification,
            UserStatus::Active,
            UserStatus::Locked,
            UserStatus::Deactivated,
            UserStatus::Closing,
        ] {
            let user: User<ResolvedTenant> =
                User::reconstitute(user_row_standing("ann@acme.example", status)).unwrap();

            assert_eq!(
                user.sort_key(UserSortField::Status),
                SortKey::Text(status.word().to_owned())
            );
            assert_eq!(UserStatus::from_word(status.word()), Some(status));
        }
    }
}
