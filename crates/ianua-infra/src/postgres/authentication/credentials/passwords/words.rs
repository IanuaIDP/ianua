//! The words a password's choices are stored as.

use ianua_domain::domains::authentication::credentials::password_rules::PasswordOrigin;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    PasswordOrigin as "password origin" {
        ChosenByHolder => "chosen_by_holder",
        SetByAdmin => "set_by_admin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Who set a password is stored as the stable name the domain gives it,
    /// and reads back as itself.
    #[test]
    fn every_origin_is_stored_as_its_stable_name() {
        for origin in [PasswordOrigin::ChosenByHolder, PasswordOrigin::SetByAdmin] {
            assert_eq!(origin.word(), origin.as_str());
            assert_eq!(PasswordOrigin::from_word(origin.word()), Some(origin));
        }
    }
}
