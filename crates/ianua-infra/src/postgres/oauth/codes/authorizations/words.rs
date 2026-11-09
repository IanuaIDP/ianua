//! The words an authorization code's choices are stored as. Its sign-in
//! method and second factor are stored as a session's are, with the words
//! of `organization/sessions/signed_in/words.rs`.

use ianua_domain::domains::oauth::grants::authorization_code::CodeChallengeMethod;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    CodeChallengeMethod as "code challenge method" {
        S256 => "s256",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// The challenge method reads back from the word it is written as.
    #[test]
    fn the_challenge_method_reads_back_from_its_word() {
        let method = CodeChallengeMethod::S256;

        assert_eq!(CodeChallengeMethod::from_word(method.word()), Some(method));
    }
}
