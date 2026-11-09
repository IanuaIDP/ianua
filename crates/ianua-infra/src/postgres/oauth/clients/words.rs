//! The words an OAuth client's choices are stored as.

use ianua_domain::domains::oauth::clients::client::GrantType;
use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    OAuthClientStatus as "OAuth client status" {
        Active => "active",
        Revoked => "revoked",
    }
}

stored_words! {
    GrantType as "grant type" {
        AuthorizationCode => "authorization_code",
        ClientCredentials => "client_credentials",
        RefreshToken => "refresh_token",
        DeviceCode => "device_code",
        TokenExchange => "token_exchange",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [OAuthClientStatus::Active, OAuthClientStatus::Revoked] {
            assert_eq!(status.word(), status.as_str());
            assert_eq!(OAuthClientStatus::from_word(status.word()), Some(status));
        }
    }

    /// Every grant reads back from the word it is written as, so a client
    /// never gains or loses a grant on the way through storage.
    #[test]
    fn every_grant_reads_back_from_its_word() {
        for grant in [
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::RefreshToken,
            GrantType::DeviceCode,
            GrantType::TokenExchange,
        ] {
            assert_eq!(GrantType::from_word(grant.word()), Some(grant));
        }
    }
}
