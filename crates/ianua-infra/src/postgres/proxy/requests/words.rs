//! The words a request record's choices are stored as.

use ianua_domain::domains::proxy::observation::TunnelCloseReason;
use ianua_domain::domains::proxy::request::context::ConsumerCredential;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    ConsumerCredential as "consumer credential" {
        ApiKey => "api_key",
        Certificate => "certificate",
        Token => "token",
    }
}

stored_words! {
    TunnelCloseReason as "connection close reason" {
        AccessEnded => "access_ended",
        CheckFailed => "check_failed",
        CredentialExpired => "credential_expired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every credential a consumer presents reads back from the word it is
    /// written as.
    #[test]
    fn every_credential_reads_back_from_its_word() {
        for credential in [
            ConsumerCredential::ApiKey,
            ConsumerCredential::Certificate,
            ConsumerCredential::Token,
        ] {
            assert_eq!(
                ConsumerCredential::from_word(credential.word()),
                Some(credential)
            );
        }
    }

    /// Every close reason reads back from the word it is written as, the
    /// word the domain names it by.
    #[test]
    fn every_close_reason_reads_back_from_its_word() {
        for reason in [
            TunnelCloseReason::AccessEnded,
            TunnelCloseReason::CheckFailed,
            TunnelCloseReason::CredentialExpired,
        ] {
            assert_eq!(TunnelCloseReason::from_word(reason.word()), Some(reason));
            assert_eq!(reason.word(), reason.as_str());
        }
    }
}
