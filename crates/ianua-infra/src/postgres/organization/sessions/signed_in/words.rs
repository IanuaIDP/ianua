//! The words a session's choices are stored as.

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::mfa_factor::MfaFactor;
use ianua_domain::domains::authentication::sessions::status::SessionStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    SessionStatus as "session status" {
        Active => "active",
        Suspended => "suspended",
        Revoked => "revoked",
    }
}

stored_words! {
    AuthMethod as "sign-in method" {
        Password => "password",
        MagicLink => "magic_link",
        Passkey => "passkey",
        Saml => "saml",
        Oidc => "oidc",
    }
}

stored_words! {
    MfaFactor as "second factor" {
        Totp => "totp",
        EmailCode => "email_code",
        SmsCode => "sms_code",
        RecoveryCode => "recovery_code",
        HardwareKey => "hardware_key",
        Passkey => "passkey",
        EmailConfirmation => "email_confirmation",
        ProviderMultiFactor => "provider_multi_factor",
        ProviderHardwareKey => "provider_hardware_key",
    }
}

stored_words! {
    SecondFactor as "step still owed" {
        NotOwed => "not_owed",
        Verify => "verify",
        Enrol => "enrol",
        ConfirmByEmail => "confirm_by_email",
        ConfirmThenEnrol => "confirm_then_enrol",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// A sign-in method is stored as the name the audit record carries, so
    /// the two never disagree.
    #[test]
    fn every_sign_in_method_is_stored_as_its_audit_name() {
        for method in [
            AuthMethod::Password,
            AuthMethod::MagicLink,
            AuthMethod::Passkey,
            AuthMethod::Saml,
            AuthMethod::Oidc,
        ] {
            assert_eq!(method.word(), method.as_str());
            assert_eq!(AuthMethod::from_word(method.word()), Some(method));
        }
    }

    /// The listing reads only sessions owing nothing, by the stored word
    /// `not_owed`, so that is the word a finished sign-in is written as.
    #[test]
    fn a_finished_sign_in_is_stored_as_not_owed() {
        assert_eq!(SecondFactor::NotOwed.word(), "not_owed");
        assert!(SecondFactor::NotOwed.is_satisfied());
    }
}
