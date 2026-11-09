//! The words a second factor's choices are stored as.

use ianua_domain::domains::authentication::mfa::enrollment::MfaMethod;
use ianua_domain::domains::authentication::mfa::enrollment_status::MfaEnrollmentStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    MfaMethod as "second factor kind" {
        Totp => "totp",
        EmailCode => "email_code",
        SmsCode => "sms_code",
    }
}

stored_words! {
    MfaEnrollmentStatus as "second factor status" {
        Pending => "pending",
        Verified => "verified",
        Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// A kind of factor is stored as the name the records and settings
    /// carry, so the two never disagree.
    #[test]
    fn every_kind_is_stored_as_its_stable_name() {
        for method in MfaMethod::ALL {
            assert_eq!(method.word(), method.as_str());
            assert_eq!(MfaMethod::from_word(method.word()), Some(method));
        }
    }
}
