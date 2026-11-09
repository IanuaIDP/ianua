//! The kinds of second factor, and what an enrolled one holds to be
//! answered: a sealed seed for an authenticator app, nothing for a code sent
//! to the account's address, a phone number for a code sent by text.

use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::identity::account::profile_values::PhoneNumber;
use crate::types::SealedSecret;

/// The kinds of second factor a person can enroll.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MfaMethod {
    /// A time-based one-time password, RFC 6238, from an authenticator app
    /// such as Google Authenticator or Authy.
    Totp,
    /// A short code mailed to the account's address for each sign-in.
    ///
    /// It proves the mailbox again, which NIST SP 800-63B (5.1.3.1) does not
    /// accept as an out-of-band authenticator: mail is read on any device,
    /// so it proves no device is held. It answers a second factor a
    /// tenant asks for, but adds no assurance: the sign-in stays at the level
    /// its first step reached.
    EmailCode,
    /// A short code sent by text message to a phone number the person
    /// confirmed with a code.
    ///
    /// NIST SP 800-63B (5.1.3.3) lists it as a restricted authenticator: a
    /// SIM swap or a hijacked number can read the code. Each tenant chooses
    /// whether to offer it as a second factor, but it never counts as a
    /// strong one: it adds no assurance, so it never meets AAL2, a step-up
    /// for a sensitive action, or a policy asking for a strong sign-in.
    SmsCode,
}

impl MfaMethod {
    /// Every method, in the order a tenant lists them.
    pub const ALL: [Self; 3] = [Self::Totp, Self::EmailCode, Self::SmsCode];

    /// The stable name records and settings carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::EmailCode => "email_code",
            Self::SmsCode => "sms_code",
        }
    }

    /// The assurance a password sign-in reaches once this factor is
    /// answered. It agrees with
    /// `assurance_level_for`.
    #[must_use]
    pub fn assurance(self) -> AssuranceLevel {
        match self {
            Self::Totp => AssuranceLevel::Aal2,
            Self::EmailCode | Self::SmsCode => AssuranceLevel::Aal1,
        }
    }

    /// Where the code to answer this factor comes from.
    #[must_use]
    pub fn delivery(self) -> CodeDelivery {
        match self {
            Self::Totp => CodeDelivery::Generated,
            Self::EmailCode | Self::SmsCode => CodeDelivery::Sent,
        }
    }
}

/// Where the code a factor is answered with comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeDelivery {
    /// The person's own app works it out from a shared seed.
    Generated,
    /// ianua makes a fresh code and sends it for each answer.
    Sent,
}

/// A second factor as it is enrolled, with what answering it needs.
///
/// An authenticator app holds a seed only in sealed form; infrastructure
/// seals and opens it. A mailed code goes to the address the account holds
/// when it is sent, so it keeps nothing. A texted code goes to the number
/// confirmed at setup, kept here rather than read from the profile: a
/// number changed on the profile was never proved to reach its holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrolledFactor {
    /// An authenticator app, with its sealed seed.
    Totp(SealedSecret),
    /// Codes mailed to the account's address.
    EmailCode,
    /// Codes texted to this number.
    SmsCode(PhoneNumber),
}

impl EnrolledFactor {
    /// The kind of factor.
    #[must_use]
    pub fn method(&self) -> MfaMethod {
        match self {
            Self::Totp(_) => MfaMethod::Totp,
            Self::EmailCode => MfaMethod::EmailCode,
            Self::SmsCode(_) => MfaMethod::SmsCode,
        }
    }

    /// The sealed seed of an authenticator app. Other factors hold none.
    #[must_use]
    pub fn sealed_secret(&self) -> Option<&SealedSecret> {
        match self {
            Self::Totp(secret) => Some(secret),
            Self::EmailCode | Self::SmsCode(_) => None,
        }
    }

    /// The number texted codes go to. Other factors hold none.
    #[must_use]
    pub fn phone_number(&self) -> Option<&PhoneNumber> {
        match self {
            Self::SmsCode(number) => Some(number),
            Self::Totp(_) | Self::EmailCode => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::methods::AuthMethod;
    use crate::domains::authentication::sessions::mfa_factor::{
        FactorProved, MfaFactor, assurance_level_for,
    };

    /// The factor each method proves at sign-in.
    fn proved_by(method: MfaMethod) -> MfaFactor {
        match method {
            MfaMethod::Totp => MfaFactor::Totp,
            MfaMethod::EmailCode => MfaFactor::EmailCode,
            MfaMethod::SmsCode => MfaFactor::SmsCode,
        }
    }

    /// The level each method says a password sign-in reaches is the level
    /// the session mapping gives it, so an offer and a sign-in never
    /// disagree.
    #[test]
    fn each_methods_assurance_agrees_with_the_session_mapping() {
        for method in MfaMethod::ALL {
            assert_eq!(
                method.assurance(),
                assurance_level_for(
                    AuthMethod::Password,
                    FactorProved::Proved(proved_by(method))
                ),
                "{method:?}"
            );
        }
    }

    /// A mailed code provides AAL1 assurance, below the second-factor level.
    #[test]
    fn a_mailed_code_adds_no_assurance() {
        assert_eq!(MfaMethod::EmailCode.assurance(), AssuranceLevel::Aal1);
    }

    /// A texted code provides AAL1 assurance, below the second-factor level.
    #[test]
    fn a_texted_code_adds_no_assurance() {
        assert_eq!(MfaMethod::SmsCode.assurance(), AssuranceLevel::Aal1);
    }

    /// An authenticator app makes its own codes. Mailed and texted codes are
    /// sent by ianua for each answer.
    #[test]
    fn only_sent_factors_are_sent_a_code() {
        assert_eq!(MfaMethod::Totp.delivery(), CodeDelivery::Generated);
        assert_eq!(MfaMethod::EmailCode.delivery(), CodeDelivery::Sent);
        assert_eq!(MfaMethod::SmsCode.delivery(), CodeDelivery::Sent);
    }

    /// An enrolled factor names its kind and hands out only what it holds: a
    /// seed for an app, a number for texts, nothing for mail.
    #[test]
    fn an_enrolled_factor_holds_only_what_its_kind_needs() {
        let app = EnrolledFactor::Totp(SealedSecret::new("sealed").unwrap());
        let text = EnrolledFactor::SmsCode(PhoneNumber::new("+4930123456").unwrap());

        assert_eq!(app.method(), MfaMethod::Totp);
        assert!(app.sealed_secret().is_some());
        assert!(app.phone_number().is_none());
        assert_eq!(text.method(), MfaMethod::SmsCode);
        assert_eq!(
            text.phone_number().map(PhoneNumber::as_str),
            Some("+4930123456")
        );
        assert!(EnrolledFactor::EmailCode.sealed_secret().is_none());
    }

    /// Each method has a stable name for records and settings.
    #[test]
    fn each_method_has_a_stable_name() {
        assert_eq!(MfaMethod::Totp.as_str(), "totp");
        assert_eq!(MfaMethod::EmailCode.as_str(), "email_code");
        assert_eq!(MfaMethod::SmsCode.as_str(), "sms_code");
    }
}
