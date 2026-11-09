//! What several sign-in bodies share: what a new session still owes, a
//! passkey's answer to a challenge, and a person proving who they are again.

use ianua_app::services::authentication::fresh_proof::ReenteredProof;
use ianua_app::services::authentication::passkey_answer::PresentedAssertion;
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CeremonyId, PasskeyCredentialId};
use serde::{Deserialize, Serialize};

use crate::codec;
use crate::error::ApiError;

/// What a new session still owes before it is finished, as every sign-in
/// answer spells it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OwedFactors {
    /// Whether the session still owes a second factor. Until it is given,
    /// the session can only finish signing in.
    pub mfa_required: bool,
    /// Whether the person has no second factor yet and must set one up
    /// first, with `…/auth/mfa/enroll` and `…/auth/mfa/enroll/confirm`.
    /// Always `false` when `mfa_required` is `false`.
    pub mfa_enrollment_required: bool,
    /// Whether the sign-in waits for the person to follow the link mailed
    /// to their address, and then `…/auth/sign-in/confirm`. Always `false`
    /// when `mfa_required` is `false`.
    pub email_confirmation_required: bool,
}

impl From<SecondFactor> for OwedFactors {
    fn from(owed: SecondFactor) -> Self {
        let (enrol, mailbox) = match owed {
            SecondFactor::NotOwed | SecondFactor::Verify => (false, false),
            SecondFactor::Enrol => (true, false),
            SecondFactor::ConfirmByEmail => (false, true),
            SecondFactor::ConfirmThenEnrol => (true, true),
        };
        Self {
            mfa_required: !owed.is_satisfied(),
            mfa_enrollment_required: enrol,
            email_confirmation_required: mailbox,
        }
    }
}

/// A passkey's answer to a challenge, as the browser hands it back.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct PasskeyAnswerBody {
    /// The `ceremony_id` from the begin call. Names the server-held
    /// challenge this assertion answers; the challenge itself is never sent
    /// back, because a caller who could choose it could choose what their
    /// own signature is checked against.
    pub ceremony_id: uuid::Uuid,
    /// The assertion from `navigator.credentials.get()`, base64url.
    pub response: String,
    /// The credential that signed it, base64url.
    pub credential_id: String,
}

impl TryFrom<PasskeyAnswerBody> for PresentedAssertion {
    type Error = ApiError;

    fn try_from(body: PasskeyAnswerBody) -> Result<Self, Self::Error> {
        let credential_id = codec::url_safe_no_pad_decode(&body.credential_id)?;
        Ok(Self {
            ceremony_id: CeremonyId::from_uuid(body.ceremony_id),
            credential_id: PasskeyCredentialId::new(credential_id).map_err(ApiError::validation)?,
            response: codec::url_safe_no_pad_decode(&body.response)?,
        })
    }
}

/// What a signed-in person gives to prove who they are again, the way they
/// sign in, before a change an open session must not make alone.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ReenteredProofBody {
    /// Their password typed again.
    Password {
        /// The password as typed.
        password: String,
        /// A code from their authenticator, needed when they have one.
        #[serde(default)]
        code: Option<String>,
    },
    /// A sign-in link mailed to them and followed just now, for an account
    /// that signs in through its mailbox.
    Mailbox {
        /// The link's token.
        link: String,
        /// A code from their authenticator, needed when they have one.
        #[serde(default)]
        code: Option<String>,
    },
    /// Their passkey's answer to a sign-in challenge opened for them.
    Passkey(PasskeyAnswerBody),
}

impl TryFrom<ReenteredProofBody> for ReenteredProof {
    type Error = ApiError;

    fn try_from(body: ReenteredProofBody) -> Result<Self, Self::Error> {
        Ok(match body {
            ReenteredProofBody::Password { password, code } => Self::Password {
                password: Secret::new(password),
                code,
            },
            ReenteredProofBody::Mailbox { link, code } => Self::Mailbox {
                link: Secret::new(link),
                code,
            },
            ReenteredProofBody::Passkey(answer) => Self::Passkey(answer.try_into()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sign-in that owes no second step says so on every flag.
    #[test]
    fn a_sign_in_owing_nothing_owes_nothing() {
        let owed = OwedFactors::from(SecondFactor::NotOwed);

        assert!(!owed.mfa_required);
        assert!(!owed.mfa_enrollment_required);
        assert!(!owed.email_confirmation_required);
    }

    /// Ann must confirm her sign-in by mail and then set up a second factor;
    /// the answer tells the dashboard both.
    #[test]
    fn a_sign_in_confirming_by_mail_then_enrolling_says_both() {
        let owed = OwedFactors::from(SecondFactor::ConfirmThenEnrol);

        assert!(owed.mfa_required);
        assert!(owed.mfa_enrollment_required);
        assert!(owed.email_confirmation_required);
    }

    /// Ann re-enters her password with an authenticator code; the proof
    /// keeps the code.
    #[test]
    fn a_password_proof_carries_its_code() {
        let body: ReenteredProofBody = serde_json::from_value(serde_json::json!({
            "kind": "password", "password": "pw", "code": "123456"
        }))
        .unwrap();

        let Ok(ReenteredProof::Password { code, .. }) = ReenteredProof::try_from(body) else {
            panic!("a password proof stays one");
        };
        assert_eq!(code.as_deref(), Some("123456"));
    }

    /// A passkey answer that is not base64url is refused.
    #[test]
    fn a_passkey_answer_that_is_not_base64url_is_refused() {
        let body = PasskeyAnswerBody {
            ceremony_id: uuid::Uuid::now_v7(),
            response: "not base64!".to_owned(),
            credential_id: "AQID".to_owned(),
        };

        assert!(PresentedAssertion::try_from(body).is_err());
    }
}
