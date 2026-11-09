//! A pushed authorization request as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::oauth::grants::pushed_request::{
    PushedParameters, PushedRequest, PushedRequestRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OAuthClientId, PushedRequestId, Usage};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;
use crate::postgres::oauth::pushed::parameters::StoredParameters;

const PUSHED: Stored = Stored("pushed authorization request");

const PARAMETERS: Kept = Kept {
    entity: PUSHED.0,
    column: "parameters",
    shape: 1,
};

/// A pushed request as it is read. The store's checked queries fill it.
pub(super) struct PushedRequestRecord {
    pub(super) id: Uuid,
    pub(super) client_id: Uuid,
    pub(super) parameters: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) used_at: Option<OffsetDateTime>,
}

impl PushedRequestRecord {
    /// The request the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its parameters do not read
    /// back, or the row breaks a rule the request keeps.
    pub(super) fn into_request(self) -> Result<PushedRequest<ResolvedTenant>, DomainError> {
        let parameters =
            PushedParameters::try_from(PARAMETERS.open::<StoredParameters>(self.parameters)?)?;
        PushedRequest::reconstitute(PushedRequestRow {
            id: PushedRequestId::from_uuid(self.id),
            client_id: OAuthClientId::from_uuid(self.client_id),
            parameters,
            created_at: self.created_at,
            expires_at: self.expires_at,
            usage: Usage::from_stored(self.used_at),
        })
    }
}

/// The `parameters` column `request` is written to.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when they cannot be written out as
/// JSON.
pub(super) fn parameters_column(
    request: &PushedRequest<ResolvedTenant>,
) -> Result<Value, DomainError> {
    PARAMETERS.seal(&StoredParameters::from(request.parameters()))
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::oauth::grants::authorization_code::{CodeChallenge, NonceSent};
    use ianua_domain::domains::oauth::grants::authorization_request::{
        AskedFlow, AskedPrompts, AskedRequest, AskedScopes, MaxAge, Prompt, RequestedAcr,
        ResponseMode,
    };
    use ianua_domain::domains::oauth::grants::pushed_request::{ClientState, StateSent};
    use ianua_domain::types::{Nonce, RedirectUri};
    use serde_json::json;

    use super::*;
    use crate::test_support::rows::oauth::{CHALLENGE, REDIRECT, scopes};

    /// Populates every pushed parameter so the stored representation covers each field.
    fn full_parameters() -> PushedParameters {
        PushedParameters {
            redirect_uri: RedirectUri::new(REDIRECT).unwrap(),
            asked: AskedRequest {
                flow: AskedFlow::CodeWithS256Challenge,
                scopes: AskedScopes::Named(scopes(&["openid", "read"])),
                prompts: AskedPrompts::Named(vec![Prompt::Login, Prompt::Consent]),
                response_mode: ResponseMode::FormPost,
            },
            max_age: MaxAge::Seconds(300),
            acr: RequestedAcr::AtLeast(AssuranceLevel::Aal2),
            code_challenge: CodeChallenge::new(CHALLENGE).unwrap(),
            nonce: NonceSent::Sent(Nonce::new("n-0S6_WzA2Mj-4fd8a").unwrap()),
            state: StateSent::Sent(ClientState::new("af0ifjsldkj").unwrap()),
        }
    }

    /// What a client pushed is written in the shape pinned here, and a row
    /// in that shape reads back the same.
    #[test]
    fn the_parameters_are_stored_in_their_pinned_shape() {
        let parameters = full_parameters();
        let stored = json!({"v": 1, "value": {
            "redirect_uri": REDIRECT,
            "asked": {
                "flow": "code_with_s256_challenge",
                "scopes": {"named": ["openid", "read"]},
                "prompts": {"named": ["login", "consent"]},
                "response_mode": "form_post"
            },
            "max_age": 300,
            "acr": "aal2",
            "code_challenge": CHALLENGE,
            "nonce": "n-0S6_WzA2Mj-4fd8a",
            "state": "af0ifjsldkj"
        }});

        assert_eq!(
            PARAMETERS
                .seal(&StoredParameters::from(&parameters))
                .unwrap(),
            stored
        );
        let read = PushedParameters::try_from(PARAMETERS.open::<StoredParameters>(stored).unwrap());
        assert_eq!(read.unwrap(), parameters);
    }

    /// Stored pushed parameters with an unknown assurance level and
    /// unreadable scope and prompt values fail as corrupt storage.
    #[test]
    fn an_unknown_level_is_refused() {
        let stored = json!({"v": 1, "value": {
            "redirect_uri": REDIRECT,
            "asked": {
                "flow": "code_with_s256_challenge",
                "scopes": "unreadable",
                "prompts": "unreadable",
                "response_mode": "query"
            },
            "max_age": null,
            "acr": "aal9",
            "code_challenge": CHALLENGE,
            "nonce": null,
            "state": null
        }});

        let read = PushedParameters::try_from(PARAMETERS.open::<StoredParameters>(stored).unwrap());

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
