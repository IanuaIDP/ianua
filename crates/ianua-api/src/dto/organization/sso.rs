//! Single sign-on bodies: a member starting a dashboard sign-in through
//! their organization's identity provider, and the dashboard handing on
//! the provider's answer.

use ianua_app::error::AppError;
use ianua_app::ports::federation::ServiceProvider;
use ianua_app::services::authentication::sign_in_gate::ClientOrigin;
use ianua_app::use_cases::authentication::federation::SsoReturn;
use ianua_app::use_cases::authentication::federation::single_sign_on::SsoStart;
use ianua_app::use_cases::organization::sign_in::{
    OrgSsoAnswer, OrgSsoCallbackRequest, OrgSsoStartRequest,
};
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::SamlRequestId;
use serde::{Deserialize, Serialize};

use crate::dto::organization::sign_in::slug_of;
use crate::error::ApiError;

/// Request body starting a sign-in through the organization's identity
/// provider.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgSsoStartBody {
    /// The slug of the organization signing in.
    pub organization: String,
    /// The tenant to sign in to. Without it the session lands in the first
    /// active tenant the member reaches.
    #[serde(default)]
    pub tenant_slug: Option<String>,
}

impl OrgSsoStartBody {
    /// The start this body asks for, the provider answering to
    /// `returns_to`, from `origin`.
    ///
    /// # Errors
    ///
    /// `422` when a slug is malformed.
    pub(crate) fn into_request(
        self,
        returns_to: SsoReturn,
        origin: ClientOrigin,
    ) -> Result<OrgSsoStartRequest, ApiError> {
        let organization = slug_of(Some(self.organization))?.ok_or_else(|| {
            ApiError::validation(message!(
                "api-organization-is-required",
                "organization is required"
            ))
        })?;
        Ok(OrgSsoStartRequest {
            organization,
            tenant_slug: slug_of(self.tenant_slug)?,
            returns_to,
            origin,
        })
    }
}

/// Where to send the browser, and the secret it keeps until it comes back.
/// Holds that secret, so it has no `Debug`.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgSsoStartResponse {
    /// The identity provider's sign-in page.
    pub redirect_url: String,
    /// The secret only this browser holds, shown once: keep it for the
    /// length of the sign-in and send it back with the provider's answer.
    pub binding: String,
}

impl From<SsoStart> for OrgSsoStartResponse {
    fn from(start: SsoStart) -> Self {
        Self {
            redirect_url: start.url.as_str().to_owned(),
            binding: start.binding.expose().to_owned(),
        }
    }
}

/// What the identity provider sent the browser back with.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub(crate) enum OrgSsoAnswerBody {
    /// An OIDC provider's redirect, as its query carried it.
    Oidc {
        /// The `state` parameter.
        state: String,
        /// The `code` parameter.
        code: String,
    },
    /// A SAML provider's posted form.
    Saml {
        /// The `RelayState` field: the request answered.
        relay_state: String,
        /// The `SAMLResponse` field, base64 as posted.
        saml_response: String,
    },
}

/// Request body handing on the identity provider's answer. Holds secrets,
/// so it has no `Debug`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgSsoCallbackBody {
    /// The secret the start handed this browser.
    pub binding: String,
    /// What the provider sent back.
    pub answer: OrgSsoAnswerBody,
}

impl OrgSsoCallbackBody {
    /// The sign-in the answer asks for, a SAML answer meant for
    /// `service_provider`, from `origin`.
    ///
    /// # Errors
    ///
    /// `403` when a SAML answer names no request this deployment could have
    /// sent.
    pub(crate) fn into_request(
        self,
        service_provider: ServiceProvider,
        origin: ClientOrigin,
    ) -> Result<OrgSsoCallbackRequest, ApiError> {
        Ok(OrgSsoCallbackRequest {
            answer: answer_of(self.answer, service_provider)?,
            binding: Secret::new(self.binding),
            origin,
        })
    }
}

/// The app's form of `answer`.
fn answer_of(
    answer: OrgSsoAnswerBody,
    service_provider: ServiceProvider,
) -> Result<OrgSsoAnswer, ApiError> {
    match answer {
        OrgSsoAnswerBody::Oidc { state, code } => Ok(OrgSsoAnswer::Oidc {
            state: Secret::new(state),
            code: Secret::new(code),
        }),
        OrgSsoAnswerBody::Saml {
            relay_state,
            saml_response,
        } => Ok(OrgSsoAnswer::Saml {
            relay_state: SamlRequestId::new(relay_state).map_err(|_| {
                AppError::Forbidden(message!(
                    "api-no-sign-in-request-awaits-this",
                    "no sign-in request awaits this answer"
                ))
            })?,
            saml_response,
            service_provider,
        }),
    }
}
