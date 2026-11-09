//! Single sign-on bodies: what an identity provider sends back, and the
//! one-time code the dashboard swaps for its session.

use ianua_app::error::AppError;
use ianua_app::ports::federation::ServiceProvider;
use ianua_app::services::authentication::sign_in_gate::ClientOrigin;
use ianua_app::use_cases::authentication::federation::{
    ExchangeSignInCodeRequest, ExchangedSession, OidcLoginRequest, SamlCallbackRequest,
};
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{SamlRequestId, SessionId};
use serde::{Deserialize, Serialize};

use crate::dto::authentication::sign_in::OwedFactors;
use crate::error::ApiError;

/// The shortest value a dashboard may keep for a sign-in: long enough that
/// nobody guesses it.
const SHORTEST_DASHBOARD_STATE: usize = 32;

/// What the dashboard sends when it starts a single sign-on.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct SsoBeginQuery {
    /// A random value of at least 32 characters the dashboard made and
    /// keeps (in `sessionStorage`), sent again with the one-time code. The
    /// code works only with it, so a code sent to someone else's browser is
    /// of no use there.
    pub state: String,
}

impl SsoBeginQuery {
    /// The dashboard's value, as the secret it is.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the value is shorter than 32
    /// characters.
    pub(crate) fn dashboard_state(self) -> Result<Secret, ApiError> {
        if self.state.chars().count() < SHORTEST_DASHBOARD_STATE {
            return Err(ApiError::validation(message!(
                "api-state-must-be-a-random-value",
                "state must be a random value of at least 32 characters"
            )));
        }
        Ok(Secret::new(self.state))
    }
}

/// What an OIDC identity provider sends the browser back with.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct OidcCallbackQuery {
    /// Authorization code from the provider.
    pub code: Option<String>,
    /// The state this deployment sent, echoed by the provider.
    pub state: Option<String>,
}

impl OidcCallbackQuery {
    /// The sign-in the provider's answer asks for, by the browser holding
    /// `binding`, from `origin`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Forbidden` when the provider sent no code or no
    /// state, which no sign-in answers.
    pub(crate) fn login(
        self,
        binding: Secret,
        origin: ClientOrigin,
    ) -> Result<OidcLoginRequest, AppError> {
        let (Some(state), Some(code)) = (self.state, self.code) else {
            return Err(AppError::Forbidden(message!(
                "api-the-identity-provider-sent-no-code",
                "the identity provider sent no code"
            )));
        };
        Ok(OidcLoginRequest {
            state: Secret::new(state),
            code: Secret::new(code),
            binding,
            origin,
        })
    }
}

/// The form a SAML identity provider posts to the assertion consumer
/// service.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SamlAcsForm {
    /// The base64 SAML response.
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    /// The ID of the sign-in request being answered.
    #[serde(rename = "RelayState", default)]
    pub relay_state: String,
}

impl SamlAcsForm {
    /// The sign-in the answer asks for, posted to `service_provider` by the
    /// browser holding `binding`, from `origin`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Forbidden` when the answer names no request this
    /// deployment could have sent.
    pub(crate) fn login(
        self,
        binding: Secret,
        service_provider: ServiceProvider,
        origin: ClientOrigin,
    ) -> Result<SamlCallbackRequest, AppError> {
        let relay_state = SamlRequestId::new(self.relay_state).map_err(|_| {
            AppError::Forbidden(message!(
                "api-no-sign-in-request-awaits-this",
                "no sign-in request awaits this answer"
            ))
        })?;
        Ok(SamlCallbackRequest {
            relay_state,
            saml_response: self.saml_response,
            binding,
            service_provider,
            origin,
        })
    }
}

/// A single sign-on's one-time code, to swap for its session.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SsoExchangeBody {
    /// The code the browser brought back from the identity provider.
    pub code: String,
    /// The value the dashboard sent when it started the sign-in.
    pub state: String,
}

impl From<SsoExchangeBody> for ExchangeSignInCodeRequest {
    fn from(body: SsoExchangeBody) -> Self {
        Self {
            code: Secret::new(body.code),
            dashboard_state: Secret::new(body.state),
        }
    }
}

/// The session a one-time code was swapped for.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SsoExchangeResponse {
    /// The session to use from now on.
    #[schema(value_type = String, format = Uuid)]
    pub session_id: SessionId,
    /// Its refresh token, shown this once.
    pub refresh_token: String,
    /// What the session still owes: a second factor when the identity
    /// provider reported none and the person has one here, or the tenant
    /// requires one. Until it is given, the session can only finish signing
    /// in.
    #[serde(flatten)]
    pub owed: OwedFactors,
}

impl From<ExchangedSession> for SsoExchangeResponse {
    fn from(exchanged: ExchangedSession) -> Self {
        Self {
            session_id: exchanged.session_id,
            refresh_token: exchanged.refresh_token.expose().to_owned(),
            owed: exchanged.second_factor.into(),
        }
    }
}
