//! Connecting an account by signing in at its service, on the wire: the
//! request to begin and the address the browser is sent to, the service's
//! answer at the platform's callback and where the browser goes after it,
//! and the one-time code that finishes the connection.

use ianua_app::error::AppError;
use ianua_app::use_cases::workflows::accounts::connections::{
    AnswerRequest, Answered, Begun, FinishRequest,
};
use ianua_domain::domains::workflows::account::connection::{ConnectionRequest, ServicePlace};
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{HttpsUrl, Label, PendingConnectionId};
use serde::{Deserialize, Serialize};
use url::form_urlencoded::Serializer;
use uuid::Uuid;

use crate::dto::workflows::accounts::{SharingBody, operation_scope};
use crate::error::ApiError;

/// The dashboard page a browser lands on once a service has answered.
const CONNECTED_PAGE: &str = "integrations/connected";

/// Request body for beginning to connect an account by signing in at its
/// service.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct BeginConnectionBody {
    /// The integration it is for, such as `github`.
    pub integration: String,
    /// Its name for people.
    pub name: String,
    /// Who may have workflows act through it; `owner_only` when left out.
    #[serde(default)]
    pub sharing: SharingBody,
    /// The operations it may be used for; every one when left out.
    #[serde(default)]
    pub operations: Option<Vec<String>>,
    /// The space at the service the account works in, such as the Azure
    /// DevOps organization `contoso`: required when the integration lists
    /// `sign_in_asks_for`, and refused otherwise.
    #[serde(default)]
    pub place: Option<String>,
}

impl TryFrom<BeginConnectionBody> for ConnectionRequest {
    type Error = ApiError;

    fn try_from(body: BeginConnectionBody) -> Result<Self, ApiError> {
        Ok(Self {
            integration: IntegrationKey::new(body.integration).map_err(ApiError::validation)?,
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            sharing: body.sharing.into(),
            scope: operation_scope(body.operations)?,
            place: body
                .place
                .map(ServicePlace::new)
                .transpose()
                .map_err(ApiError::validation)?,
        })
    }
}

/// Pending account link and provider address for the browser's authorization step.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ConnectionBegunResponse {
    /// The connection, which finishing it names.
    pub connection_id: Uuid,
    /// Where to send the browser to sign in at the service.
    pub address: String,
}

impl From<Begun> for ConnectionBegunResponse {
    fn from(begun: Begun) -> Self {
        Self {
            connection_id: *begun.connection_id.as_uuid(),
            address: begun.address.as_str().to_owned(),
        }
    }
}

/// What a service sends the browser back to the callback with: its code
/// and the `state`, or an `error` when the person declined.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CallbackParams {
    /// The `state` the browser carried to the service.
    #[serde(default)]
    pub state: Option<String>,
    /// The service's code.
    #[serde(default)]
    pub code: Option<String>,
    /// The service's error, such as `access_denied`.
    #[serde(default)]
    pub error: Option<String>,
}

impl CallbackParams {
    /// The answer to take, when the service sent a code and a `state`.
    /// `None` when the person declined or the service sent neither.
    #[must_use]
    pub(crate) fn answer(self) -> Option<AnswerRequest> {
        if self.error.is_some() {
            return None;
        }
        let state = self.state.filter(|state| !state.is_empty())?;
        let code = self.code.filter(|code| !code.is_empty())?;
        Some(AnswerRequest {
            state: Secret::new(state),
            code: Secret::new(code),
        })
    }
}

/// Where the browser goes after the service's answer: the dashboard's page
/// for it under `base`, carrying the connection and its one-time code, or
/// why it cannot be finished.
///
/// Both travel in the fragment, so they never reach a server's log or a
/// `Referer`.
#[must_use]
pub fn landing(base: &HttpsUrl, answered: Option<Result<Answered, AppError>>) -> String {
    let mut fragment = Serializer::new(String::new());
    match answered {
        Some(Ok(answered)) => {
            fragment.append_pair("connection", &answered.connection_id.to_string());
            fragment.append_pair("code", answered.code.expose());
        }
        Some(Err(failure)) => {
            fragment.append_pair("error", failure_code(&failure));
        }
        None => {
            fragment.append_pair("error", "declined");
        }
    }
    format!(
        "{}/{CONNECTED_PAGE}#{}",
        base.as_str().trim_end_matches('/'),
        fragment.finish()
    )
}

/// The word the dashboard is told a failed answer with.
fn failure_code(failure: &AppError) -> &'static str {
    match failure {
        AppError::Unauthenticated => "unknown",
        AppError::Conflict(_) => "expired",
        AppError::Upstream(_) => "unreachable",
        _ => "refused",
    }
}

/// Request body for finishing a connection.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct FinishConnectionBody {
    /// The one-time code the browser brought back from the callback.
    pub code: String,
}

impl FinishConnectionBody {
    /// The request finishing `connection_id`.
    #[must_use]
    pub(crate) fn finishing(self, connection_id: PendingConnectionId) -> FinishRequest {
        FinishRequest {
            connection_id,
            code: Secret::new(self.code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deployment's public base URL, with a trailing slash to trim.
    fn base() -> HttpsUrl {
        HttpsUrl::new("https://ianua.example.com/").unwrap()
    }

    /// Ann allowed the platform at GitHub, so her browser lands on the
    /// dashboard with her connection and its code after the `#`, out of
    /// every log.
    #[test]
    fn an_answered_connection_lands_with_its_code_in_the_fragment() {
        let id = PendingConnectionId::new();
        let answered = Answered {
            connection_id: id,
            code: Secret::new("one time code".to_owned()),
        };

        let to = landing(&base(), Some(Ok(answered)));

        assert_eq!(
            to,
            format!(
                "https://ianua.example.com/integrations/connected#connection={id}&code=one+time+code"
            )
        );
    }

    /// Ann clicked "Cancel" at GitHub, so she lands on the dashboard told
    /// she declined, and nothing is exchanged.
    #[test]
    fn a_declined_sign_in_takes_no_answer_and_lands_as_declined() {
        let params = CallbackParams {
            state: Some("state".to_owned()),
            code: None,
            error: Some("access_denied".to_owned()),
        };

        let answer = params.answer();

        assert!(answer.is_none());
        assert_eq!(
            landing(&base(), None),
            "https://ianua.example.com/integrations/connected#error=declined"
        );
    }

    /// Ann came back after ten minutes, so the dashboard is told the
    /// connection expired.
    #[test]
    fn an_expired_connection_lands_as_expired() {
        let failure = AppError::Conflict("expired".into());

        let to = landing(&base(), Some(Err(failure)));

        assert!(to.ends_with("#error=expired"));
    }
}
