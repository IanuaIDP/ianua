//! What a workflow's webhook is called with, the secret issued for it in
//! its own header, what an integration's service sends a workflow
//! registered for its events, and where a page of a memory's texts starts.

use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Path, Request};
use axum::http::Uri;
use axum::http::request::Parts;
use axum::http::uri::PathAndQuery;
use axum::response::{IntoResponse, Response};
use ianua_app::auditor::RequestAuditor;
use ianua_app::error::AppError;
use ianua_domain::domains::workflows::memory::entry::PageStart;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{HttpsUrl, MemoryEntryId};
use serde::Deserialize;
use uuid::Uuid;

use crate::dto::workflows::executions::WebhookCallParams;
use crate::error::ApiError;
use crate::extractors::callers::RequestMeta;
use crate::extractors::paths::workflows::TriggerPath;
use crate::extractors::query::Query;
use crate::state::ApiState;

/// The header a workflow webhook's secret travels in.
pub(crate) const TRIGGER_SECRET_HEADER: &str = "ianua-trigger-secret";

/// The secret a webhook call presented, never logged and never answered.
///
/// A call without one is `401`, the same as one with a wrong secret, so
/// the answer does not say which webhooks exist.
struct TriggerSecret(Secret);

impl FromRequestParts<ApiState> for TriggerSecret {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .headers
            .get(TRIGGER_SECRET_HEADER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(|value| Self(Secret::new(value.to_owned())))
            .ok_or(ApiError(AppError::Unauthenticated))
    }
}

/// A webhook's route, presented secret and query, read before its JSON body.
pub(crate) struct WebhookCall {
    /// The trigger named by the route.
    pub path: TriggerPath,
    /// The secret sent in the trigger header.
    pub presented: Secret,
    /// The exposure declared for the webhook input.
    pub params: WebhookCallParams,
}

impl FromRequestParts<ApiState> for WebhookCall {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let Path(path) = Path::<TriggerPath>::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let TriggerSecret(presented) = TriggerSecret::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let Query(params) = Query::<WebhookCallParams>::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Ok(Self {
            path,
            presented,
            params,
        })
    }
}

/// A browser an integration's service sent back to the platform's one
/// callback address after a sign-in, nobody signed in and its tenant not
/// yet known.
pub(crate) struct ServiceReturn {
    /// Records what the answer changes, by the platform, from the browser's
    /// address and user agent.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for ServiceReturn {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
        Ok(Self {
            auditor: RequestAuditor::system(state.event_dispatcher.clone())
                .with_request(meta.ip_address, meta.user_agent),
        })
    }
}

/// A request an integration's service sent: the address it was sent to as
/// the service signed it, its headers and its body byte for byte, nobody
/// signed in.
///
/// Nothing is read from it here. The integration checks the signature over
/// the exact bytes before anything else is read.
pub(crate) struct ServiceDelivery {
    /// The full address it was sent to, under the deployment's public base
    /// URL, query included.
    pub address: String,
    /// Its headers, names in lowercase.
    pub headers: Vec<(String, String)>,
    /// Its body, as sent.
    pub body: Vec<u8>,
    /// Records what the delivery starts, by the platform.
    pub auditor: RequestAuditor,
}

impl FromRequest<ApiState> for ServiceDelivery {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        let address = public_address(&state.workflows.app_base_url, request.uri());
        let headers = request
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                let value = value.to_str().ok()?;
                Some((name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        let body = Bytes::from_request(request, state).await.map_err(|_| {
            ApiError::validation(message!(
                "api-the-delivery-s-body-could-not",
                "the delivery's body could not be read"
            ))
        })?;
        Ok(Self {
            address,
            headers,
            body: body.to_vec(),
            auditor: RequestAuditor::system(state.event_dispatcher.clone()),
        })
    }
}

/// `uri`'s path and query under `base`: the address a service signed,
/// whatever proxy the request came through.
fn public_address(base: &HttpsUrl, uri: &Uri) -> String {
    let path = uri
        .path_and_query()
        .map_or_else(|| uri.path(), PathAndQuery::as_str);
    format!("{}{path}", base.as_str().trim_end_matches('/'))
}

/// Where a page of a memory's texts starts: `?from=<entry id>`, the `next`
/// of the page before, or the oldest text when left out.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct MemoryPageQuery {
    /// The `next` of the page before; absent for the first page.
    from: Option<Uuid>,
}

impl MemoryPageQuery {
    /// Where the page starts.
    #[must_use]
    pub(crate) fn start(&self) -> PageStart {
        self.from.map_or(PageStart::First, |id| {
            PageStart::At(MemoryEntryId::from_uuid(id))
        })
    }
}
