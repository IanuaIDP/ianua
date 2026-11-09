//! Who calls a signal stream endpoint: the receiver confirming its
//! endpoint, known only by the tenant the path names and the challenge it
//! echoes, and the stream's manager, a person of the tenant or the
//! receiver signed in with its stream's key.

use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::error::AppError;
use ianua_app::ports::shared::ResolvedCaller;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_cases::signals::caller::{ReceiverCaller, SignalsCaller};
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;

use crate::error::ApiError;
use crate::extractors::callers::TenantCaller;
use crate::extractors::paths::signals::StreamPath;
use crate::extractors::public_tenant::PublicTenant;
use crate::state::ApiState;

/// The receiver of a tenant's signal stream, calling without a session.
///
/// It holds no credential here: the challenge in its body, or its stream's
/// key, is the proof, which the app checks. The tenant is the open one the
/// path names, scoped as the request resolved it. A path naming no tenant,
/// or a closed one, answers as a proof that does not hold.
pub(crate) struct StreamReceiver {
    /// The tenant the path names.
    pub tenant: ScopedTenant,
    /// Records what the request changes, in the tenant, with the client's
    /// address.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for StreamReceiver {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let public = PublicTenant::from_request_parts(parts, state)
            .await
            .map_err(as_unproven)?;
        Ok(Self {
            tenant: public.tenant,
            auditor: public.auditor,
        })
    }
}

/// A tenant the path names that is missing or closed, answered as a proof
/// that does not hold.
///
/// Only a receiver holding its stream's challenge or key has any use for
/// these routes. Without this, Mallory, holding neither, tries tenant names
/// and learns from a `404` or a `403` which exist and which are closed.
fn as_unproven(refused: ApiError) -> ApiError {
    match refused.0 {
        AppError::Internal(_) => refused,
        _ => ApiError(AppError::Unauthenticated),
    }
}

/// Who manages the stream the path names: a person acting in the tenant,
/// whose session or key the auth middleware resolved, or else the stream's
/// receiver, presenting its stream's key as the bearer.
///
/// A receiver's key resolves to no caller, so a bearer the middleware did
/// not know is taken as one. Whether it is the stream's key is the app's
/// question, answered `401` like an unknown session when it is not. The key
/// is never logged and never put in an answer.
pub(crate) struct StreamCaller {
    /// Who is calling, as the signals use cases take them.
    pub caller: SignalsCaller,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for StreamCaller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        if parts.extensions.get::<ResolvedCaller>().is_some() {
            let person = TenantCaller::from_request_parts(parts, state).await?;
            return Ok(Self {
                caller: SignalsCaller::Person(person.caller),
                auditor: person.auditor,
            });
        }
        let key = bearer_key(parts).ok_or(ApiError(AppError::Unauthenticated))?;
        let Path(path) = Path::<StreamPath>::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError(AppError::NotFound(message!("api-not-found", "not found"))))?;
        let receiver = StreamReceiver::from_request_parts(parts, state).await?;
        Ok(Self {
            caller: SignalsCaller::Receiver(ReceiverCaller {
                tenant: receiver.tenant,
                stream_id: path.stream(),
                key,
            }),
            auditor: receiver.auditor,
        })
    }
}

/// The bearer of `parts`' `Authorization` header, if it carries one.
fn bearer_key(parts: &Parts) -> Option<Secret> {
    let header = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let key = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))?;
    (!key.is_empty()).then(|| Secret::new(key.to_owned()))
}
