//! Who links their own accounts across the tenants of an organization: the
//! person signed in to the account joining a group, and, when the group
//! exists already, signed in to one of its accounts as well.
//!
//! The second sign-in comes as the bearer token of that session in the
//! `X-Linked-Session` header. Both are only resolved here; whether they
//! belong to the same person is the app's question.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::CallerContext;
use ianua_app::error::AppError;
use ianua_app::ports::shared::ResolvedCaller;
use ianua_app::use_cases::organization::members::LinkingPerson;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;

use crate::error::ApiError;
use crate::extractors::callers::{RequestMeta, TenantCaller};
use crate::state::ApiState;

/// The header carrying the bearer token of the person's session in an
/// account already in the group.
pub(crate) const LINKED_SESSION_HEADER: &str = "x-linked-session";

/// A person linking their accounts, signed in to each end.
pub(crate) struct LinkingCaller {
    /// The person, with their session in each account.
    pub person: LinkingPerson,
    /// Records what the request changes, in the joining account's tenant.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for LinkingCaller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let joining = TenantCaller::from_request_parts(parts, state).await?;
        let already_linked = linked_session(parts, state).await?;
        Ok(Self {
            person: LinkingPerson {
                joining: joining.caller,
                already_linked,
            },
            auditor: joining.auditor,
        })
    }
}

/// The session the `X-Linked-Session` header names, in its own tenant, or
/// none when the header is absent.
async fn linked_session(
    parts: &mut Parts,
    state: &ApiState,
) -> Result<Option<CallerContext>, ApiError> {
    let Some(value) = parts.headers.get(LINKED_SESSION_HEADER) else {
        return Ok(None);
    };
    let token = value
        .to_str()
        .map(|raw| Secret::new(raw.trim().trim_start_matches("Bearer ").to_owned()))
        .map_err(|_| {
            ApiError::validation(message!(
                "api-the-linked-session-token-is-not",
                "the linked session token is not readable text"
            ))
        })?;
    let resolved = state
        .token_resolver
        .resolve(&token)
        .await
        .map_err(AppError::internal)?
        .ok_or(ApiError(AppError::Unauthenticated))?;
    linked_caller(parts, state, resolved).await.map(Some)
}

/// Builds the linked tenant caller only after resolving its organization and request metadata.
async fn linked_caller(
    parts: &mut Parts,
    state: &ApiState,
    resolved: ResolvedCaller,
) -> Result<CallerContext, ApiError> {
    let (Some(organization_id), Some(tenant_id)) = (resolved.organization_id, resolved.tenant_id)
    else {
        return Err(ApiError(AppError::Forbidden(message!(
            "api-the-linked-session-is-not-a",
            "the linked session is not a tenant account's"
        ))));
    };
    let organization = state
        .org_store
        .find_by_id(&organization_id)
        .await
        .map_err(AppError::internal)?
        .ok_or(ApiError(AppError::Unauthenticated))?;
    let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
    let caller = CallerContext::new(
        resolved.identity,
        resolved.credential,
        organization_id,
        tenant_id,
        organization.limits(),
    )?
    .with_request_metadata(meta.ip_address, meta.user_agent);
    Ok(caller)
}
