//! Agents calling in their own name, with no session.
//!
//! An agent signs in by what it presents: a platform attestation, an
//! assertion its own key signed, or the task token a delegation gave it.
//! These extractors only say which tenant the path names and hand the use
//! case what the agent presented. Whether it proves anything is the app's
//! question: the app verifies the attestation, the assertion or the token
//! against the stored records and refuses whatever does not hold.
//!
//! - [`AgentEndpoint`]: bootstrap, its challenge and the token exchange,
//!   where the proof travels in the body.
//! - [`AgentRelayCaller`]: the message relay, where the agent's task token
//!   is its `Authorization: Bearer` credential.
//! - [`AttenuatingCaller`]: passing part of a delegation on, by a person
//!   with a session or by the agent holding it, signing an assertion.
//! - [`AskingAgentCaller`]: an agent asking a person for a delegation,
//!   signing an assertion.
//! - [`ReviewerAgent`]: the review desk, where the reviewer signs an
//!   assertion and names itself.
//!
//! An agent's assertion travels in the [`ASSERTION_HEADER`] header, and a
//! reviewer names itself in the [`AGENT_ID_HEADER`] header: an assertion is
//! checked against the keys of the agent it is presented for, so the agent
//! has to be named beside it.

use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Path, Request};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::AgentAssertion;
use ianua_app::error::AppError;
use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::audit::AuditLogSortField;
use ianua_app::tenancy::ScopedTenant;
use ianua_app::use_cases::agents::delegation::{AskingAgent, Attenuating};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::AgentId;
use serde::Deserialize;
use uuid::Uuid;

use crate::dto::agents::evidence::ActivityQueryParams;
use crate::error::ApiError;
use crate::extractors::callers::{
    PathSlugs, TenantCaller, Visitor, organization_named, tenant_named,
};
use crate::extractors::listing::PageQuery;
use crate::extractors::paths::agents::{AgentDelegationPath, AgentPath};
use crate::extractors::query::QueryRefusal;
use crate::extractors::sort::SortQuery;
use crate::state::ApiState;

/// The header an agent's signed assertion travels in.
pub(crate) const ASSERTION_HEADER: &str = "ianua-agent-assertion";

/// The header a reviewer agent names itself in.
pub(crate) const AGENT_ID_HEADER: &str = "ianua-agent-id";

/// An activity timeline's ordering, filters and page, checked in that order.
pub(crate) struct ActivityPage {
    /// Which audit fields order the activity.
    pub sort: SortOrder<AuditLogSortField>,
    /// The activity filters supplied by the caller.
    pub query: ActivityQueryParams,
    /// The checked cursor and page size.
    pub page: PageRequest,
}

impl<S: Send + Sync> FromRequestParts<S> for ActivityPage {
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let SortQuery(sort) =
            SortQuery::<AuditLogSortField>::from_request_parts(parts, state).await?;
        let PageQuery { query, page } =
            PageQuery::<ActivityQueryParams>::from_request_parts(parts, state).await?;
        Ok(Self { sort, query, page })
    }
}

/// An agent calling before it holds anything the API could read: the
/// tenant the path names, and an auditor that records the client's
/// address. The proof is in the body, for the use case to check.
pub(crate) struct AgentEndpoint {
    /// The tenant the path names.
    pub tenant: ScopedTenant,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for AgentEndpoint {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let tenant = path_tenant(parts, state).await?;
        let Ok(visitor) = Visitor::from_request_parts(parts, state).await;
        Ok(Self {
            tenant,
            auditor: visitor.auditor,
        })
    }
}

/// An agent at the message relay, presenting its task token.
pub(crate) struct AgentRelayCaller {
    /// The tenant the path names; the token must have been issued for it.
    pub tenant: ScopedTenant,
    /// The task token from `Authorization: Bearer`.
    pub credential: Secret,
    /// Records the relay's decisions.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for AgentRelayCaller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let credential = bearer(parts)?;
        let endpoint = AgentEndpoint::from_request_parts(parts, state).await?;
        Ok(Self {
            tenant: endpoint.tenant,
            credential,
            auditor: endpoint.auditor,
        })
    }
}

/// Whoever passes part of a delegation on: a person with a say over the
/// agent holding it, or that agent itself.
///
/// A request carrying an assertion in [`ASSERTION_HEADER`] is the agent
/// named in the path signing in as itself; any other request is a person
/// and needs a tenant caller's credential.
pub(crate) struct AttenuatingCaller {
    /// Who passes it on.
    pub by: Attenuating,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for AttenuatingCaller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let Some(assertion) = header(parts, ASSERTION_HEADER) else {
            let person = TenantCaller::from_request_parts(parts, state).await?;
            return Ok(Self {
                by: Attenuating::Person(Box::new(person.caller)),
                auditor: person.auditor,
            });
        };
        let Path(path) = Path::<AgentDelegationPath>::from_request_parts(parts, state)
            .await
            .map_err(|rejection| ApiError::rejected(rejection.body_text()))?;
        let endpoint = AgentEndpoint::from_request_parts(parts, state).await?;
        Ok(Self {
            by: Attenuating::Agent {
                tenant: endpoint.tenant,
                assertion: AgentAssertion {
                    agent_id: path.agent(),
                    assertion,
                },
            },
            auditor: endpoint.auditor,
        })
    }
}

/// An agent asking a person for a delegation, signed in as itself: the
/// agent the path names, presenting the assertion it signed in
/// [`ASSERTION_HEADER`].
pub(crate) struct AskingAgentCaller {
    /// The agent asking, in the tenant the path names.
    pub asking: AskingAgent,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for AskingAgentCaller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let assertion = header(parts, ASSERTION_HEADER).ok_or_else(unauthenticated)?;
        let Path(path) = Path::<AgentPath>::from_request_parts(parts, state)
            .await
            .map_err(|rejection| ApiError::rejected(rejection.body_text()))?;
        let endpoint = AgentEndpoint::from_request_parts(parts, state).await?;
        Ok(Self {
            asking: AskingAgent {
                tenant: endpoint.tenant,
                assertion: AgentAssertion {
                    agent_id: path.agent(),
                    assertion,
                },
            },
            auditor: endpoint.auditor,
        })
    }
}

/// A reviewer agent at the review desk: the agent it names in
/// [`AGENT_ID_HEADER`] and the assertion it signed in [`ASSERTION_HEADER`].
pub(crate) struct ReviewerAgent {
    /// The tenant the path names.
    pub tenant: ScopedTenant,
    /// The reviewer and the assertion its key signed.
    pub reviewer: AgentAssertion,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for ReviewerAgent {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let assertion = header(parts, ASSERTION_HEADER).ok_or_else(unauthenticated)?;
        let agent_id = header(parts, AGENT_ID_HEADER)
            .and_then(|id| Uuid::parse_str(&id).ok())
            .map(AgentId::from_uuid)
            .ok_or_else(unauthenticated)?;
        let endpoint = AgentEndpoint::from_request_parts(parts, state).await?;
        Ok(Self {
            tenant: endpoint.tenant,
            reviewer: AgentAssertion {
                agent_id,
                assertion,
            },
            auditor: endpoint.auditor,
        })
    }
}

/// A fresh second-factor code, when the request carries one.
///
/// Approving a high-risk agent action needs the approver to answer their
/// second factor right then. The code travels in an optional JSON body,
/// `{"mfa_code": "123456"}`, so a request that needs none can send no body
/// at all.
pub(crate) struct StepUpCode(pub Option<String>);

#[derive(Deserialize)]
struct StepUpBody {
    #[serde(default)]
    mfa_code: Option<String>,
}

impl<S: Send + Sync> FromRequest<S> for StepUpCode {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|rejection| ApiError::rejected(rejection.body_text()))?;
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self(None));
        }
        let parsed: StepUpBody = serde_json::from_slice(&body).map_err(|_| {
            ApiError::validation(message!(
                "api-the-body-must-be",
                "the body must be {\"mfa_code\": \"...\"}"
            ))
        })?;
        Ok(Self(parsed.mfa_code.filter(|code| !code.trim().is_empty())))
    }
}

/// The tenant the path names, as a store call may be scoped to it.
///
/// A tenant that is missing or closed answers as a proof that does not
/// hold. An agent calling here holds nothing the API could read yet.
/// Without this, Mallory, holding no proof, tries tenant names and learns
/// from a `404` or a `403` which exist and which are suspended.
async fn path_tenant(parts: &mut Parts, state: &ApiState) -> Result<ScopedTenant, ApiError> {
    named_tenant(parts, state)
        .await
        .map_err(|refused| match refused.0 {
            AppError::Internal(_) => refused,
            _ => unauthenticated(),
        })
}

/// The open tenant the path names.
async fn named_tenant(parts: &mut Parts, state: &ApiState) -> Result<ScopedTenant, ApiError> {
    let slugs = PathSlugs::of(parts, state).await?;
    let organization = organization_named(state, slugs.organization()?).await?;
    let tenant = tenant_named(state, slugs.tenant()?, &organization).await?;
    Ok(ScopedTenant::from(&ResolvedTenant::new(
        *tenant.id(),
        tenant.slug().clone(),
    )))
}

/// The `Authorization: Bearer` credential, or `401` without one.
fn bearer(parts: &Parts) -> Result<Secret, ApiError> {
    parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(Secret::new)
        .ok_or_else(unauthenticated)
}

/// The value of header `name`, when it is present, readable and not blank.
fn header(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// The `401` for a caller whose credential is missing or not honoured.
fn unauthenticated() -> ApiError {
    ApiError(AppError::Unauthenticated)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The second-factor code read from a request carrying `body`.
    async fn code_of(body: &'static str) -> Result<Option<String>, ApiError> {
        let req = Request::builder()
            .body(axum::body::Body::from(body))
            .unwrap();
        StepUpCode::from_request(req, &())
            .await
            .map(|StepUpCode(code)| code)
    }

    /// An approver who sends no body sends no code.
    #[tokio::test]
    async fn no_body_is_no_code() {
        assert_eq!(code_of("").await.ok().flatten(), None);
    }

    /// Ann types her code and it is read from the body as she sent it.
    #[tokio::test]
    async fn a_code_is_read_from_the_body() {
        assert_eq!(
            code_of(r#"{"mfa_code":"246810"}"#)
                .await
                .ok()
                .flatten()
                .as_deref(),
            Some("246810")
        );
    }

    /// A code of only spaces counts as no code at all.
    #[tokio::test]
    async fn an_empty_code_is_no_code() {
        assert_eq!(code_of(r#"{"mfa_code":"  "}"#).await.ok().flatten(), None);
    }

    /// A bare code that is not wrapped in JSON is refused.
    #[tokio::test]
    async fn a_body_that_is_not_json_is_refused() {
        assert!(code_of("246810").await.is_err());
    }
}
