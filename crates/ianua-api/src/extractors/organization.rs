//! Callers of the organization endpoints that the shared caller extractors
//! do not give as they are: a steward who may be a member or an operator,
//! a member acting from their own organization on a path that names none,
//! a visitor on an organization's public pages, and where an emailed link
//! for the organization lands.
//!
//! These say who is calling and where. What they may do is the app's
//! question.

pub mod billing;
pub mod cloud;
pub mod members;
pub mod platform;
pub mod sign_in;

use axum::extract::{FromRequestParts, RawPathParams};
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::{CallerIdentity, OrgCaller};
use ianua_app::email::LinkScope;
use ianua_app::error::AppError;
use ianua_app::ports::shared::ResolvedCaller;
use ianua_app::use_cases::organization::steward::OrganizationSteward;
use ianua_domain::message;
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::types::{OrganizationId, TenantSlug};

use crate::error::ApiError;
use crate::extractors::callers::{
    Operator, OrgMember, RequestMeta, Visitor, org_credential, resolved_caller,
};
use crate::state::ApiState;

/// Whoever takes a platform action on the organization the path names: one
/// of its members, or an operator acting for the platform.
pub(crate) struct OrgSteward {
    /// The member or operator.
    pub caller: OrganizationSteward,
    /// The organization the path names.
    pub organization: OrganizationId,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for OrgSteward {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        match caller_identity(parts)? {
            CallerIdentity::Operator(_) => Self::operator(parts, state).await,
            CallerIdentity::OrgUser(_) | CallerIdentity::TenantUser(_) => {
                Self::member(parts, state).await
            }
        }
    }
}

impl OrgSteward {
    /// An operator acting for the platform on the organization the path
    /// names, which must exist.
    async fn operator(parts: &mut Parts, state: &ApiState) -> Result<Self, ApiError> {
        let organization = organization_named(parts, state).await?;
        let operator = Operator::from_request_parts(parts, state).await?;
        Ok(Self {
            caller: OrganizationSteward::Platform(operator.caller),
            organization,
            auditor: operator.auditor,
        })
    }

    /// A member acting on their own organization.
    async fn member(parts: &mut Parts, state: &ApiState) -> Result<Self, ApiError> {
        let member = OrgMember::from_request_parts(parts, state).await?;
        Ok(Self {
            organization: member.caller.organization_id(),
            caller: OrganizationSteward::Member(member.caller),
            auditor: member.auditor,
        })
    }
}

/// A member acting from their own organization, on a path that names
/// none: founding another organization. The organization is the one their
/// credential belongs to, never one the request chooses.
pub(crate) struct HomeMember {
    /// Who is calling, and with what credential.
    pub caller: OrgCaller,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for HomeMember {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let resolved = resolved_caller(parts)?;
        let (member, credential) = org_credential(&resolved)?;
        let organization = resolved
            .organization_id
            .ok_or(ApiError(AppError::Unauthenticated))?;
        let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
        let caller = OrgCaller::new(member, credential, organization)
            .with_request_metadata(meta.ip_address, meta.user_agent);
        Ok(Self {
            auditor: RequestAuditor::new(state.event_dispatcher.clone(), caller.audit_context()),
            caller,
        })
    }
}

/// Someone nobody has identified yet, on a public page of the organization
/// the path names: accepting an invitation, confirming an address.
pub(crate) struct OrgVisitor {
    /// Records what the request changes.
    pub auditor: RequestAuditor,
    /// The organization the path names.
    pub organization: OrganizationId,
    /// Where links mailed for this organization land.
    pub links: LinkScope,
}

impl FromRequestParts<ApiState> for OrgVisitor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let organization = organization_named(parts, state).await?;
        let OrgLinks(links) = OrgLinks::from_request_parts(parts, state).await?;
        let Ok(visitor) = Visitor::from_request_parts(parts, state).await;
        Ok(Self {
            auditor: visitor.auditor,
            organization,
            links,
        })
    }
}

/// Where links mailed for the organization the path names land: its own
/// pages, above any tenant.
pub(crate) struct OrgLinks(pub LinkScope);

impl FromRequestParts<ApiState> for OrgLinks {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let slug = org_slug(parts, state).await?;
        Ok(Self(LinkScope::organization(slug)))
    }
}

/// Who the auth middleware found, or `401` when nobody was.
fn caller_identity(parts: &Parts) -> Result<CallerIdentity, ApiError> {
    parts
        .extensions
        .get::<ResolvedCaller>()
        .map(|resolved| resolved.identity)
        .ok_or(ApiError(AppError::Unauthenticated))
}

/// The organization slug of the path. A slug that is not a valid one names
/// nothing, so it is not found.
async fn org_slug(parts: &mut Parts, state: &ApiState) -> Result<TenantSlug, ApiError> {
    let params = RawPathParams::from_request_parts(parts, state)
        .await
        .map_err(|_| not_found())?;
    let value = params
        .iter()
        .find(|(key, _)| *key == "org_slug")
        .map(|(_, value)| value.to_owned())
        .ok_or_else(not_found)?;
    TenantSlug::new(&value, &SlugLimits::default()).map_err(|_| not_found())
}

/// The id of the organization the path names.
async fn organization_named(
    parts: &mut Parts,
    state: &ApiState,
) -> Result<OrganizationId, ApiError> {
    let slug = org_slug(parts, state).await?;
    let organization = state
        .org_store
        .find_by_slug(&slug)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(not_found)?;
    Ok(*organization.id())
}

/// The `404` for a path naming no organization, the same whatever was wrong.
fn not_found() -> ApiError {
    ApiError(AppError::NotFound(message!("api-not-found", "not found")))
}
