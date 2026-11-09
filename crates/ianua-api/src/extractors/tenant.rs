//! Callers of the tenant endpoints that the shared caller extractors do not
//! give as they are: a steward who may be a member of the organization or
//! an operator, whoever lists or reads a tenant, and the tenant a path
//! names.
//!
//! These say who is calling and where. What they may do is the app's
//! question.

use axum::extract::{FromRequestParts, RawPathParams};
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::context::CallerIdentity;
use ianua_app::error::AppError;
use ianua_app::ports::shared::ResolvedCaller;
use ianua_app::use_cases::tenant::lifecycle::steward::TenantSteward;
use ianua_app::use_cases::tenant::lifecycle::{TenantLister, TenantViewer};
use ianua_domain::message;
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::types::{OrganizationId, TenantId, TenantSlug};

use crate::error::ApiError;
use crate::extractors::callers::{Operator, OrgMember, TenantCaller};
use crate::state::ApiState;

/// The tenant the path's `{org_slug}` and `{tenant_slug}` name.
///
/// A slug that names nothing is `404`, as it is for every caller.
pub(crate) struct TenantInPath(pub TenantId);

impl FromRequestParts<ApiState> for TenantInPath {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let organization = organization_named(parts, state).await?;
        let slug = path_slug(parts, state, "tenant_slug").await?;
        let tenant = state
            .tenant_store
            .find_by_slug_in_org(&slug, &organization)
            .await
            .map_err(AppError::internal)?
            .ok_or_else(not_found)?;
        Ok(Self(*tenant.id()))
    }
}

/// Whoever moves a tenant of the organization the path names through its
/// life: one of its members, or an operator acting for the platform.
pub(crate) struct Steward {
    /// The member or operator.
    pub caller: TenantSteward,
    /// The organization the path names.
    pub organization: OrganizationId,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for Steward {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        if let CallerIdentity::Operator(_) = caller_identity(parts)? {
            let organization = organization_named(parts, state).await?;
            let operator = Operator::from_request_parts(parts, state).await?;
            return Ok(Self {
                caller: TenantSteward::Platform(operator.caller),
                organization,
                auditor: operator.auditor,
            });
        }
        let member = OrgMember::from_request_parts(parts, state).await?;
        Ok(Self {
            organization: member.caller.organization_id(),
            caller: TenantSteward::Member(member.caller),
            auditor: member.auditor,
        })
    }
}

/// Whoever lists the tenants of the organization the path names: one of
/// its members, or an operator.
pub(crate) struct Lister(pub TenantLister);

impl FromRequestParts<ApiState> for Lister {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        if let CallerIdentity::Operator(_) = caller_identity(parts)? {
            let organization = organization_named(parts, state).await?;
            let operator = Operator::from_request_parts(parts, state).await?;
            return Ok(Self(TenantLister::Platform {
                caller: operator.caller,
                organization: Some(organization),
            }));
        }
        let member = OrgMember::from_request_parts(parts, state).await?;
        Ok(Self(TenantLister::Member(member.caller)))
    }
}

/// Whoever reads the tenant the path names: someone acting in it, a member
/// of its organization, or an operator.
pub(crate) struct Viewer(pub TenantViewer);

impl FromRequestParts<ApiState> for Viewer {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        match caller_identity(parts)? {
            CallerIdentity::TenantUser(_) => {
                let tenant = TenantCaller::from_request_parts(parts, state).await?;
                Ok(Self(TenantViewer::Tenant(tenant.caller)))
            }
            CallerIdentity::OrgUser(_) => {
                let member = OrgMember::from_request_parts(parts, state).await?;
                let TenantInPath(tenant_id) =
                    TenantInPath::from_request_parts(parts, state).await?;
                Ok(Self(TenantViewer::Organization {
                    caller: member.caller,
                    tenant_id,
                }))
            }
            CallerIdentity::Operator(_) => {
                let operator = Operator::from_request_parts(parts, state).await?;
                let TenantInPath(tenant_id) =
                    TenantInPath::from_request_parts(parts, state).await?;
                Ok(Self(TenantViewer::Platform {
                    caller: operator.caller,
                    tenant_id,
                }))
            }
        }
    }
}

/// Who the auth middleware found, or `401` when there is no one.
fn caller_identity(parts: &Parts) -> Result<CallerIdentity, ApiError> {
    parts
        .extensions
        .get::<ResolvedCaller>()
        .map(|resolved| resolved.identity)
        .ok_or(ApiError(AppError::Unauthenticated))
}

/// The organization the path's `{org_slug}` names.
async fn organization_named(
    parts: &mut Parts,
    state: &ApiState,
) -> Result<OrganizationId, ApiError> {
    let slug = path_slug(parts, state, "org_slug").await?;
    let organization = state
        .org_store
        .find_by_slug(&slug)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(not_found)?;
    Ok(*organization.id())
}

/// The slug the path segment `name` holds. One that is missing or not a
/// valid slug names nothing, so it is not found.
pub(crate) async fn path_slug(
    parts: &mut Parts,
    state: &ApiState,
    name: &str,
) -> Result<TenantSlug, ApiError> {
    let params = RawPathParams::from_request_parts(parts, state)
        .await
        .map_err(|_| not_found())?;
    let value = params
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
        .ok_or_else(not_found)?;
    TenantSlug::new(value, &SlugLimits::default()).map_err(|_| not_found())
}

/// The `404` for a path naming nothing, the same whatever was wrong.
fn not_found() -> ApiError {
    ApiError(AppError::NotFound(message!("api-not-found", "not found")))
}
