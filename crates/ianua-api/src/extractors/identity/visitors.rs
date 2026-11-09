//! Someone nobody has signed in yet, following an emailed link or filling
//! in a public form on the tenant or organization the path names.
//!
//! The path names where the request belongs; the link's token, or the form,
//! is what the use case checks. These extractors find the organization and
//! tenant, scope the request to them, and record it as an anonymous request
//! there. They decide nothing about the token.

use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use ianua_app::auditor::RequestAuditor;
use ianua_app::email::LinkScope;
use ianua_app::error::AppError;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::domains::organization::billing::plan::PlanLimits;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::Fact;

use crate::error::ApiError;
use crate::extractors::callers::{RequestMeta, organization_named, tenant_named};
use crate::extractors::paths::identity::{OrgPath, TenantPath};
use crate::state::ApiState;

/// A visitor to the tenant the path names.
pub(crate) struct TenantVisitor {
    /// The tenant, as the request resolved it.
    pub tenant: ScopedTenant,
    /// Where a link mailed from this request lands.
    pub scope: LinkScope,
    /// The limits of the plan the tenant's organization is on.
    pub plan_limits: PlanLimits,
    /// Records what the request changes, as an anonymous request in the
    /// tenant.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for TenantVisitor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let Path(path) = Path::<TenantPath>::from_request_parts(parts, state)
            .await
            .map_err(|_| not_found())?;
        let organization = organization_named(state, path.organization()).await?;
        let tenant = tenant_named(state, path.tenant(), &organization).await?;
        let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
        let context = AuditContext::anonymous(*organization.id())
            .with_tenant(*tenant.id())
            .with_request(
                Fact::from_option(meta.ip_address),
                Fact::from_option(meta.user_agent),
            );
        Ok(Self {
            tenant: ScopedTenant::from(&ResolvedTenant::new(*tenant.id(), tenant.slug().clone())),
            scope: path.link_scope(),
            plan_limits: organization.limits(),
            auditor: RequestAuditor::new(state.event_dispatcher.clone(), context),
        })
    }
}

/// A visitor to the organization the path names.
pub(crate) struct OrgVisitor {
    /// Where a link mailed from this request lands.
    pub scope: LinkScope,
    /// Records what the request changes, as an anonymous request in the
    /// organization.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for OrgVisitor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let Path(path) = Path::<OrgPath>::from_request_parts(parts, state)
            .await
            .map_err(|_| not_found())?;
        let organization = organization_named(state, path.organization()).await?;
        let Ok(meta) = RequestMeta::from_request_parts(parts, state).await;
        let context = AuditContext::anonymous(*organization.id()).with_request(
            Fact::from_option(meta.ip_address),
            Fact::from_option(meta.user_agent),
        );
        Ok(Self {
            scope: path.link_scope(),
            auditor: RequestAuditor::new(state.event_dispatcher.clone(), context),
        })
    }
}

/// A plain `404` that says nothing of what was missing.
fn not_found() -> ApiError {
    ApiError(AppError::NotFound(message!("api-not-found", "not found")))
}
