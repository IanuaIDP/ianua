//! Get an access request: one request of the tenant, by id, for the person
//! who asked it or someone who may view roles.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_request::AccessRequest;
use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AccessRequestId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::AccessRequestStore;
use crate::use_case::Query;
use crate::use_cases::authorization::access_requests::lookup::{existing_request, owned_request};

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Loads requests.
    pub request_store: Arc<dyn AccessRequestStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one access request of the caller's tenant.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = AccessRequestId;
    type Output = Result<AccessRequest<ResolvedTenant>, AppError>;

    /// The request `id`, as it stands now: to someone who may view roles,
    /// or to the person who asked it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::NotFound` when the tenant has no such request, or it is
    ///   someone else's and the caller may not view roles.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: AccessRequestId,
    ) -> Result<AccessRequest<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let store = self.ports.request_store.as_ref();
        let tenant = ctx.tenant();
        if authority
            .ensure_holds(SystemPermission::Roles(RoleAction::View))
            .is_ok()
        {
            return existing_request(store, &tenant, &id).await;
        }
        owned_request(store, &tenant, &id, &authority).await
    }
}
