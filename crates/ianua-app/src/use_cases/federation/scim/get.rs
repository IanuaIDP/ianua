//! Get SCIM: whether the tenant's directory provisions through SCIM, and how
//! the endpoint is set up, for the dashboard's SCIM card.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{ScimAction, SystemPermission};
use ianua_domain::domains::federation::scim::ScimEndpoint;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::ScimStore;
use crate::use_case::Query;

/// Whether SCIM is set up for the tenant. The endpoint holds only its
/// token's hash, so the token itself never comes back here.
#[derive(Debug)]
pub enum Status {
    /// SCIM was never set up.
    NotSetUp,
    /// The endpoint, on or off, with its settings and when it last synced.
    SetUp(ScimEndpoint<ResolvedTenant>),
}

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// The tenant's SCIM endpoint.
    pub scim_store: Arc<dyn ScimStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the tenant's SCIM endpoint.
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
    type Input = ();
    type Output = Result<Status, AppError>;

    /// Whether SCIM is set up, and how, for a caller who may view SCIM.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not view SCIM.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<Status, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::Scim(ScimAction::View))
            .map_err(AppError::from_domain)?;
        let endpoint = self
            .ports
            .scim_store
            .find(&ctx.tenant())
            .await
            .or_internal()?;
        Ok(endpoint.map_or(Status::NotSetUp, Status::SetUp))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::Enablement;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::federation::{FakeScimStore, test_scim_endpoint};
    use crate::test_support::{block_on, test_ctx};

    fn get(store: FakeScimStore, authorities: FakeTenantAuthorities) -> Result<Status, AppError> {
        let use_case = GetUseCase::new(GetPorts {
            scim_store: Arc::new(store),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), ()))
    }

    fn viewer() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Scim(ScimAction::View)])
    }

    /// Acme provisions through Okta over SCIM, switched off for now. Ann's
    /// SCIM card shows the endpoint, off.
    #[test]
    fn a_set_up_endpoint_is_shown() {
        let store = FakeScimStore::holding(
            &test_ctx().tenant(),
            test_scim_endpoint("hash:token", Enablement::Disabled),
        );

        let status = get(store, viewer()).unwrap();

        let Status::SetUp(endpoint) = status else {
            panic!("SCIM is set up");
        };
        assert!(!endpoint.enabled());
    }

    /// Acme never set SCIM up. The card says so.
    #[test]
    fn a_tenant_without_scim_is_not_set_up() {
        let status = get(FakeScimStore::empty(), viewer()).unwrap();

        assert!(matches!(status, Status::NotSetUp));
    }

    /// Reading SCIM settings requires the tenant's viewing right, even when
    /// no endpoint is configured.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let result = get(FakeScimStore::empty(), FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read SCIM settings.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = get(
            FakeScimStore::empty(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
