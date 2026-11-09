//! Get access request policy: the longest the tenant's people may ask for
//! access.
//!
//! Everyone who may ask reads it, so they know how long to ask for before
//! they do.

use std::sync::Arc;

use ianua_domain::domains::authorization::request_policy::AccessRequestPolicy;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::AccessRequestPolicyStore;
use crate::use_case::Query;
use crate::use_cases::authorization::access_requests::lookup::tenant_policy;

/// The ports [`GetPolicyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPolicyPorts {
    /// Reads the tenant's limit.
    pub policy_store: Arc<dyn AccessRequestPolicyStore>,
    /// Who the caller is in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads the longest the caller's tenant lets its people ask for access.
pub struct GetPolicyUseCase {
    ports: GetPolicyPorts,
}

impl GetPolicyUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetPolicyPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetPolicyUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<AccessRequestPolicy<ResolvedTenant>, AppError>;

    /// The tenant's limit, or the longest anyone may ask for when it never
    /// set one.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Internal` when the limit cannot be read.
    async fn execute(
        &self,
        ctx: &CallerContext,
        (): (),
    ) -> Result<AccessRequestPolicy<ResolvedTenant>, AppError> {
        self.ports.tenant_authorities.authority(ctx).await?;
        tenant_policy(self.ports.policy_store.as_ref(), &ctx.tenant()).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::access_request::AccessRequestLimits;
    use ianua_domain::types::Lifetime;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakeAccessRequestPolicyStore, stored_request_policy};
    use crate::test_support::{block_on, test_ctx};

    fn read(ports: GetPolicyPorts) -> Result<AccessRequestPolicy<ResolvedTenant>, AppError> {
        block_on(GetPolicyUseCase::new(ports).execute(&test_ctx(), ()))
    }

    /// Acme never set a limit. Ann reads the month anyone may ask for; once
    /// Acme holds requests to eight hours, she reads that.
    #[test]
    fn the_limit_read_is_the_tenants_or_the_longest() {
        let eight_hours = Lifetime::seconds(8 * 3600).unwrap();
        let set = FakeAccessRequestPolicyStore::holding(
            test_ctx().tenant_id(),
            stored_request_policy(eight_hours),
        );

        let unset = read(GetPolicyPorts::fakes()).unwrap();
        let held = read(GetPolicyPorts {
            policy_store: Arc::new(set),
            ..GetPolicyPorts::fakes()
        })
        .unwrap();

        assert_eq!(unset.limits(), AccessRequestLimits::WIDEST);
        assert_eq!(held.limits().longest(), eight_hours);
    }

    /// Reading the request limit requires a session that is still signed in.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = GetPolicyPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..GetPolicyPorts::fakes()
        };

        let result = read(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
