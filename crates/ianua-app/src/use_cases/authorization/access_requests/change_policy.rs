//! Change access request policy: set the longest the tenant's people may
//! ask for access.
//!
//! Requests already made keep the length they asked for; the next one is
//! held to the new limit.

use std::sync::Arc;

use ianua_domain::domains::authorization::access_request::AccessRequestLimits;
use ianua_domain::domains::authorization::request_policy::AccessRequestPolicy;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::Lifetime;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::AccessRequestPolicyStore;
use crate::use_case::Command;
use crate::use_cases::authorization::access_requests::lookup::tenant_policy;

/// The ports [`ChangePolicyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangePolicyPorts {
    /// Loads and saves the tenant's limit.
    pub policy_store: Arc<dyn AccessRequestPolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Sets the longest the caller's tenant lets its people ask for access.
pub struct ChangePolicyUseCase {
    ports: ChangePolicyPorts,
}

impl ChangePolicyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangePolicyPorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangePolicyUseCase {
    type Caller = CallerContext;
    type Input = Lifetime;
    type Output = Result<AccessRequestPolicy<ResolvedTenant>, AppError>;

    /// Holds the tenant's requests to at most `longest` from now on, for the
    /// caller, and records the limit before and after. Setting the limit
    /// already set records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update roles.
    /// - `AppError::Domain` when `longest` is past the month anyone may ask
    ///   for.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        longest: Lifetime,
    ) -> Result<AccessRequestPolicy<ResolvedTenant>, AppError> {
        let tenant = ctx.tenant();
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let limits = AccessRequestLimits::new(longest).map_err(AppError::from_domain)?;
        let store = self.ports.policy_store.as_ref();
        let mut policy = tenant_policy(store, &tenant).await?;
        policy
            .change_limits(limits, &authority)
            .map_err(AppError::from_domain)?;

        store.save(&tenant, &policy).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), policy.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{RoleAction, SystemPermission};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeAccessRequestPolicyStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn hours(count: i64) -> Lifetime {
        Lifetime::seconds(count * 3600).unwrap()
    }

    fn change(
        policies: &Arc<FakeAccessRequestPolicyStore>,
        authorities: FakeTenantAuthorities,
        sink: &Arc<FakeEventDispatcher>,
        longest: Lifetime,
    ) -> Result<AccessRequestPolicy<ResolvedTenant>, AppError> {
        let use_case = ChangePolicyUseCase::new(ChangePolicyPorts {
            policy_store: policies.clone(),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(sink.clone()), longest))
    }

    fn updater() -> FakeTenantAuthorities {
        FakeTenantAuthorities::holding(&[SystemPermission::Roles(RoleAction::Update)])
    }

    /// Ann, who may update roles, holds Acme's requests to eight hours. The
    /// limit is saved and the change recorded.
    #[test]
    fn the_limit_is_saved_and_recorded() {
        let policies = Arc::new(FakeAccessRequestPolicyStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());

        change(&policies, updater(), &sink, hours(8)).unwrap();

        assert_eq!(policies.longest_of(test_ctx().tenant_id()), Some(hours(8)));
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.access_request_policy_changed"]
        );
    }

    /// Role view permission cannot raise the access-request duration limit.
    /// The refusal leaves the policy unset and the audit trail empty.
    #[test]
    fn a_caller_who_may_not_update_roles_is_refused() {
        let policies = Arc::new(FakeAccessRequestPolicyStore::empty());
        let sink = Arc::new(FakeEventDispatcher::new());
        let viewer = FakeTenantAuthorities::holding(&[SystemPermission::Roles(RoleAction::View)]);

        let result = change(&policies, viewer, &sink, hours(24 * 30));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(policies.longest_of(test_ctx().tenant_id()), None);
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A forty-day request limit exceeds the permitted month and is rejected.
    #[test]
    fn a_limit_past_a_month_is_refused() {
        let policies = Arc::new(FakeAccessRequestPolicyStore::empty());

        let result = change(
            &policies,
            updater(),
            &Arc::new(FakeEventDispatcher::new()),
            hours(24 * 40),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Changing the request limit rejects a signed-out session as unauthenticated.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let policies = Arc::new(FakeAccessRequestPolicyStore::empty());
        let signed_out = FakeTenantAuthorities::refusing(Refusal::SignedOut);

        let result = change(
            &policies,
            signed_out,
            &Arc::new(FakeEventDispatcher::new()),
            hours(8),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
