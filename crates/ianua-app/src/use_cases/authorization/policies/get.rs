//! Get policy: the tenant's live policy and the draft open beside it, the
//! two an editor works between.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{PolicySetAction, SystemPermission};
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::policy::version::PolicyHistory;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::authorization::PolicyStore;
use crate::use_case::Query;
use crate::use_cases::authorization::lookup::policy_versions;

/// The ports [`GetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Loads the policy's versions.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// The versions of a tenant's policy in use now.
#[derive(Debug, Clone)]
pub struct Overview {
    /// The version deciding requests, if any.
    pub live: Option<PolicySet>,
    /// The draft being written or reviewed beside it, if any.
    pub draft: Option<PolicySet>,
}

/// Reads the live policy and the open draft of the caller's tenant.
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
    type Output = Result<Overview, AppError>;

    /// The tenant's live version and its open draft, either missing when
    /// there is none.
    ///
    /// A tenant that has not started is nothing exceptional, so it is not
    /// an error. Nor is it shown a policy that allows everything: what an
    /// editor opens for a tenant without one is the editor's choice.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the policy.
    /// - `AppError::Internal` when the versions cannot be read, or two are
    ///   live or open at once.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<Overview, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::PolicySet(PolicySetAction::View))
            .map_err(AppError::from_domain)?;
        let versions = policy_versions(self.ports.policy_store.as_ref(), &ctx.tenant()).await?;
        let history = PolicyHistory::of(&versions).map_err(AppError::from_domain)?;
        Ok(Overview {
            live: history.live().cloned(),
            draft: history.open().cloned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakePolicyStore, draft_beside, policy_in};
    use crate::test_support::{block_on, test_ctx};

    fn get(ports: GetPorts) -> Result<Overview, AppError> {
        block_on(GetUseCase::new(ports).execute(&test_ctx(), ()))
    }

    fn holding_a_draft() -> GetPorts {
        GetPorts {
            policy_store: Arc::new(FakePolicyStore::holding(
                test_ctx().tenant_id(),
                PolicySet::permissive(),
            )),
            ..GetPorts::fakes()
        }
    }

    /// Ann's tenant has only a draft. She reads it, and nothing live.
    #[test]
    fn the_tenants_draft_is_read() {
        let overview = get(holding_a_draft()).unwrap();

        assert!(
            overview
                .draft
                .is_some_and(|policy| policy.status().is_editable())
        );
        assert!(overview.live.is_none());
    }

    /// Ann's tenant has a live version and a draft beside it. She reads
    /// both, each as it is.
    #[test]
    fn the_live_version_and_the_draft_beside_it_are_read() {
        let live = policy_in(PolicyStatus::Active, Vec::new());
        let draft = draft_beside(&live);
        let ports = GetPorts {
            policy_store: Arc::new(FakePolicyStore::holding_versions(
                test_ctx().tenant_id(),
                [live, draft],
            )),
            ..GetPorts::fakes()
        };

        let overview = get(ports).unwrap();

        assert!(overview.live.is_some_and(|live| live.status().is_active()));
        assert!(
            overview
                .draft
                .is_some_and(|draft| draft.status().is_editable())
        );
    }

    /// Ann's tenant never saved a policy. She reads none, not an error.
    #[test]
    fn a_tenant_without_a_policy_reads_none() {
        let overview = get(GetPorts::fakes()).unwrap();

        assert!(overview.live.is_none() && overview.draft.is_none());
    }

    /// Reading the policy is forbidden without policy view permission.
    #[test]
    fn a_caller_who_may_not_view_the_policy_is_refused() {
        let ports = GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..holding_a_draft()
        };

        let result = get(ports);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read the policy overview.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = GetPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..holding_a_draft()
        };

        let result = get(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
