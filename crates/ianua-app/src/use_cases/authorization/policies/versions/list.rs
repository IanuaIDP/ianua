//! List policy versions: the history of a tenant's policy, newest first, so
//! an admin sees what was live when and picks one to compare or restore.

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

/// The ports [`ListVersionsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListVersionsPorts {
    /// Loads the policy's versions.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists every version of the caller's tenant's policy.
pub struct ListVersionsUseCase {
    ports: ListVersionsPorts,
}

impl ListVersionsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListVersionsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListVersionsUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<PolicySet>, AppError>;

    /// Every version of the tenant's policy, newest first: the open draft,
    /// the live version and the past ones. Empty when it never saved one.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the policy.
    /// - `AppError::Internal` when the versions cannot be read, or two are
    ///   live or open at once.
    async fn execute(&self, ctx: &CallerContext, (): ()) -> Result<Vec<PolicySet>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::PolicySet(PolicySetAction::View))
            .map_err(AppError::from_domain)?;
        let mut versions = policy_versions(self.ports.policy_store.as_ref(), &ctx.tenant()).await?;
        PolicyHistory::of(&versions).map_err(AppError::from_domain)?;
        versions.sort_by_key(|version| std::cmp::Reverse(version.version()));
        Ok(versions)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;
    use ianua_domain::domains::authorization::policy::version::PolicyVersion;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakePolicyStore, draft_beside, policy_in};
    use crate::test_support::{block_on, test_ctx};

    fn list(ports: ListVersionsPorts) -> Result<Vec<PolicySet>, AppError> {
        block_on(ListVersionsUseCase::new(ports).execute(&test_ctx(), ()))
    }

    /// A live version 1 and a draft version 2 beside it.
    fn live_and_draft() -> ListVersionsPorts {
        let live = policy_in(PolicyStatus::Active, Vec::new());
        let draft = draft_beside(&live);
        ListVersionsPorts {
            policy_store: Arc::new(FakePolicyStore::holding_versions(
                test_ctx().tenant_id(),
                [live, draft],
            )),
            ..ListVersionsPorts::fakes()
        }
    }

    /// Ann's tenant has a live version 1 and a draft 2. She reads both,
    /// the draft first.
    #[test]
    fn every_version_is_listed_newest_first() {
        let versions = list(live_and_draft()).unwrap();

        let numbers: Vec<PolicyVersion> = versions.iter().map(PolicySet::version).collect();
        assert_eq!(numbers.len(), 2);
        assert!(numbers[0] > numbers[1]);
        assert_eq!(numbers[1], PolicyVersion::FIRST);
    }

    /// Ann's tenant never saved a policy. She reads an empty history.
    #[test]
    fn a_tenant_without_a_policy_has_no_history() {
        assert!(list(ListVersionsPorts::fakes()).unwrap().is_empty());
    }

    /// Listing policy history is forbidden without policy view permission.
    #[test]
    fn a_caller_who_may_not_view_the_policy_is_refused() {
        let ports = ListVersionsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..live_and_draft()
        };

        assert!(matches!(list(ports), Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot list policy history.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = ListVersionsPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..live_and_draft()
        };

        assert!(matches!(list(ports), Err(AppError::Unauthenticated)));
    }
}
