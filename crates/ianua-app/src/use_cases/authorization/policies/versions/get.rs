//! Get policy version: one version of a tenant's policy by its number, as
//! it was when it decided requests or as it is being written.
//!
//! A decision record names the version that made it; this reads which
//! rules that was.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{PolicySetAction, SystemPermission};
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::policy::version::{PolicyHistory, PolicyVersion};
use ianua_domain::message;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrNotFound};
use crate::ports::authorization::PolicyStore;
use crate::use_case::Query;
use crate::use_cases::authorization::lookup::policy_versions;

/// The ports [`GetVersionUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetVersionPorts {
    /// Loads the policy's versions.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads one version of the caller's tenant's policy.
pub struct GetVersionUseCase {
    ports: GetVersionPorts,
}

impl GetVersionUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetVersionPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetVersionUseCase {
    type Caller = CallerContext;
    type Input = PolicyVersion;
    type Output = Result<PolicySet, AppError>;

    /// The tenant's version numbered `number`, whatever its state.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the policy.
    /// - `AppError::NotFound` when the tenant has no such version.
    /// - `AppError::Internal` when the versions cannot be read, or two are
    ///   live or open at once.
    async fn execute(
        &self,
        ctx: &CallerContext,
        number: PolicyVersion,
    ) -> Result<PolicySet, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::PolicySet(PolicySetAction::View))
            .map_err(AppError::from_domain)?;
        let versions = policy_versions(self.ports.policy_store.as_ref(), &ctx.tenant()).await?;
        PolicyHistory::of(&versions)
            .map_err(AppError::from_domain)?
            .version(number)
            .cloned()
            .or_not_found(message!(
                "authorization-this-tenant-has-no-such-policy",
                "this tenant has no such policy version"
            ))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{FakePolicyStore, block_admin_rule, policy_in};
    use crate::test_support::{block_on, test_ctx};

    fn get(ports: GetVersionPorts, number: u32) -> Result<PolicySet, AppError> {
        let number = PolicyVersion::parse(number).unwrap();
        block_on(GetVersionUseCase::new(ports).execute(&test_ctx(), number))
    }

    /// The tenant's archived version 1, which blocked the admin pages.
    fn archived_first() -> GetVersionPorts {
        GetVersionPorts {
            policy_store: Arc::new(FakePolicyStore::holding(
                test_ctx().tenant_id(),
                policy_in(PolicyStatus::Archived, vec![block_admin_rule()]),
            )),
            ..GetVersionPorts::fakes()
        }
    }

    /// Ann reads version 1, long out of use. She sees the rule it held.
    #[test]
    fn a_past_version_is_read_as_it_was() {
        let version = get(archived_first(), 1).unwrap();

        assert_eq!(version.status(), PolicyStatus::Archived);
        assert_eq!(version.rules()[0].name().as_str(), "block-admin");
    }

    /// Ann reads version 7 of a tenant that has one version. It is not
    /// found.
    #[test]
    fn an_unknown_version_is_not_found() {
        assert!(matches!(
            get(archived_first(), 7),
            Err(AppError::NotFound(_))
        ));
    }

    /// Reading an archived version still requires policy view permission.
    #[test]
    fn a_caller_who_may_not_view_the_policy_is_refused() {
        let ports = GetVersionPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..archived_first()
        };

        assert!(matches!(get(ports, 1), Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot read an archived policy version.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = GetVersionPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..archived_first()
        };

        assert!(matches!(get(ports, 1), Err(AppError::Unauthenticated)));
    }
}
