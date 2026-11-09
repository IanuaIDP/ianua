//! Update egress policy: rename it, or change where a service may go, or how
//! sensitive the data behind a call may be.

use std::sync::Arc;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::egress::{EgressDestination, EgressPolicy};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{EgressPolicyId, Label};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::EgressPolicyStore;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::existing_egress_policy;

/// What to change on a policy. A field left `None` stays as it is.
pub struct UpdatePolicyRequest {
    /// The policy to change.
    pub policy_id: EgressPolicyId,
    /// A new name people recognise the service by.
    pub name: Option<Label>,
    /// The whole new destination list.
    pub destinations: Option<Vec<EgressDestination>>,
    /// The new data ceiling.
    pub max_data_class: Option<DataClassLevel>,
}

/// The ports [`UpdatePolicyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePolicyPorts {
    /// Keeps the tenant's egress policies.
    pub egress_store: Arc<dyn EgressPolicyStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes an egress policy.
pub struct UpdatePolicyUseCase {
    ports: UpdatePolicyPorts,
}

impl UpdatePolicyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePolicyPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdatePolicyUseCase {
    type Caller = CallerContext;
    type Input = UpdatePolicyRequest;
    type Output = Result<(), AppError>;

    /// Applies the changes `request` carries and records
    /// `routing.egress_policy_updated`. A request changing nothing records
    /// nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not update routing.
    /// - `AppError::NotFound` when the policy is not in the tenant.
    /// - `AppError::Domain` when the new destination list is empty, too long,
    ///   or names one destination twice.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdatePolicyRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut policy = existing_egress_policy(
            self.ports.egress_store.as_ref(),
            &tenant,
            &request.policy_id,
        )
        .await?;
        apply_changes(&mut policy, request, &control).map_err(AppError::from_domain)?;
        self.ports
            .egress_store
            .save(&tenant, &policy)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), policy.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Applies every change `request` carries to `policy`, on behalf of `by`.
fn apply_changes(
    policy: &mut EgressPolicy<ResolvedTenant>,
    request: UpdatePolicyRequest,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    if let Some(name) = request.name {
        policy.rename(name, by)?;
    }
    if let Some(destinations) = request.destinations {
        policy.replace_destinations(destinations, by)?;
    }
    let Some(class) = request.max_data_class else {
        return Ok(());
    };
    policy.change_max_data_class(class, by)
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::DomainName;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeEgressPolicyStore, egress_policy_for};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        policies: Arc<FakeEgressPolicyStore>,
        audit: Arc<FakeEventDispatcher>,
        policy_id: EgressPolicyId,
        use_case: UpdatePolicyUseCase,
    }

    fn fixture(authorities: FakeTenantAuthorities) -> Fixture {
        let policy = egress_policy_for("spiffe://ianua.test/ns/svc/sa/fetcher");
        let policies = Arc::new(FakeEgressPolicyStore::default());
        block_on(policies.save(&test_ctx().tenant(), &policy)).unwrap();
        Fixture {
            use_case: UpdatePolicyUseCase::new(UpdatePolicyPorts {
                egress_store: policies.clone(),
                tenant_authorities: Arc::new(authorities),
            }),
            policies,
            audit: Arc::new(FakeEventDispatcher::new()),
            policy_id: *policy.id(),
        }
    }

    fn pypi_only(policy_id: EgressPolicyId) -> UpdatePolicyRequest {
        UpdatePolicyRequest {
            policy_id,
            name: None,
            destinations: Some(vec![
                EgressDestination::new(DomainName::new("pypi.org").unwrap(), 443).unwrap(),
            ]),
            max_data_class: Some(DataClassLevel::Public),
        }
    }

    fn run(f: &Fixture, request: UpdatePolicyRequest) -> Result<(), AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    fn saved(f: &Fixture) -> EgressPolicy<ResolvedTenant> {
        block_on(f.policies.find_by_id(&test_ctx().tenant(), &f.policy_id))
            .unwrap()
            .unwrap()
    }

    /// Ann lets the fetcher reach only PyPI, with public data. Both changes
    /// are kept and recorded.
    #[test]
    fn destinations_and_ceiling_change_and_are_recorded() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        run(&f, pypi_only(f.policy_id)).unwrap();

        let policy = saved(&f);
        assert_eq!(policy.destinations()[0].host().as_str(), "pypi.org");
        assert_eq!(policy.max_data_class(), DataClassLevel::Public);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.egress_policy_updated"]
        );
    }

    /// Ann renames the fetcher's policy. The new name is kept, its ways out
    /// stay, and the change is recorded.
    #[test]
    fn a_policy_is_renamed_and_recorded() {
        let f = fixture(FakeTenantAuthorities::holding_everything());
        let before = saved(&f).destinations().to_vec();

        run(
            &f,
            UpdatePolicyRequest {
                policy_id: f.policy_id,
                name: Some(Label::new("name", "partner-fetcher").unwrap()),
                destinations: None,
                max_data_class: None,
            },
        )
        .unwrap();

        let policy = saved(&f);
        assert_eq!(policy.name().as_str(), "partner-fetcher");
        assert_eq!(policy.destinations(), before.as_slice());
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.egress_policy_updated"]
        );
    }

    /// Ann changes a policy that does not exist. She is told it was not
    /// found.
    #[test]
    fn an_unknown_policy_is_not_found() {
        let f = fixture(FakeTenantAuthorities::holding_everything());

        let result = run(&f, pypi_only(EgressPolicyId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Raising an egress policy's data ceiling without the update right is
    /// forbidden and preserves the internal-data ceiling.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(
            &f,
            UpdatePolicyRequest {
                policy_id: f.policy_id,
                name: None,
                destinations: None,
                max_data_class: Some(DataClassLevel::Restricted),
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(saved(&f).max_data_class(), DataClassLevel::Internal);
    }

    /// A caller without the update right receives a permission refusal even
    /// when the requested egress policy does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_policy() {
        let f = fixture(FakeTenantAuthorities::holding(&[]));

        let result = run(&f, pypi_only(EgressPolicyId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot update an egress policy.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = run(&f, pypi_only(f.policy_id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
