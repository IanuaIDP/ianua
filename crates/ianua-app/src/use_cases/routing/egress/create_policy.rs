//! Create egress policy: say where a service agents can reach may go.

use std::sync::Arc;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::egress::{
    CreateEgressPolicyParams, EgressDestination, EgressPolicy, ServiceIdentity,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::Label;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::routing::EgressPolicyStore;
use crate::use_case::Command;

/// What a new egress policy is made of.
pub struct CreatePolicyRequest {
    /// A name people recognise the service by.
    pub name: Label,
    /// The workload identity allowed to use these outbound rules.
    pub service: ServiceIdentity,
    /// Where it may go.
    pub destinations: Vec<EgressDestination>,
    /// The most sensitive data an agent behind a call may have touched.
    pub max_data_class: DataClassLevel,
}

/// The ports [`CreatePolicyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePolicyPorts {
    /// Keeps the tenant's egress policies.
    pub egress_store: Arc<dyn EgressPolicyStore>,
    /// The plan's ceiling on egress policies.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Creates an egress policy.
pub struct CreatePolicyUseCase {
    ports: CreatePolicyPorts,
}

impl CreatePolicyUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePolicyPorts) -> Self {
        Self { ports }
    }
}

impl Command for CreatePolicyUseCase {
    type Caller = CallerContext;
    type Input = CreatePolicyRequest;
    type Output = Result<EgressPolicy<ResolvedTenant>, AppError>;

    /// Creates the policy and records `routing.egress_policy_created`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not create routing, or the
    ///   plan's limit is reached.
    /// - `AppError::Domain` when the destination list is empty, too long, or
    ///   names one destination twice.
    /// - `AppError::Conflict` when the service already has a policy.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: CreatePolicyRequest,
    ) -> Result<EgressPolicy<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let tenant = caller.tenant();
        let mut policy = new_policy(request, &RoutingControl::new(&authority))?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(caller.plan_limits(), &tenant, ResourceKind::EgressPolicies)
            .await
            .map_err(AppError::from_domain)?;
        self.ports
            .egress_store
            .save(&tenant, &policy)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), policy.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(policy)
    }
}

/// The policy `request` describes, made by `by`.
fn new_policy(
    request: CreatePolicyRequest,
    by: &RoutingControl<'_>,
) -> Result<EgressPolicy<ResolvedTenant>, AppError> {
    EgressPolicy::create(
        CreateEgressPolicyParams {
            name: request.name,
            service: request.service,
            destinations: request.destinations,
            max_data_class: request.max_data_class,
        },
        by,
    )
    .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::DomainName;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::routing::{FakeEgressPolicyStore, github, routing_label};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    const FETCHER: &str = "spiffe://ianua.test/ns/svc/sa/fetcher";

    struct Fixture {
        policies: Arc<FakeEgressPolicyStore>,
        audit: Arc<FakeEventDispatcher>,
        use_case: CreatePolicyUseCase,
    }

    fn fixture_with(ports: impl FnOnce(CreatePolicyPorts) -> CreatePolicyPorts) -> Fixture {
        let policies = Arc::new(FakeEgressPolicyStore::default());
        Fixture {
            use_case: CreatePolicyUseCase::new(ports(CreatePolicyPorts {
                egress_store: policies.clone(),
                ..CreatePolicyPorts::fakes()
            })),
            policies,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn fixture() -> Fixture {
        fixture_with(|ports| ports)
    }

    fn request(destinations: Vec<EgressDestination>) -> CreatePolicyRequest {
        CreatePolicyRequest {
            name: routing_label("fetcher"),
            service: ServiceIdentity::new(FETCHER).unwrap(),
            destinations,
            max_data_class: DataClassLevel::Internal,
        }
    }

    fn run(
        f: &Fixture,
        request: CreatePolicyRequest,
    ) -> Result<EgressPolicy<ResolvedTenant>, AppError> {
        block_on(
            f.use_case
                .execute(&test_ctx(), &test_auditor(f.audit.clone()), request),
        )
    }

    fn stored(f: &Fixture) -> Vec<EgressPolicy<ResolvedTenant>> {
        block_on(f.policies.list(&test_ctx().tenant())).unwrap()
    }

    /// Ann lets the fetcher reach GitHub. The policy is kept and the change
    /// recorded.
    #[test]
    fn a_policy_is_kept_and_recorded() {
        let f = fixture();

        let policy = run(&f, request(vec![github()])).unwrap();

        assert!(
            block_on(
                f.policies
                    .find_by_service(&test_ctx().tenant(), policy.service())
            )
            .unwrap()
            .is_some()
        );
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.egress_policy_created"]
        );
    }

    /// Ann adds a second policy for the fetcher. A service has one policy, so
    /// it is refused as a conflict.
    #[test]
    fn a_second_policy_for_one_service_is_a_conflict() {
        let f = fixture();
        run(&f, request(vec![github()])).unwrap();

        let again = run(&f, request(vec![github()]));

        assert!(matches!(again, Err(AppError::Conflict(_))));
    }

    /// Ann gives the fetcher a policy listing nowhere. It is refused, since a
    /// policy that lets nothing out is no policy to review.
    #[test]
    fn a_policy_without_destinations_is_refused() {
        let f = fixture();

        let result = run(&f, request(Vec::new()));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
        assert!(stored(&f).is_empty());
    }

    /// Ann lists `pypi.org` twice. It is refused.
    #[test]
    fn a_destination_listed_twice_is_refused() {
        let f = fixture();
        let pypi = || EgressDestination::new(DomainName::new("pypi.org").unwrap(), 443).unwrap();

        let result = run(&f, request(vec![pypi(), pypi()]));

        assert!(matches!(result, Err(AppError::Domain(_))), "{result:?}");
    }

    /// Acme's plan holds no more egress policies. Ann's is refused and
    /// nothing is kept.
    #[test]
    fn a_policy_past_the_plan_limit_is_refused() {
        let f = fixture_with(|ports| CreatePolicyPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..ports
        });

        let result = run(&f, request(vec![github()]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(stored(&f).is_empty());
    }

    /// Creating an egress policy without tenant rights is forbidden and
    /// leaves the policy store empty.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let f = fixture_with(|ports| CreatePolicyPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..ports
        });

        let result = run(&f, request(vec![github()]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(stored(&f).is_empty());
    }

    /// A signed-out session cannot create an egress policy.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(|ports| CreatePolicyPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..ports
        });

        let result = run(&f, request(vec![github()]));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
