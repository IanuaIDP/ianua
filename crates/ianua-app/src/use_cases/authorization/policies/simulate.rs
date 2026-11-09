//! Simulate policy: try a version of the tenant's policy against a request
//! that is never made, and show which rule would fire and what would
//! happen.
//!
//! The live version answers "what happens now"; the open draft, or one in
//! review, answers "what would happen if this went live", which is what an
//! admin most wants to know before approving it. Every run is recorded.
//! Many runs in a row can be someone probing for a way past the policy,
//! which is worth an alert.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{PolicySetAction, SystemPermission};
use ianua_domain::domains::authorization::policy::set::PolicySet;
use ianua_domain::domains::authorization::policy::simulator::{SimulationInput, SimulationResult};
use ianua_domain::domains::authorization::policy::version::{PolicyHistory, PolicyVersion};
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authorization::PolicyStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authorization::lookup::policy_versions;

/// The ports [`SimulateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SimulatePorts {
    /// Loads the policy's versions.
    pub policy_store: Arc<dyn PolicyStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Which version a simulation runs against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulatedVersion {
    /// The version deciding requests now.
    Live,
    /// The open draft, being written or in review.
    Draft,
    /// The version with this number, whatever its state.
    Numbered(PolicyVersion),
}

/// A request to try, and the version to try it against.
pub struct SimulateRequest {
    /// The version to try.
    pub version: SimulatedVersion,
    /// The made-up request.
    pub scenario: SimulationInput,
}

/// Tries a version of the caller's tenant's policy against a request.
pub struct SimulateUseCase {
    ports: SimulatePorts,
}

impl SimulateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SimulatePorts) -> Self {
        Self { ports }
    }

    /// The version `wanted` names.
    async fn chosen(
        &self,
        tenant: &ScopedTenant,
        wanted: SimulatedVersion,
    ) -> Result<PolicySet, AppError> {
        let versions = policy_versions(self.ports.policy_store.as_ref(), tenant).await?;
        let history = PolicyHistory::of(&versions).map_err(AppError::from_domain)?;
        let found = match wanted {
            SimulatedVersion::Live => history.live(),
            SimulatedVersion::Draft => history.open(),
            SimulatedVersion::Numbered(number) => history.version(number),
        };
        found.cloned().or_not_found(message!(
            "authorization-this-tenant-has-no-such-policy",
            "this tenant has no such policy version"
        ))
    }
}

impl Command for SimulateUseCase {
    type Caller = CallerContext;
    type Input = SimulateRequest;
    type Output = Result<SimulationResult, AppError>;

    /// How the version `request` names would decide its scenario, for the
    /// caller, with the run recorded. The result names the version and the
    /// rule that decided.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view the policy.
    /// - `AppError::NotFound` when the tenant has no such version: nothing
    ///   live, no open draft, or no version of that number.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: SimulateRequest,
    ) -> Result<SimulationResult, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        authority
            .ensure_holds(SystemPermission::PolicySet(PolicySetAction::View))
            .map_err(AppError::from_domain)?;
        let tenant = ctx.tenant();
        let mut policy = self.chosen(&tenant, request.version).await?;
        let result = policy
            .simulate(&request.scenario, &authority)
            .map_err(AppError::from_domain)?;

        auditor
            .dispatch_by(&authority.actor(), policy.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::policy::status::PolicyStatus;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::{CanonicalPath, Fact};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::{
        FakePolicyStore, block_admin_rule, draft_beside, policy_in,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    fn live_policy_blocking_admin() -> SimulatePorts {
        let policy = policy_in(PolicyStatus::Active, vec![block_admin_rule()]);
        SimulatePorts {
            policy_store: Arc::new(FakePolicyStore::holding(test_ctx().tenant_id(), policy)),
            ..SimulatePorts::fakes()
        }
    }

    /// An empty live policy that allows all, with a draft beside it that
    /// blocks the admin pages.
    fn live_open_with_a_blocking_draft() -> SimulatePorts {
        let live = policy_in(PolicyStatus::Active, Vec::new());
        let mut draft = draft_beside(&live);
        let by = anyone_holding(&[SystemPermission::ManagePolicy]);
        draft.add_rule(block_admin_rule(), by).unwrap();
        SimulatePorts {
            policy_store: Arc::new(FakePolicyStore::holding_versions(
                test_ctx().tenant_id(),
                [live, draft],
            )),
            ..SimulatePorts::fakes()
        }
    }

    fn request_to(path: &str) -> SimulationInput {
        SimulationInput {
            path: Fact::Known(CanonicalPath::new(path).unwrap()),
            ..SimulationInput::new()
        }
    }

    fn simulate_version(
        ports: SimulatePorts,
        sink: &Arc<FakeEventDispatcher>,
        version: SimulatedVersion,
        scenario: SimulationInput,
    ) -> Result<SimulationResult, AppError> {
        block_on(SimulateUseCase::new(ports).execute(
            &test_ctx(),
            &test_auditor(sink.clone()),
            SimulateRequest { version, scenario },
        ))
    }

    fn simulate(
        ports: SimulatePorts,
        sink: &Arc<FakeEventDispatcher>,
        scenario: SimulationInput,
    ) -> Result<SimulationResult, AppError> {
        simulate_version(ports, sink, SimulatedVersion::Live, scenario)
    }

    /// Ann tries `/admin/users` against the live policy. "block-admin"
    /// fires and denies it, and the run is recorded.
    #[test]
    fn a_matching_rule_decides_and_the_run_is_recorded() {
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = simulate(
            live_policy_blocking_admin(),
            &sink,
            request_to("/admin/users"),
        )
        .unwrap();

        assert!(result.is_denied());
        assert_eq!(result.matched_rule().unwrap().as_str(), "block-admin");
        assert_eq!(result.policy_version(), PolicyVersion::FIRST);
        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["authorization.policy_simulated"]
        );
    }

    /// Ann tries `/admin` against the draft beside the live policy. The
    /// draft would block it, while the live version still lets it in.
    #[test]
    fn a_draft_is_tried_before_it_goes_live() {
        let sink = Arc::new(FakeEventDispatcher::new());

        let drafted = simulate_version(
            live_open_with_a_blocking_draft(),
            &sink,
            SimulatedVersion::Draft,
            request_to("/admin"),
        )
        .unwrap();
        let live = simulate(
            live_open_with_a_blocking_draft(),
            &sink,
            request_to("/admin"),
        )
        .unwrap();

        assert!(drafted.is_denied());
        assert_ne!(drafted.policy_version(), PolicyVersion::FIRST);
        assert!(live.is_allowed());
    }

    /// Ann tries `/api/data`, which no rule matches. The default allows it
    /// and no rule is named.
    #[test]
    fn a_request_no_rule_matches_gets_the_default() {
        let sink = Arc::new(FakeEventDispatcher::new());

        let result =
            simulate(live_policy_blocking_admin(), &sink, request_to("/api/data")).unwrap();

        assert!(result.is_allowed());
        assert!(result.matched_rule().is_none());
    }

    /// No policy is live in Ann's tenant. There is nothing to try, and
    /// nothing is recorded.
    #[test]
    fn without_a_live_policy_nothing_is_found_or_recorded() {
        let sink = Arc::new(FakeEventDispatcher::new());

        let result = simulate(SimulatePorts::fakes(), &sink, SimulationInput::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// Ann tries the draft of a tenant whose only version is live. There is
    /// no draft to try.
    #[test]
    fn without_a_draft_there_is_nothing_to_try() {
        let result = simulate_version(
            live_policy_blocking_admin(),
            &Arc::new(FakeEventDispatcher::new()),
            SimulatedVersion::Draft,
            SimulationInput::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Simulating the admin path without policy view permission is forbidden
    /// and records no simulation event.
    #[test]
    fn a_caller_who_may_not_view_the_policy_is_refused() {
        let sink = Arc::new(FakeEventDispatcher::new());
        let ports = SimulatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..live_policy_blocking_admin()
        };

        let result = simulate(ports, &sink, request_to("/admin"));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(sink.records.lock().unwrap().is_empty());
    }

    /// A signed-out session cannot simulate a policy decision.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let ports = SimulatePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..live_policy_blocking_admin()
        };

        let result = simulate(
            ports,
            &Arc::new(FakeEventDispatcher::new()),
            request_to("/admin"),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
