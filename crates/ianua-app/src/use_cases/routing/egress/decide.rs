//! Decide a way out: whether the egress gateway lets a service's outbound
//! connection go where it asks.
//!
//! The service is named by the client certificate it connected with, and
//! the tenant by the one egress policy written for that name; a service no
//! tenant claims, or two tenants claim, reaches nothing. When the call
//! carries the assertion the gateway signed onto the agent's request that
//! caused it, and the assertion checks as one of that tenant's, the agent's
//! data mark is held to the policy's class. A call with no assertion, or
//! one that does not check, could be any agent's, so it is judged as
//! carrying the most sensitive data. A refusal an agent caused is recorded
//! against it, through the data plane's inbox. Any answer other than a
//! clear yes refuses, no answer included.

use std::sync::Arc;

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::assertion::AssertedCaller;
use ianua_domain::domains::routing::egress::{
    AgentMark, EgressDecision, EgressDenial, EgressTarget, ServiceIdentity, sole_claim,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::causes;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AgentId, DelegationId, EgressPolicyId, TenantId, UntrustedText};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::agents::AgentExposureGate;
use crate::ports::crypto::AssertionVerifier;
use crate::ports::routing::{ClaimedEgressPolicy, CrossTenantEgressPolicies};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::agents::enforcement::{RecordEgressDenialRequest, RecordEgressDenialUseCase};

/// One outbound connection a service asks the egress gateway for.
pub struct DecideRequest {
    /// The service, as its verified client certificate names it.
    pub service: ServiceIdentity,
    /// Where it asks to go.
    pub target: EgressTarget,
    /// The assertion the call carries, if it carries one. A secret: it
    /// names whom the agent acts for.
    pub assertion: Option<Secret>,
}

/// The verdict on one way out, with what its audit line names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressVerdict {
    /// Let out, or refused and why.
    pub decision: EgressDecision,
    /// The tenant whose policy decided, when one tenant alone claims the
    /// service.
    pub tenant_id: Option<TenantId>,
    /// The policy that decided.
    pub policy_id: Option<EgressPolicyId>,
    /// The agent the call was held against, when its assertion checked.
    pub agent_id: Option<AgentId>,
}

/// The ports [`DecideUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DecidePorts {
    /// Every tenant's policies for a service.
    pub policies: Arc<dyn CrossTenantEgressPolicies>,
    /// Checks the assertion a call carries.
    pub assertions: Arc<dyn AssertionVerifier>,
    /// The agents' data marks.
    pub exposure: Arc<dyn AgentExposureGate>,
}

/// Decides outbound connections for the egress gateway.
pub struct DecideUseCase {
    ports: DecidePorts,
}

/// The agent whose request caused a call, and the delegation it acted
/// under.
#[derive(Debug, Clone, Copy)]
struct Attribution {
    agent_id: AgentId,
    delegation_id: DelegationId,
}

impl DecideUseCase {
    /// A use case deciding through `ports`.
    #[must_use]
    pub fn new(ports: DecidePorts) -> Self {
        Self { ports }
    }

    /// The agent `assertion` names, when it checks as one of `tenant`'s
    /// and names an agent. A person's or a consumer's assertion names no
    /// agent, so the call stays unattributed and is judged strictly.
    async fn attribution(
        &self,
        tenant: &ScopedTenant,
        assertion: Option<&Secret>,
    ) -> Option<Attribution> {
        let assertion = assertion?;
        match self.ports.assertions.caller(tenant, assertion).await {
            Ok(AssertedCaller::Agent {
                agent_id,
                delegation_id,
                ..
            }) => Some(Attribution {
                agent_id,
                delegation_id,
            }),
            Ok(AssertedCaller::User { .. } | AssertedCaller::Consumer { .. }) => None,
            Err(error) => {
                tracing::info!(error = %causes(&error), "an egress call's assertion did not check; judged as unattributed");
                None
            }
        }
    }

    /// The mark the call carries: the attributed agent's, or the most
    /// sensitive class when it cannot be read, so an unreadable mark never
    /// lets data out.
    async fn mark(&self, tenant: &ScopedTenant, attribution: Option<&Attribution>) -> AgentMark {
        let Some(attribution) = attribution else {
            return AgentMark::Unattributed;
        };
        let read = self
            .ports
            .exposure
            .current(tenant, &attribution.agent_id)
            .await;
        match read {
            Ok(level) => AgentMark::Marked(level),
            Err(error) => {
                tracing::warn!(error = %causes(&error), "an agent's data mark could not be read; judged as restricted");
                AgentMark::Marked(DataClassLevel::Restricted)
            }
        }
    }
}

impl Command for DecideUseCase {
    type Caller = ();
    type Input = DecideRequest;
    type Output = Result<EgressVerdict, AppError>;

    /// Decides `req` under the one policy written for its service, and
    /// records a refusal an agent caused as `agents.egress_denied` in the
    /// tenant whose policy refused it.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the policies cannot be read, or a
    ///   refusal cannot be recorded. The way out stays refused either way.
    async fn execute(
        &self,
        _caller: &(),
        auditor: &RequestAuditor,
        req: DecideRequest,
    ) -> Result<EgressVerdict, AppError> {
        let claims = self
            .ports
            .policies
            .claiming(&req.service)
            .await
            .or_internal()?;
        let Some(claim) = sole_claim(claims) else {
            return Ok(unclaimed());
        };
        let tenant = ScopedTenant::from_service_claim(claim.tenant_id);
        let attribution = self.attribution(&tenant, req.assertion.as_ref()).await;
        let mark = self.mark(&tenant, attribution.as_ref()).await;
        let decision = claim.policy.decide(&req.target.request(mark));
        let verdict = verdict_of(&claim, decision, attribution.as_ref());
        let (EgressDecision::Deny(reason), Some(attribution)) = (decision, attribution) else {
            return Ok(verdict);
        };
        RecordEgressDenialUseCase
            .execute(
                &tenant,
                &auditor.with_tenant(claim.tenant_id),
                denial_request(&req, attribution, reason),
            )
            .await?;
        Ok(verdict)
    }
}

/// The verdict on a service no tenant claims, or more than one does.
fn unclaimed() -> EgressVerdict {
    EgressVerdict {
        decision: EgressDecision::Deny(EgressDenial::NoPolicy),
        tenant_id: None,
        policy_id: None,
        agent_id: None,
    }
}

/// The verdict `claim`'s policy gave as `decision`, held against the agent
/// `attribution` names, if any.
fn verdict_of(
    claim: &ClaimedEgressPolicy,
    decision: EgressDecision,
    attribution: Option<&Attribution>,
) -> EgressVerdict {
    EgressVerdict {
        decision,
        tenant_id: Some(claim.tenant_id),
        policy_id: Some(*claim.policy.id()),
        agent_id: attribution.map(|attribution| attribution.agent_id),
    }
}

/// The record of `req` refused for `reason`, held against `attribution`.
fn denial_request(
    req: &DecideRequest,
    attribution: Attribution,
    reason: EgressDenial,
) -> RecordEgressDenialRequest {
    RecordEgressDenialRequest {
        agent_id: attribution.agent_id,
        delegation_id: attribution.delegation_id,
        service: req.service.clone(),
        destination: UntrustedText::record(&req.target.to_string()),
        reason,
        decided_at: clock::now(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{PrincipalRef, UserId};

    use super::*;
    use crate::ports::routing::EgressPolicyStore as _;
    use crate::test_support::agents::FakeExposureGate;
    use crate::test_support::crypto::FakeAssertionVerifier;
    use crate::test_support::routing::{
        FailingEgressPolicies, FakeEgressPolicyStore, egress_policy_for,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const FETCHER: &str = "spiffe://ianua.test/ns/svc/sa/fetcher";

    struct Bench {
        tenant: ScopedTenant,
        policies: Arc<FakeEgressPolicyStore>,
        assertions: Arc<FakeAssertionVerifier>,
        exposure: Arc<FakeExposureGate>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Bench {
        /// One tenant, Acme, with a policy letting the fetcher reach
        /// `api.github.com:443` with internal data.
        fn new() -> Self {
            let bench = Self {
                tenant: ScopedTenant::for_test(TenantId::new()),
                policies: Arc::new(FakeEgressPolicyStore::default()),
                assertions: Arc::new(FakeAssertionVerifier::default()),
                exposure: Arc::new(FakeExposureGate::default()),
                sink: Arc::new(FakeEventDispatcher::new()),
            };
            block_on(
                bench
                    .policies
                    .save(&bench.tenant, &egress_policy_for(FETCHER)),
            )
            .unwrap();
            bench
        }

        fn use_case(&self) -> DecideUseCase {
            DecideUseCase::new(DecidePorts {
                policies: self.policies.clone(),
                assertions: self.assertions.clone(),
                exposure: self.exposure.clone(),
            })
        }

        /// An assertion of Acme's naming `agent`, acting for a person.
        fn assertion_for(&self, agent: AgentId) -> Secret {
            let caller = AssertedCaller::Agent {
                agent_id: agent,
                acting_for: PrincipalRef::User(UserId::new()),
                delegation_id: DelegationId::new(),
            };
            self.assertions.issue(*self.tenant, caller)
        }

        fn decide(&self, req: DecideRequest) -> Result<EgressVerdict, AppError> {
            block_on(
                self.use_case()
                    .execute(&(), &test_auditor(self.sink.clone()), req),
            )
        }
    }

    fn to(host: &str, assertion: Option<Secret>) -> DecideRequest {
        DecideRequest {
            service: ServiceIdentity::new(FETCHER).unwrap(),
            target: EgressTarget::new(host, 443).unwrap(),
            assertion,
        }
    }

    /// Ann's agent, which has read only public data, has the fetcher call
    /// `api.github.com`. It is let out under Acme's policy, held against
    /// the agent, and nothing is recorded.
    #[test]
    fn a_listed_call_an_agent_caused_is_let_out() {
        let bench = Bench::new();
        let agent = AgentId::new();
        let assertion = bench.assertion_for(agent);

        let verdict = bench.decide(to("api.github.com", Some(assertion))).unwrap();

        assert_eq!(verdict.decision, EgressDecision::Allow);
        assert_eq!(verdict.tenant_id, Some(*bench.tenant));
        assert_eq!(verdict.agent_id, Some(agent));
        assert!(bench.sink.records.lock().unwrap().is_empty());
    }

    /// An attributed call to an unlisted host is denied for its destination,
    /// with an egress-denial audit event recorded in the policy's tenant.
    #[test]
    fn an_unlisted_host_is_refused_and_held_against_the_agent() {
        let bench = Bench::new();
        let assertion = bench.assertion_for(AgentId::new());

        let verdict = bench.decide(to("evil.example", Some(assertion))).unwrap();

        assert_eq!(
            verdict.decision,
            EgressDecision::Deny(EgressDenial::DestinationNotListed)
        );
        assert_eq!(
            bench.sink.records.lock().unwrap().as_slice(),
            ["agents.egress_denied"]
        );
        assert_eq!(
            bench.sink.tenant_of("agents.egress_denied"),
            Some(*bench.tenant)
        );
    }

    /// An agent marked as holding restricted data is denied by an egress
    /// policy limited to internal data, even for a listed destination.
    #[test]
    fn an_agent_holding_more_sensitive_data_is_refused() {
        let bench = Bench::new();
        let agent = AgentId::new();
        bench
            .exposure
            .set(&bench.tenant, agent, DataClassLevel::Restricted);
        let assertion = bench.assertion_for(agent);

        let verdict = bench.decide(to("api.github.com", Some(assertion))).unwrap();

        assert_eq!(
            verdict.decision,
            EgressDecision::Deny(EgressDenial::DataTooSensitive)
        );
    }

    /// A call without an assertion is denied as unattributed under an
    /// internal-data policy. It names no agent and records no audit event.
    #[test]
    fn an_unattributed_call_is_refused_below_the_top_class() {
        let bench = Bench::new();

        let verdict = bench.decide(to("api.github.com", None)).unwrap();

        assert_eq!(
            verdict.decision,
            EgressDecision::Deny(EgressDenial::Unattributed)
        );
        assert_eq!(verdict.agent_id, None);
        assert!(bench.sink.records.lock().unwrap().is_empty());
    }

    /// A forged assertion produces an unattributed denial with no agent named.
    #[test]
    fn an_assertion_that_does_not_check_is_unattributed() {
        let bench = Bench::new();
        let forged = Secret::new("forged.assertion.value");

        let verdict = bench.decide(to("api.github.com", Some(forged))).unwrap();

        assert_eq!(
            verdict.decision,
            EgressDecision::Deny(EgressDenial::Unattributed)
        );
        assert_eq!(verdict.agent_id, None);
    }

    /// Services claimed by no tenant or by two tenants receive a no-policy
    /// denial without a tenant attribution.
    #[test]
    fn a_service_without_one_claim_reaches_nothing() {
        let bench = Bench::new();
        let mallory = ScopedTenant::for_test(TenantId::new());
        block_on(bench.policies.save(&mallory, &egress_policy_for(FETCHER))).unwrap();
        let unknown = DecideRequest {
            service: ServiceIdentity::new("spiffe://ianua.test/ns/svc/sa/unknown").unwrap(),
            ..to("api.github.com", None)
        };

        let claimed_twice = bench.decide(to("api.github.com", None)).unwrap();
        let unclaimed = bench.decide(unknown).unwrap();

        for verdict in [claimed_twice, unclaimed] {
            assert_eq!(
                verdict.decision,
                EgressDecision::Deny(EgressDenial::NoPolicy)
            );
            assert_eq!(verdict.tenant_id, None);
        }
    }

    /// A failed policy-store read returns an internal error instead of an
    /// egress verdict.
    #[test]
    fn an_unreachable_store_is_an_error() {
        let bench = Bench::new();
        let use_case = DecideUseCase::new(DecidePorts {
            policies: Arc::new(FailingEgressPolicies),
            ..DecidePorts::fakes()
        });

        let decided = block_on(use_case.execute(
            &(),
            &test_auditor(bench.sink.clone()),
            to("api.github.com", None),
        ));

        assert!(matches!(decided, Err(AppError::Internal(_))));
    }
}
