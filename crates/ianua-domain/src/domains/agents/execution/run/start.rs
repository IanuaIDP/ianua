//! What a run checks before it starts: that it acts for its agent, under a
//! live delegation, inside that delegation's intent.

use time::OffsetDateTime;

use crate::domains::agents::authority::delegation::Delegation;
use crate::domains::agents::authority::intent::IntentEnvelope;
use crate::domains::agents::execution::run::params::{MAX_RUN_STEPS, StartRunParams};
use crate::domains::agents::execution::run::starter::RunStarter;
use crate::domains::agents::identity::agent::AgentIdentity;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::restriction::Restriction;
use crate::shared::validation::numeric::validate_range;

/// Refuses a run of `agent` that `starter` starts under `delegation` at
/// `now`, as `params` asks.
///
/// A delegation backs only the runs its delegator starts. Sam hands his
/// rights to the tenant's shared agent, which Ann looks after. Without this
/// check, Ann starts the agent under Sam's delegation and acts with his
/// rights.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the delegation was granted to another
///   agent.
/// - [`DomainError::Forbidden`] when `starter` is not its delegator.
/// - [`DomainError::Forbidden`] when the delegation is revoked or expired.
/// - [`DomainError::Forbidden`] when the agent may not act.
/// - [`DomainError::Forbidden`] when the purpose reaches past the
///   delegation's intent.
pub(super) fn ensure_startable<T: TenantScope>(
    starter: &RunStarter<'_>,
    params: &StartRunParams,
    delegation: &Delegation<T>,
    agent: &AgentIdentity<T>,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    if delegation.delegate() != agent.id() {
        return Err(DomainError::forbidden(message!(
            "agents-the-delegation-was-granted-to-another",
            "the delegation was granted to another agent"
        )));
    }
    if starter.principal() != *delegation.delegator() {
        return Err(DomainError::forbidden(message!(
            "agents-a-delegation-backs-only-the-runs",
            "a delegation backs only the runs its delegator starts"
        )));
    }
    if !delegation.is_valid(now) {
        return Err(DomainError::forbidden(message!(
            "agents-the-delegation-is-revoked-or-expired",
            "the delegation is revoked or expired"
        )));
    }
    ensure_agent_may_act(agent, now)?;
    ensure_within_intent(&params.purpose, delegation)
}

/// Refuses a run of `agent` at `now` that acts under no delegation but was
/// given a tool.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the agent may not act.
/// - [`DomainError::Validation`] when `params` gives the run a tool.
pub(super) fn ensure_toolless<T: TenantScope>(
    params: &StartRunParams,
    agent: &AgentIdentity<T>,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    ensure_agent_may_act(agent, now)?;
    ensure_step_limit(params.max_steps)?;
    ensure_spend_check_below_limit(params)?;
    if !params.granted_tools.is_empty() {
        return Err(DomainError::invalid(message!(
            "agents-a-run-under-no-delegation-may",
            "a run under no delegation may be given no tool"
        )));
    }
    Ok(())
}

/// Refuses an amount to ask a person at that is nothing, which would
/// pause before the first call, or that is not below the spend limit,
/// which would stop the run before anyone could be asked.
pub(super) fn ensure_spend_check_below_limit(params: &StartRunParams) -> Result<(), DomainError> {
    let Restriction::To(mark) = params.ask_past else {
        return Ok(());
    };
    let ceiling = params
        .spend_limit
        .limit()
        .map_or(u64::MAX, |limit| limit.micros().saturating_sub(1));
    validate_range("ask_past", mark.micros(), 1..=ceiling)?;
    Ok(())
}

/// Refuses a step limit of zero, which fails at once, or past
/// [`MAX_RUN_STEPS`].
pub(super) fn ensure_step_limit(max_steps: u32) -> Result<(), DomainError> {
    validate_range("max_steps", max_steps, 1..=MAX_RUN_STEPS)?;
    Ok(())
}

fn ensure_agent_may_act<T: TenantScope>(
    agent: &AgentIdentity<T>,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    if agent.may_act_at(now) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-the-agent-may-not-act-it",
        "the agent may not act: it is suspended, revoked or must re-attest"
    )))
}

/// Refuses a purpose wider than the delegation's intent. A delegation with no
/// intent sets no bound here.
///
/// Ann's delegation lets her agent read reports. Without this check, a run
/// started under it declares deletes as its purpose. Its own call check then
/// lets a delete through, and only the proxy is left to refuse it.
fn ensure_within_intent<T: TenantScope>(
    purpose: &IntentEnvelope,
    delegation: &Delegation<T>,
) -> Result<(), DomainError> {
    let Some(intent) = delegation.constraints().intent().limit() else {
        return Ok(());
    };
    if purpose.subset_of(intent.envelope()) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "agents-the-run-s-purpose-reaches-past",
        "the run's purpose reaches past the delegation's intent"
    )))
}

#[cfg(test)]
mod tests {
    use crate::domains::agents::authority::capability::ActionApproval;
    use crate::domains::agents::authority::delegation::ActingUnder;
    use crate::domains::agents::authority::intent::{
        DriftPolicy, IntentBinding, IntentDigest, IntentEnvelope, IntentStatement,
    };
    use crate::domains::agents::execution::run::tests::fixtures::{
        agent, ann, by_ann, calling, constraints, delegation, params, tool,
    };
    use crate::domains::agents::execution::run::{Admission, AgentRun, RunStarter, StartRunParams};
    use crate::domains::agents::identity::acting::ActingAgent;
    use crate::domains::agents::identity::agent::SuspendedBy;
    use crate::shared::errors::DomainError;
    use crate::test_support::authority::assumed_authority;
    use crate::types::{ActionClass, Human, HumanAccount, Initiator, PersonKey, TenantId, UserId};

    /// A read-only intent: "read the Q1 reports".
    fn read_only() -> IntentBinding {
        IntentBinding::new(
            IntentStatement::new("read the Q1 reports").unwrap(),
            IntentDigest::new([1u8; 32]),
            DriftPolicy::Off,
            IntentEnvelope::new([ActionClass::Read]),
        )
    }

    /// Ann's agent starts a run under a delegation granted to it. The run
    /// acts for that agent under that delegation.
    #[test]
    fn a_run_starts_for_the_agent_its_delegation_was_granted_to() {
        let agent = agent();
        let delegation = delegation(&agent, constraints());

        let run = AgentRun::start(by_ann(), params(5), &delegation, &agent).unwrap();

        assert_eq!(run.agent_id(), agent.id());
        assert_eq!(run.delegation_id().delegation(), Some(delegation.id()));
    }

    /// A run cannot start for an agent other than the delegation's recipient.
    #[test]
    fn a_run_under_another_agents_delegation_is_refused() {
        let anns_agent = agent();
        let sams_agent = agent();
        let anns = delegation(&anns_agent, constraints());

        let result = AgentRun::start(by_ann(), params(5), &anns, &sams_agent);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Another person cannot start a run under Ann's delegation, even when
    /// the agent is the delegation's recipient.
    #[test]
    fn a_delegation_backs_only_the_runs_its_delegator_starts() {
        let agent = agent();
        let anns = delegation(&agent, constraints());
        let owen = Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("owen@corp.test").unwrap(),
        );
        let by_owen = RunStarter::person(assumed_authority(&owen, TenantId::new(), &[], &[]));

        let result = AgentRun::start(by_owen, params(5), &anns, &agent);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An authenticated agent cannot start its own run under a person's
    /// delegation because it is not the delegator.
    #[test]
    fn an_agent_does_not_start_a_run_under_its_delegators_delegation() {
        let agent = agent();
        let anns = delegation(&agent, constraints());
        let signed_in = ActingAgent::assumed(*agent.id());

        let result = AgentRun::start(RunStarter::agent(&signed_in), params(5), &anns, &agent);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// The run records the person who proved who they are as its starter,
    /// so only they are kept from approving its paused calls.
    #[test]
    fn a_run_records_its_proven_starter() {
        let agent = agent();
        let delegation = delegation(&agent, constraints());

        let run = AgentRun::start(by_ann(), params(5), &delegation, &agent).unwrap();

        assert_eq!(run.started_by(), &Initiator::Human(ann()));
    }

    /// Starting a run an hour after its delegation expires is forbidden.
    #[test]
    fn a_run_under_an_expired_delegation_is_refused() {
        let agent = agent();
        let delegation = delegation(&agent, constraints());
        let later = crate::shared::clock::freeze(delegation.expires_at() + time::Duration::HOUR);

        let result = AgentRun::start(by_ann(), params(5), &delegation, &agent);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        drop(later);
    }

    /// A monitor-suspended agent cannot start a run under its delegation.
    #[test]
    fn a_run_for_an_agent_that_may_not_act_is_refused() {
        let mut agent = agent();
        let delegation = delegation(&agent, constraints());
        agent.suspend(SuspendedBy::Monitor).unwrap();

        let result = AgentRun::start(by_ann(), params(5), &delegation, &agent);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A run declaring writes and deletes cannot start under a delegation
    /// whose intent allows only reads.
    #[test]
    fn a_purpose_past_the_delegations_intent_is_refused() {
        let agent = agent();
        let delegation = delegation(&agent, constraints().with_intent(read_only()));

        let result = AgentRun::start(by_ann(), params(5), &delegation, &agent);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// The same read-only delegation starts a run that only reads.
    #[test]
    fn a_purpose_inside_the_delegations_intent_starts() {
        let agent = agent();
        let delegation = delegation(&agent, constraints().with_intent(read_only()));
        let reads = StartRunParams {
            purpose: IntentEnvelope::new([ActionClass::Read]),
            ..params(5)
        };

        assert!(AgentRun::start(by_ann(), reads, &delegation, &agent).is_ok());
    }

    /// A workflow step that only writes text starts its agent's run under
    /// no delegation and with no tools. It acts under none.
    #[test]
    fn a_run_with_no_tools_starts_under_no_delegation() {
        let agent = agent();
        let toolless = StartRunParams {
            granted_tools: Vec::new(),
            ..params(5)
        };

        let run = AgentRun::start_without_tools(by_ann(), toolless, &agent).unwrap();

        assert_eq!(run.delegation_id(), &ActingUnder::NoDelegation);
        assert!(run.granted_tools().is_empty());
    }

    /// Starting without a delegation is invalid when the run has granted tools.
    #[test]
    fn a_run_under_no_delegation_given_a_tool_is_refused() {
        let agent = agent();

        let result = AgentRun::start_without_tools(by_ann(), params(5), &agent);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A suspended agent cannot start a run even with no tools or delegation.
    #[test]
    fn a_run_with_no_tools_for_an_agent_that_may_not_act_is_refused() {
        let mut agent = agent();
        agent.suspend(SuspendedBy::Monitor).unwrap();
        let toolless = StartRunParams {
            granted_tools: Vec::new(),
            ..params(5)
        };

        let result = AgentRun::start_without_tools(by_ann(), toolless, &agent);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Per-action approval on the delegation makes even a read await approval;
    /// the run cannot record that call as allowed without it.
    #[test]
    fn a_delegation_that_approves_every_action_makes_every_call_wait() {
        let agent = agent();
        let delegation = delegation(&agent, constraints().requiring_approval());
        let mut run = AgentRun::start(by_ann(), params(5), &delegation, &agent).unwrap();
        let get_order = tool("get_order");

        assert_eq!(run.approval(), ActionApproval::PerAction);
        assert_eq!(
            run.admit(&calling(&get_order, "{}")),
            Ok(Admission::NeedsApproval)
        );
        let result = run.record_allowed(calling(&get_order, "{}"), &agent, "ok");
        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}
