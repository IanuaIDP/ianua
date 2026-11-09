//! What a run may reach for while a worker drives it.
//!
//! A run can wait a long time between steps, and the delegation behind it
//! can change meanwhile. So the worker checks it again before driving: the
//! delegation and every delegation it was cut or minted from must still be
//! live, and none may grant more than the person behind it holds today. Only
//! then is the task token minted. The tools offered are the run's granted
//! tools, inside its purpose, that the person who started it may still use.

use ianua_domain::domains::agents::authority::capability::{CapabilitySet, ResourceCapability};
use ianua_domain::domains::agents::authority::delegation::{Delegation, HeldNow};
use ianua_domain::domains::agents::execution::run::AgentRun;
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::oversight::approval::ActionAuthority;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{DelegationId, HumanAccount, Initiator, PrincipalRef};

use crate::error::{AppError, OrInternal};
use crate::ports::agents::TaskToken;
use crate::use_cases::agents::delegation::granting::authority::asked_about;
use crate::use_cases::agents::lookup::delegations_above;
use crate::use_cases::agents::runs::driving::drive::Driving;

/// What a run may reach for: its tools, and the authority its calls carry.
pub(in crate::use_cases::agents::runs) struct Toolbox {
    /// The tools the run may call.
    tools: Vec<AgentTool<ResolvedTenant>>,
    /// The delegation the calls use, when there is one.
    authority: RunAuthority,
}

/// The authority a run's calls carry.
enum RunAuthority {
    /// The run acts under no delegation, so it may call no tool.
    NoDelegation,
    /// The run acts under `chain`, and its calls carry `token`.
    Delegation {
        /// The delegation and every delegation above it.
        chain: Box<Chain>,
        /// The task token minted from it.
        token: TaskToken,
    },
}

/// A delegation with every delegation it was cut or minted from.
struct Chain {
    /// The delegation the run acts under.
    delegation: Delegation<ResolvedTenant>,
    /// The delegations above it, in any order.
    above: Vec<Delegation<ResolvedTenant>>,
}

impl Toolbox {
    /// The tools the model is told about. None for a run that may call
    /// none: offering tools that will all be refused only wastes its steps.
    pub(in crate::use_cases::agents::runs) fn offered(&self) -> &[AgentTool<ResolvedTenant>] {
        match self.authority {
            RunAuthority::NoDelegation => &[],
            RunAuthority::Delegation { .. } => &self.tools,
        }
    }

    /// The task token the run's calls carry, when it acts under a
    /// delegation.
    pub(in crate::use_cases::agents::runs) fn token(&self) -> Option<&TaskToken> {
        match &self.authority {
            RunAuthority::NoDelegation => None,
            RunAuthority::Delegation { token, .. } => Some(token),
        }
    }

    /// The offered tool named `name`.
    pub(in crate::use_cases::agents::runs) fn tool(
        &self,
        name: &str,
    ) -> Option<&AgentTool<ResolvedTenant>> {
        self.offered()
            .iter()
            .find(|tool| tool.name().as_str() == name)
    }

    /// The authority an action of the run uses, as an approval names it.
    pub(in crate::use_cases::agents::runs) fn action_authority(
        &self,
    ) -> ActionAuthority<'_, ResolvedTenant> {
        match &self.authority {
            RunAuthority::NoDelegation => ActionAuthority::NoDelegation,
            RunAuthority::Delegation { chain, .. } => ActionAuthority::Delegation {
                delegation: &chain.delegation,
                above: &chain.above,
            },
        }
    }

    /// Every delegator along the run's chain.
    pub(in crate::use_cases::agents::runs) fn delegators(&self) -> Vec<PrincipalRef> {
        match &self.authority {
            RunAuthority::NoDelegation => Vec::new(),
            RunAuthority::Delegation { chain, .. } => {
                chain.links().map(|link| *link.delegator()).collect()
            }
        }
    }
}

impl Chain {
    /// The delegation and every delegation above it.
    fn links(&self) -> impl Iterator<Item = &Delegation<ResolvedTenant>> {
        std::iter::once(&self.delegation).chain(&self.above)
    }
}

/// What `run` may reach for now, or `None` when its delegation no longer
/// holds.
///
/// # Errors
///
/// - `AppError::Internal` on storage failure.
/// - The issuer's error, through [`AppError::from_domain`], when the token
///   cannot be minted.
pub(in crate::use_cases::agents::runs) async fn run_toolbox(
    driving: &Driving<'_>,
    run: &AgentRun<ResolvedTenant>,
) -> Result<Option<Toolbox>, AppError> {
    let Some(chain) = unless_refused(run_chain(driving, run).await)? else {
        return Ok(None);
    };
    let registry = registered_tools(driving).await?;
    let held = run_authority(driving, &registry, chain).await;
    let Some(authority) = unless_refused(held)? else {
        return Ok(None);
    };
    let tools = offered_tools(driving, &registry, run).await;
    Ok(Some(Toolbox { tools, authority }))
}

/// `result`, with a refusal read as `None`: a run whose delegation no
/// longer holds is given no toolbox.
fn unless_refused<T>(result: Result<T, AppError>) -> Result<Option<T>, AppError> {
    match result {
        Ok(found) => Ok(Some(found)),
        Err(AppError::Forbidden(reason)) => {
            tracing::warn!(%reason, "the run's delegation no longer holds; halting it");
            Ok(None)
        }
        Err(failed) => Err(failed),
    }
}

/// Every tool the tenant registered.
async fn registered_tools(
    driving: &Driving<'_>,
) -> Result<Vec<AgentTool<ResolvedTenant>>, AppError> {
    driving
        .ports
        .stores
        .tool_store
        .list(driving.tenant)
        .await
        .or_internal()
}

/// The delegation `run` acts under with every one above it, once all are
/// live, or `None` when it acts under none.
///
/// # Errors
///
/// - `AppError::Forbidden` when the delegation or one above it is gone,
///   revoked or expired.
/// - `AppError::Internal` on storage failure.
async fn run_chain(
    driving: &Driving<'_>,
    run: &AgentRun<ResolvedTenant>,
) -> Result<Option<Chain>, AppError> {
    let Some(delegation_id) = run.delegation_id().delegation() else {
        return Ok(None);
    };
    live_chain(driving, delegation_id).await.map(Some)
}

/// The authority a run acting under `chain` carries, checked again now.
///
/// # Errors
///
/// - `AppError::Forbidden` when a delegation of the chain grants more than
///   the person behind it holds, or that person may no longer act.
/// - `AppError::NotFound` when the tenant or its organization, whose issuer
///   the token names, is not on record.
/// - `AppError::Internal` on storage or signing failure.
async fn run_authority(
    driving: &Driving<'_>,
    registry: &[AgentTool<ResolvedTenant>],
    chain: Option<Chain>,
) -> Result<RunAuthority, AppError> {
    let Some(chain) = chain else {
        return Ok(RunAuthority::NoDelegation);
    };
    ensure_still_held(driving, registry, &chain).await?;
    let issuer = driving.ports.calls.issuers.of(driving.tenant).await?;
    let token = driving
        .ports
        .calls
        .task_token_issuer
        .issue(driving.tenant, &issuer, &chain.delegation)
        .await
        .map_err(AppError::from_domain)?;
    Ok(RunAuthority::Delegation {
        chain: Box::new(chain),
        token,
    })
}

/// Refuses a chain where a delegation a person granted grants more than
/// they hold today.
///
/// Granting checked the person once. Losing a role since does not revoke
/// the delegation, so without this the agent goes on acting with authority
/// its delegator no longer has. A link an agent passed on or minted is held
/// to what it was cut from, which [`live_chain`] checks.
async fn ensure_still_held(
    driving: &Driving<'_>,
    registry: &[AgentTool<ResolvedTenant>],
    chain: &Chain,
) -> Result<(), AppError> {
    for link in chain.links() {
        let Some(delegator) = link.delegator().human_account() else {
            continue;
        };
        let held = held_now(driving, delegator, link.granted(), registry).await?;
        if !link.still_allowed(&held) {
            return Err(AppError::Forbidden(message!(
                "agents-the-run-s-delegation-grants-more",
                "the run's delegation grants more than its delegator now holds"
            )));
        }
    }
    Ok(())
}

/// The delegation `delegation_id` names with every delegation above it,
/// once all of them are live.
///
/// # Errors
///
/// - `AppError::Forbidden` when the delegation is gone, or it or one above
///   it is revoked or expired.
/// - `AppError::Internal` on storage failure.
async fn live_chain(
    driving: &Driving<'_>,
    delegation_id: &DelegationId,
) -> Result<Chain, AppError> {
    let delegation = stored_delegation(driving, delegation_id)
        .await?
        .ok_or_else(|| {
            AppError::Forbidden(message!(
                "agents-the-run-s-delegation-no-longer",
                "the run's delegation no longer exists"
            ))
        })?;
    let above = delegations_above(
        driving.ports.stores.delegation_store.as_ref(),
        driving.tenant,
        &delegation,
    )
    .await?;
    if !delegation.live_under(&above, clock::now()) {
        return Err(AppError::Forbidden(message!(
            "agents-the-run-s-delegation-or-one",
            "the run's delegation, or one it rests on, is revoked or expired"
        )));
    }
    Ok(Chain { delegation, above })
}

/// The tenant's delegation with `id`, if it is still stored.
async fn stored_delegation(
    driving: &Driving<'_>,
    id: &DelegationId,
) -> Result<Option<Delegation<ResolvedTenant>>, AppError> {
    driving
        .ports
        .stores
        .delegation_store
        .find_by_id(driving.tenant, id)
        .await
        .or_internal()
}

/// What the person holding `account` holds now of `wanted`, from their
/// account as it stands, their share of the tenant's records and the
/// relationship graph's answer for them.
///
/// # Errors
///
/// - `AppError::Forbidden` when their account is gone, or may not act in
///   the tenant now.
/// - `AppError::Internal` when the records cannot be read, or name a role
///   or group that is not there.
async fn held_now(
    driving: &Driving<'_>,
    account: HumanAccount,
    wanted: &CapabilitySet,
    registry: &[AgentTool<ResolvedTenant>],
) -> Result<HeldNow, AppError> {
    let asked = asked_about(wanted, registry);
    let accounts = driving.ports.people.accounts_now.as_ref();
    let Some(person) = accounts.holder_of(driving.tenant, account, &asked).await? else {
        return Err(AppError::Forbidden(message!(
            "agents-the-person-behind-the-run-s",
            "the person behind the run's delegation is gone"
        )));
    };
    person
        .authority(|account, access, held| {
            HeldNow::worked_out(access, account, wanted, held, registry)
        })?
        .ok_or_else(|| {
            AppError::Forbidden(message!(
                "agents-the-person-behind-the-run-s-2",
                "the person behind the run's delegation may not act now"
            ))
        })
}

/// The registered tools `run` may be offered: active, granted to it, inside
/// its purpose, and ones the person who started it may still use.
///
/// A run an agent started for itself is held to its delegation instead. A
/// run a consumer started is offered none. Whatever cannot be worked out
/// offers none.
async fn offered_tools(
    driving: &Driving<'_>,
    registry: &[AgentTool<ResolvedTenant>],
    run: &AgentRun<ResolvedTenant>,
) -> Vec<AgentTool<ResolvedTenant>> {
    let candidates: Vec<_> = registry
        .iter()
        .filter(|tool| {
            tool.is_active()
                && run.grants_tool(tool.name())
                && run.purpose().permits(tool.action_class())
        })
        .cloned()
        .collect();
    match run.started_by() {
        Initiator::Human(person) => {
            usable_by(driving, person.account(), candidates, registry).await
        }
        Initiator::Agent(_) => candidates,
        Initiator::Consumer(_) => Vec::new(),
    }
}

/// The part of `candidates` that `person` may use now: all of them for an
/// agent administrator, otherwise the ones they were given use of.
async fn usable_by(
    driving: &Driving<'_>,
    person: HumanAccount,
    candidates: Vec<AgentTool<ResolvedTenant>>,
    registry: &[AgentTool<ResolvedTenant>],
) -> Vec<AgentTool<ResolvedTenant>> {
    let uses = candidates
        .iter()
        .map(|tool| ResourceCapability::use_of_tool(tool.id()))
        .collect();
    let wanted = CapabilitySet::empty().with_resources(uses);
    let Ok(held) = held_now(driving, person, &wanted, registry).await else {
        return Vec::new();
    };
    let administers = held.caps().permits(&SystemPermission::ManageAgents);
    candidates
        .into_iter()
        .filter(|tool| {
            administers
                || held
                    .caps()
                    .permits_resource(&ResourceCapability::use_of_tool(tool.id()))
        })
        .collect()
}
