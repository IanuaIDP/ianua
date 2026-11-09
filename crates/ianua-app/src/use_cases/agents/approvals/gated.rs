//! An agent action the gateway asks about: the exact action a person
//! approves, and the live delegation it must use.
//!
//! Holding an action for a person and spending their approval both refuse
//! a delegation that is not the agent's, or no longer backs anything.
//! Nothing is held or let through on a delegation revoked or expired,
//! itself or up its chain, however it was approved.

use ianua_domain::domains::agents::authority::delegation::{ActingUnder, Delegation};
use ianua_domain::domains::agents::oversight::approval::ApprovalAction;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{ActionClass, DeclaredAction};
use time::OffsetDateTime;

use crate::error::AppError;
use crate::ports::agents::GatedAction;
use crate::use_cases::agents::approvals::action_authority::LoadedAuthority;
use crate::use_cases::agents::reject_foreign_child;

/// The exact action a person approves: method and target, nothing looser.
///
/// # Errors
///
/// `AppError::Domain` when the action cannot be summarized.
pub(super) fn approval_action(action: &GatedAction) -> Result<ApprovalAction, AppError> {
    ApprovalAction::for_call(action.method, &action.target).map_err(AppError::from_domain)
}

/// The class the person deciding sees: the route's declared one, or what
/// the call reads as.
pub(super) fn action_class(action: &GatedAction) -> DeclaredAction {
    DeclaredAction::Declared(ActionClass::for_call(
        action.method,
        &action.target,
        action.declared,
    ))
}

/// The authority the action acts under.
pub(super) fn acting_under(action: &GatedAction) -> ActingUnder {
    ActingUnder::Delegation(action.delegation_id)
}

/// The delegation the action uses, once it is the agent's own and still
/// backs something at `now`: not revoked or expired, itself or up its
/// chain.
///
/// # Errors
///
/// - `AppError::NotFound` when the delegation was granted to another agent.
/// - `AppError::Forbidden` when it, or one above it, is no longer live.
pub(super) fn live_delegation<'a>(
    action: &GatedAction,
    loaded: &'a LoadedAuthority,
    now: OffsetDateTime,
) -> Result<&'a Delegation<ResolvedTenant>, AppError> {
    let Some(delegation) = loaded.delegation() else {
        return Err(no_longer_live());
    };
    reject_foreign_child(&action.agent_id, delegation.delegate())?;
    if loaded.authority().backs(&acting_under(action), now) {
        return Ok(delegation);
    }
    Err(no_longer_live())
}

fn no_longer_live() -> AppError {
    AppError::Forbidden(message!(
        "agents-the-delegation-the-action-uses-is",
        "the delegation the action uses is no longer live"
    ))
}
