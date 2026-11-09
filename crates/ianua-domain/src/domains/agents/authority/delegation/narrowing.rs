//! Keeps a sub-delegation inside its parent. Every limit the parent carries
//! is carried into the child.

use crate::domains::agents::authority::capability::{
    ActionApproval, AgentBudget, AppAccess, DelegationConstraints, Limits, ResourceScope,
    TokenBinding,
};
use crate::domains::agents::authority::delegation::Delegation;
use crate::domains::agents::authority::intent::IntentBinding;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// The constraints a child gets, held inside its parent's.
///
/// The child keeps the parent's task, depth limit, purpose, resource scope,
/// apps, data class, template, budget, bound token and approval rule. It may
/// tighten any of them, never loosen one. Narrowing the capabilities alone is
/// not enough. Ann lets agent A act only with her approval. Without this, A
/// hands B the same rights with no approval rule, and B acts without asking.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when the child asks for a wider limit than
///   the parent has, or names a different task.
pub(crate) fn attenuate_constraints(
    parent: &DelegationConstraints,
    child: DelegationConstraints,
) -> Result<DelegationConstraints, DomainError> {
    let child = inherit_task(parent, attenuate_depth(parent, child)?)?;
    let limits = narrowed_limits(&parent.limits(), child.limits())?;
    Ok(inherit_gates(parent, child.with_limits(limits)))
}

/// `requested`, held inside the limits of every delegation in `ceiling`.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when `requested` asks for a wider limit
///   than one of them has, or names a different task.
pub(super) fn narrowed_by_all<T: TenantScope>(
    ceiling: &[Delegation<T>],
    requested: DelegationConstraints,
) -> Result<DelegationConstraints, DomainError> {
    ceiling.iter().try_fold(requested, |narrowed, parent| {
        attenuate_constraints(parent.constraints(), narrowed)
    })
}

/// Carries the parent's task into the child.
///
/// A delegation bound to a task binds everything made from it to that task.
/// A child that names no task gets the parent's. A child naming another task
/// is refused.
fn inherit_task(
    parent: &DelegationConstraints,
    child: DelegationConstraints,
) -> Result<DelegationConstraints, DomainError> {
    match (parent.task(), child.task()) {
        (None, _) => Ok(child),
        (Some(task), None) => Ok(child.with_task(task.clone())),
        (Some(task), Some(asked)) if asked == task => Ok(child),
        (Some(_), Some(_)) => Err(DomainError::forbidden(message!(
            "agents-a-sub-delegation-stays-bound-to",
            "a sub-delegation stays bound to its parent's task"
        ))),
    }
}

/// The limits `asked` for, each held inside the parent's limit in `ceiling`.
/// A limit the child leaves out takes the parent's own.
///
/// A purpose fits when its envelope is inside the parent's and its drift is
/// watched at least as strictly. A budget, resource scope or data class fits
/// when it is no wider. A template fits only when it is the parent's own,
/// because another template could allow more.
fn narrowed_limits(ceiling: &Limits, asked: Limits) -> Result<Limits, DomainError> {
    let exceeds = |what: &str| {
        DomainError::forbidden(message!(
            "agents-sub-delegation-exceeds-parent",
            format!("sub-delegation {what} exceeds parent")
        ))
    };
    Ok(Limits {
        budget: asked
            .budget
            .under(&ceiling.budget, AgentBudget::within)
            .ok_or_else(|| exceeds("budget"))?,
        intent: asked
            .intent
            .under(&ceiling.intent, intent_within)
            .ok_or_else(|| exceeds("intent"))?,
        resource_scope: asked
            .resource_scope
            .under(&ceiling.resource_scope, ResourceScope::subset_of)
            .ok_or_else(|| exceeds("resource scope"))?,
        apps: apps_under(asked.apps, &ceiling.apps)?,
        max_data_class: asked
            .max_data_class
            .under(&ceiling.max_data_class, |child, parent| child <= parent)
            .ok_or_else(|| exceeds("data class"))?,
        template: asked
            .template
            .under(&ceiling.template, |child, parent| child == parent)
            .ok_or_else(|| exceeds("template"))?,
    })
}

/// Whether the purpose `child` asks for fits inside `parent`: its envelope
/// is inside the parent's and its drift is watched at least as strictly.
fn intent_within(child: &IntentBinding, parent: &IntentBinding) -> bool {
    child.envelope().subset_of(parent.envelope())
        && child
            .drift_policy()
            .at_least_as_strict_as(parent.drift_policy())
}

/// The apps `asked` for, held inside the apps the parent reaches.
///
/// A child naming no apps reaches none. A child of a parent that reaches no
/// app may not name any.
fn apps_under(asked: AppAccess, ceiling: &AppAccess) -> Result<AppAccess, DomainError> {
    match (ceiling, asked) {
        (_, AppAccess::NoApps) => Ok(AppAccess::NoApps),
        (AppAccess::NoApps, AppAccess::Listed(_)) => Err(DomainError::forbidden(message!(
            "agents-sub-delegation-names-apps-its-parent",
            "sub-delegation names apps its parent does not reach"
        ))),
        (AppAccess::Listed(parent), AppAccess::Listed(child)) if child.subset_of(parent) => {
            Ok(AppAccess::Listed(child))
        }
        (AppAccess::Listed(_), AppAccess::Listed(_)) => Err(DomainError::forbidden(message!(
            "agents-sub-delegation-apps-exceed-parent",
            "sub-delegation apps exceed parent"
        ))),
    }
}

/// Refuses a child whose depth limit is higher than its parent's, so a
/// child never allows a longer chain than its parent does.
fn attenuate_depth(
    parent: &DelegationConstraints,
    child: DelegationConstraints,
) -> Result<DelegationConstraints, DomainError> {
    if child.max_depth() > parent.max_depth() {
        return Err(DomainError::forbidden(message!(
            "agents-sub-delegation-max-depth-exceeds-parent",
            "sub-delegation max depth exceeds parent"
        )));
    }
    Ok(child)
}

/// Carries the parent's bound-token rule and per-action approval into the
/// child. A child keeps each one whenever the parent has it.
fn inherit_gates(
    parent: &DelegationConstraints,
    child: DelegationConstraints,
) -> DelegationConstraints {
    let child = match (parent.binding(), child.binding()) {
        (TokenBinding::ProofOfPossession, TokenBinding::Bearer) => child.sender_constrained(),
        (TokenBinding::Bearer | TokenBinding::ProofOfPossession, _) => child,
    };
    match (parent.approval(), child.approval()) {
        (ActionApproval::PerAction, ActionApproval::NotRequired) => child.requiring_approval(),
        (ActionApproval::NotRequired | ActionApproval::PerAction, _) => child,
    }
}
