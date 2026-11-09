//! The rules a resource type's actions keep: a bounded number, concrete
//! names, each declared once, conferring only declared actions, no loop.

use std::collections::HashSet;

use crate::domains::authorization::ladder::{index_by_key, walk_for_loops};
use crate::domains::authorization::permission::PermissionSegment;
use crate::domains::authorization::resource_type::{
    ActionDefinition, MAX_ACTIONS, ensure_concrete,
};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;

/// Refuses a set of actions that is empty or too long, names `*`, declares
/// a key twice, confers what it does not declare, or loops.
pub(super) fn validate_actions(actions: &[ActionDefinition]) -> Result<(), DomainError> {
    ensure_action_count(actions)?;
    ensure_concrete_verbs(actions)?;
    let keys = unique_keys(actions)?;
    ensure_implications_declared(actions, &keys)?;
    reject_cycles(actions)
}

/// Refuses `*` as an action or as an action it confers. A `*` there would
/// hand out every action on the resource, now and later, under a name
/// that looks like any other.
fn ensure_concrete_verbs(actions: &[ActionDefinition]) -> Result<(), DomainError> {
    actions
        .iter()
        .flat_map(|action| std::iter::once(&action.key).chain(&action.implies))
        .try_for_each(|segment| ensure_concrete("action", segment))
}

fn ensure_action_count(actions: &[ActionDefinition]) -> Result<(), DomainError> {
    validate_count("actions", actions.len(), 1..=MAX_ACTIONS)?;
    Ok(())
}

/// The declared keys, once none is declared twice.
fn unique_keys(actions: &[ActionDefinition]) -> Result<HashSet<&str>, DomainError> {
    let keys = actions.iter().map(|action| action.key.as_str());
    if let Some(twice) = first_repeat(keys.clone()) {
        return Err(DomainError::invalid(message!(
            "authorization-action-is-declared-twice",
            format!("action '{twice}' is declared twice")
        )));
    }
    Ok(keys.collect())
}

/// Refuses an action that confers itself, or an action this resource
/// does not declare.
fn ensure_implications_declared(
    actions: &[ActionDefinition],
    keys: &HashSet<&str>,
) -> Result<(), DomainError> {
    actions.iter().try_for_each(|action| {
        action
            .implies
            .iter()
            .try_for_each(|implied| ensure_confers_declared(action, implied, keys))
    })
}

fn ensure_confers_declared(
    action: &ActionDefinition,
    implied: &PermissionSegment,
    keys: &HashSet<&str>,
) -> Result<(), DomainError> {
    if implied == &action.key {
        return Err(DomainError::invalid(message!(
            "authorization-action-cannot-confer-itself",
            format!("action '{}' cannot confer itself", action.key)
        )));
    }
    if !keys.contains(implied.as_str()) {
        return Err(DomainError::invalid(message!(
            "authorization-action-confers-which-this-resource-does",
            format!(
                "action '{}' confers '{implied}', which this resource does not declare",
                action.key
            )
        )));
    }
    Ok(())
}

/// Refuses a ladder that loops. In a loop, each action on it confers all
/// the others, which nobody means.
fn reject_cycles(actions: &[ActionDefinition]) -> Result<(), DomainError> {
    let by_key = index_by_key(actions);
    let mut settled: HashSet<&str> = HashSet::new();
    actions
        .iter()
        .try_for_each(|action| walk_for_loops(action.key.as_str(), &by_key, &mut settled))
}
