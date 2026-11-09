//! Walking a resource type's ladder: which actions an action leads to, and
//! what a new ladder confers that the old one did not.

use std::collections::{HashMap, HashSet};

use crate::domains::authorization::permission::{CustomPermission, PermissionSegment};
use crate::domains::authorization::resource_type::ActionDefinition;
use crate::message;
use crate::shared::errors::DomainError;

/// Every action `action` leads to down `actions`, itself included, sorted.
pub(crate) fn reachable<'a>(actions: &'a [ActionDefinition], action: &'a str) -> Vec<&'a str> {
    let by_key = index_by_key(actions);
    let mut seen = HashSet::new();
    let mut queue = vec![action];
    let mut reached = Vec::new();
    while let Some(current) = queue.pop() {
        if !seen.insert(current) {
            continue;
        }
        reached.push(current);
        let implied = by_key
            .get(current)
            .copied()
            .map_or(&[][..], ActionDefinition::implies);
        queue.extend(implied.iter().map(PermissionSegment::as_str));
    }
    reached.sort_unstable();
    reached
}

/// What the ladder `after` confers that `before` did not. For each action,
/// this is what it reaches now beyond itself and beyond what it reached
/// before.
///
/// # Errors
///
/// - [`DomainError::Validation`] if a pair is not a valid permission. The
///   catalogue's own checks make this unexpected.
pub(crate) fn widening(
    resource: &PermissionSegment,
    before: &[ActionDefinition],
    after: &[ActionDefinition],
) -> Result<Vec<CustomPermission>, DomainError> {
    let mut added: Vec<&str> = after
        .iter()
        .flat_map(|action| {
            let key = action.key().as_str();
            let previously = reachable(before, key);
            reachable(after, key)
                .into_iter()
                .filter(move |reached| *reached != key && !previously.contains(reached))
        })
        .collect();
    added.sort_unstable();
    added.dedup();
    added
        .into_iter()
        .map(|action| CustomPermission::new(resource.as_str(), action).map_err(DomainError::from))
        .collect()
}

/// The actions of a ladder by their keys.
pub(crate) fn index_by_key(actions: &[ActionDefinition]) -> HashMap<&str, &ActionDefinition> {
    actions
        .iter()
        .map(|entry| (entry.key().as_str(), entry))
        .collect()
}

/// Walks the ladder down from `start` depth first, failing on the first
/// action reached again while still on the current path. Actions already
/// proven loop-free go into `settled` and are not walked twice.
///
/// # Errors
///
/// - [`DomainError::Validation`] when an action confers itself through a
///   loop.
pub(crate) fn walk_for_loops<'a>(
    start: &'a str,
    by_key: &HashMap<&'a str, &'a ActionDefinition>,
    settled: &mut HashSet<&'a str>,
) -> Result<(), DomainError> {
    let mut on_path: HashSet<&str> = HashSet::new();
    let mut stack: Vec<(&str, usize)> = vec![(start, 0)];
    while let Some((current, index)) = stack.pop() {
        if index == 0 && settled.contains(current) {
            continue;
        }
        if index == 0 && !on_path.insert(current) {
            return Err(DomainError::invalid(message!(
                "authorization-action-confers-itself-through-a-loop",
                format!("action '{current}' confers itself through a loop")
            )));
        }
        let implied = by_key
            .get(current)
            .copied()
            .map_or(&[][..], ActionDefinition::implies);
        let Some(next) = implied.get(index) else {
            on_path.remove(current);
            settled.insert(current);
            continue;
        };
        stack.push((current, index.saturating_add(1)));
        stack.push((next.as_str(), 0));
    }
    Ok(())
}
