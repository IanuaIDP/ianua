//! What a proposed task template must hold before anyone can approve it.

use crate::domains::agents::authority::capability::DelegationConstraints;
use crate::domains::agents::authority::task_template::ProposeTaskTemplateParams;
use crate::message;
use crate::shared::errors::DomainError;

/// Refuses a proposal that allows no capability or no action, or sets
/// limits no delegation could keep.
pub(super) fn ensure_proposable(params: &ProposeTaskTemplateParams) -> Result<(), DomainError> {
    if params.ceiling.is_empty() {
        return Err(DomainError::invalid(message!(
            "agents-a-task-template-must-allow-some-2",
            "a task template must allow some capability"
        )));
    }
    if params.classes.is_empty() {
        return Err(DomainError::invalid(message!(
            "agents-a-task-template-must-allow-some",
            "a task template must allow some kind of action"
        )));
    }
    DelegationConstraints::new(params.limits.max_ttl_seconds, params.limits.max_depth)?;
    Ok(())
}
