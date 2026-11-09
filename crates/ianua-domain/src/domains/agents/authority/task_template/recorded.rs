//! What a task template raises as it is proposed, approved and retired.

use crate::domains::agents::authority::task_template::TaskTemplate;
use crate::domains::agents::events::authority::{AgentTaskTemplateChanged, TaskTemplateChange};
use crate::isolation::scope::TenantScope;
use crate::shared::clock;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raises, SavedFor};
use crate::types::EventLabel;

/// `template`, new, having raised its proposal.
pub(super) fn proposed<T: TenantScope>(mut template: TaskTemplate<T>) -> TaskTemplate<T> {
    raise_change(&mut template, TaskTemplateChange::Proposed);
    template
}

/// Raises the approval of `template`.
pub(super) fn raise_approval<T: TenantScope>(template: &mut TaskTemplate<T>) {
    raise_change(template, TaskTemplateChange::Approved);
}

/// Raises the retirement of `template`.
pub(super) fn raise_retirement<T: TenantScope>(template: &mut TaskTemplate<T>) {
    raise_change(template, TaskTemplateChange::Retired);
}

/// Raises `change` to `template`, naming it by its name.
fn raise_change<T: TenantScope>(template: &mut TaskTemplate<T>, change: TaskTemplateChange) {
    let event = AgentTaskTemplateChanged {
        template_id: template.id,
        template_label: EventLabel::of(template.name.as_str()),
        change,
        occurred_at: clock::now(),
    };
    template.raised.raise(event);
}

impl<T: TenantScope> Raises for TaskTemplate<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}
