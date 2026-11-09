//! What a delegation raises as it is handed over, narrowed, widened,
//! renewed, taken back or caught drifting, and how it names itself in the
//! record.

use crate::domains::agents::authority::capability::{Relation, ResourceRef};
use crate::domains::agents::authority::delegation::Delegation;
use crate::domains::agents::events::authority::{
    AgentDelegationGranted, AgentDelegationRenewed, AgentDelegationResourceGranted,
    AgentDelegationResourceRevoked, AgentDelegationRevoked, AgentTokenIssued,
};
use crate::domains::agents::events::oversight::AgentIntentDrift;
use crate::isolation::scope::TenantScope;
use crate::shared::clock;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raises, SavedFor};
use crate::types::EventLabel;

/// The name a delegation is recorded under: its title, or its id when it
/// has none.
fn label<T: TenantScope>(delegation: &Delegation<T>) -> EventLabel {
    delegation.name.as_ref().map_or_else(
        || EventLabel::of(&delegation.id.to_string()),
        |name| EventLabel::of(name.as_str()),
    )
}

/// `delegation`, new, having raised its hand-over to the agent named
/// `delegate_label` and the issue of the task token it goes out with.
///
/// A delegation is never kept without its token: the application mints the
/// token before it saves the delegation, and one whose token cannot be
/// minted is never saved, so the two are recorded together.
pub(super) fn handed_over<T: TenantScope>(
    mut delegation: Delegation<T>,
    delegate_label: &EventLabel,
) -> Delegation<T> {
    let granted = AgentDelegationGranted {
        delegation_id: delegation.id,
        delegation_label: label(&delegation),
        delegate: delegation.delegate,
        delegate_label: delegate_label.clone(),
        occurred_at: delegation.issued_at,
    };
    let issued = AgentTokenIssued {
        delegation_id: delegation.id,
        delegation_label: label(&delegation),
        delegate: delegation.delegate,
        delegate_label: delegate_label.clone(),
        occurred_at: delegation.issued_at,
    };
    delegation.raised.raise(granted);
    delegation.raised.raise(issued);
    delegation
}

/// Raises the revoke of `delegation`.
pub(super) fn raise_revocation<T: TenantScope>(delegation: &mut Delegation<T>) {
    let event = AgentDelegationRevoked {
        delegation_id: delegation.id,
        delegation_label: label(delegation),
        occurred_at: clock::now(),
    };
    delegation.raised.raise(event);
}

/// Raises `relation` on `resource` being added to `delegation`.
pub(super) fn resource_granted<T: TenantScope>(
    delegation: &mut Delegation<T>,
    relation: &Relation,
    resource: &ResourceRef,
) {
    let event = AgentDelegationResourceGranted {
        delegation_id: delegation.id,
        delegation_label: label(delegation),
        relation: relation.clone(),
        resource: resource.clone(),
        occurred_at: clock::now(),
    };
    delegation.raised.raise(event);
}

/// Raises `relation` on `resource` being taken from `delegation`.
pub(super) fn resource_revoked<T: TenantScope>(
    delegation: &mut Delegation<T>,
    relation: &Relation,
    resource: &ResourceRef,
) {
    let event = AgentDelegationResourceRevoked {
        delegation_id: delegation.id,
        delegation_label: label(delegation),
        relation: relation.clone(),
        resource: resource.clone(),
        occurred_at: clock::now(),
    };
    delegation.raised.raise(event);
}

/// Raises the renewal of `delegation`, with the time it now expires.
pub(super) fn raise_renewal<T: TenantScope>(delegation: &mut Delegation<T>) {
    let event = AgentDelegationRenewed {
        delegation_id: delegation.id,
        delegation_label: label(delegation),
        expires_at: delegation.expires_at,
        occurred_at: delegation.updated_at,
    };
    delegation.raised.raise(event);
}

/// Raises an action under `delegation` leaving the intent it binds.
pub(super) fn raise_drift<T: TenantScope>(delegation: &mut Delegation<T>) {
    let event = AgentIntentDrift {
        delegation_id: delegation.id,
        delegation_label: label(delegation),
        occurred_at: clock::now(),
    };
    delegation.raised.raise(event);
}

impl<T: TenantScope> Raises for Delegation<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}
