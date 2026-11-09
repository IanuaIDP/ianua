//! What a break-glass grant records: its granting and its early end, each
//! naming the user, for the tenant the grant is in; and what the tenant's
//! policy records when it changes.
//!
//! A grant and a policy hold their tenant, so their records are whole when
//! they are raised.

use crate::domains::authentication::events::break_glass::{BreakGlassGranted, BreakGlassRevoked};
use crate::domains::authorization::break_glass::{BreakGlassGrant, BreakGlassPolicy, SelfService};
use crate::domains::authorization::events::break_glass::BreakGlassPolicyChanged;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::RaisesComplete;
use crate::types::EventLabel;

impl BreakGlassGrant {
    /// Raises `authentication.break_glass_granted` for the grant just made,
    /// naming its user as `grantee_label`, with the reason and its end.
    pub(super) fn raise_granted(&mut self, grantee_label: EventLabel) {
        let granted = BreakGlassGranted {
            user_id: self.user_id,
            user_label: grantee_label,
            reason: self.reason.clone(),
            expires_at: self.expires_at,
            occurred_at: self.created_at,
        };
        self.raised.raise_tenant(self.tenant_id, granted);
    }

    /// Ends the grant now while it is in force, and raises
    /// `authentication.break_glass_revoked`, naming its user as `holder`. A
    /// grant already ended keeps its first end and raises nothing.
    pub(super) fn end_early(&mut self, holder: EventLabel) {
        if self.revocation.is_revoked() {
            return;
        }
        let now = crate::shared::clock::now();
        self.revocation = self.revocation.revoke_at(now);
        let revoked = BreakGlassRevoked {
            user_id: self.user_id,
            user_label: holder,
            occurred_at: now,
        };
        self.raised.raise_tenant(self.tenant_id, revoked);
    }
}

impl RaisesComplete for BreakGlassGrant {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

impl BreakGlassPolicy {
    /// Raises `authorization.break_glass_policy_changed`, from `previous`
    /// to what the policy lets now.
    pub(super) fn raise_changed(&mut self, previous: SelfService) {
        let changed = BreakGlassPolicyChanged {
            previous,
            current: self.self_service.clone(),
            occurred_at: self.updated_at,
        };
        self.raised.raise_tenant(self.tenant_id, changed);
    }
}

impl RaisesComplete for BreakGlassPolicy {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}
