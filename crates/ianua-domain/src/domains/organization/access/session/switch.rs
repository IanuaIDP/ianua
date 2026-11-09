//! Moving a session into a tenant of the organization without signing in
//! again: a new session there, checked against the member's grants as
//! signing in is, that carries the sign-in the old one finished.

use crate::domains::authentication::sessions::status::SessionStatus;
use crate::domains::organization::access::session::{
    OrgSession, SessionPlace, SessionSwitch, ensure_may_enter,
};
use crate::domains::organization::access::session_check::OrgSessionCheck;
use crate::domains::organization::events::access::OrgSessionMoved;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::raised::RaisedEvents;
use crate::types::TenantId;

impl OrgSession {
    /// A new session in a tenant of the organization, carrying `from` on
    /// without signing in again. `from` is retired in the same step.
    ///
    /// An organization session works in one tenant, or on the organization
    /// alone. Moving into a tenant is a new session there, checked against
    /// the member's grants as signing in is: an owner reaches every tenant
    /// the organization owns, a plain member only those they hold a grant
    /// for, a billing contact or a viewer none. Sam is granted only
    /// `staging`. Without this, he switches his `staging` session to
    /// `production` and manages it. Sam signed in before anyone granted him
    /// a tenant, so his session works on the organization alone; once Ann
    /// grants him `staging`, he moves into it the same way.
    ///
    /// The new session keeps the sign-in `from` finished, its address and
    /// client, and ends when `from` would have, so switching never extends
    /// a sign-in. Only a session that still counts under `check` is carried
    /// on. The new session raises `organization.org_session_moved`; `from`
    /// raises nothing, its end is part of the move.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `check` does not admit `from`: it
    ///   is not the member's, owes a step, ended, sat idle too long, or the
    ///   organization no longer lets the member in.
    /// - [`DomainError::Forbidden`] when `to.entry` is for another member
    ///   or organization than `from`.
    /// - [`DomainError::Validation`] when `to.tenant_id` is the tenant
    ///   `from` already works in.
    /// - The cases [`OrgSession::create`] lists for entering the tenant.
    /// - [`DomainError::InvalidTransition`] when `from` cannot be retired.
    pub fn switch_to(
        from: &mut OrgSession,
        check: &OrgSessionCheck<'_>,
        to: SessionSwitch<'_>,
    ) -> Result<Self, DomainError> {
        if !check.admits(from) {
            return Err(DomainError::forbidden(message!(
                "organization-the-session-no-longer-counts-so",
                "the session no longer counts, so it moves to no other tenant"
            )));
        }
        let source = from.source_of_switch(&to)?;
        ensure_may_enter(&to.entry, SessionPlace::Tenant(to.tenant_id))?;
        from.status = from.status.try_transition(SessionStatus::Revoked)?;
        let now = check.now;
        let mut moved = Self {
            id: to.id,
            org_user_id: from.org_user_id,
            organization_id: from.organization_id,
            place: SessionPlace::Tenant(to.tenant_id),
            refresh_token_hash: to.refresh_token_hash,
            progress: from.progress.carried(),
            ip_address: from.ip_address.clone(),
            user_agent: from.user_agent.clone(),
            status: SessionStatus::Active,
            created_at: now,
            last_active_at: now,
            expires_at: from.expires_at,
            kept_through: from.kept_through,
            raised: RaisedEvents::default(),
        };
        moved.raise_moved(source, to.tenant_id);
        Ok(moved)
    }

    /// Raises this new session's move from `source` into `target`.
    fn raise_moved(&mut self, source: SessionPlace, target: TenantId) {
        self.raised.raise_organization(OrgSessionMoved {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            source,
            target_tenant_id: target,
            new_session_id: self.id,
            occurred_at: self.created_at,
        });
    }

    /// Where this session works, once the switch `to` carries it on:
    /// refused when its entry is for another member or organization, or
    /// `to` lands in the tenant it works in already.
    fn source_of_switch(&self, to: &SessionSwitch<'_>) -> Result<SessionPlace, DomainError> {
        if *to.entry.member.id() != self.org_user_id
            || *to.entry.organization.id() != self.organization_id
        {
            return Err(DomainError::forbidden(message!(
                "organization-a-session-moves-only-its-own",
                "a session moves only its own member within its own organization"
            )));
        }
        if self.place == SessionPlace::Tenant(to.tenant_id) {
            return Err(DomainError::invalid(message!(
                "organization-the-session-already-works-in-this",
                "the session already works in this tenant"
            )));
        }
        Ok(self.place)
    }
}
