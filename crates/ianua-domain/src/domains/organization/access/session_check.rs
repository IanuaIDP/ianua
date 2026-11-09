//! The check a stored organization session passes each time it is used,
//! and the session that passed it.

use time::OffsetDateTime;

use crate::domains::organization::access::session::OrgSession;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::status::OrgStanding;
use crate::types::Seconds;

/// What a stored org session is held to each time it is used: the member
/// as they stand now, and the organization's idle timeout.
#[derive(Debug, Clone, Copy)]
pub struct OrgSessionCheck<'a> {
    /// The organization as it stands now.
    pub organization: OrgStanding,
    /// The member the session belongs to, as they are now.
    pub member: &'a OrgUser,
    /// How long the session may sit unused.
    pub idle_timeout: Seconds,
    /// When the session is being used.
    pub now: OffsetDateTime,
}

impl OrgSessionCheck<'_> {
    /// `session`, once it passes this check, for a member to act through.
    ///
    /// It is the only way a session reaches an
    /// [`OrgControl`](crate::domains::organization::members::control::OrgControl).
    /// So a session that sat unused past the idle timeout never carries its
    /// member's role, whichever path builds the control.
    #[must_use]
    pub fn checked<'s>(&self, session: &'s OrgSession) -> Option<CheckedOrgSession<'s>> {
        self.admits(session)
            .then_some(CheckedOrgSession { session })
    }

    /// Whether `session` still counts: it counts for the member, has not
    /// sat unused longer than the idle timeout, and the organization still
    /// lets the member in. A plain member signed in before the platform
    /// suspended Acme is out at once.
    #[must_use]
    pub fn admits(&self, session: &OrgSession) -> bool {
        let idle_until = session
            .last_active_at()
            .saturating_add(self.idle_timeout.duration());
        session.counts_for(self.member)
            && self.now < idle_until
            && self.organization.id() == session.organization_id()
            && self.organization.ensure_admits(self.member.role()).is_ok()
    }
}

/// A session that passed its [`OrgSessionCheck`] when it was used.
///
/// It counts for its member, has not sat unused past the organization's
/// idle timeout, and the organization lets the member in. Only
/// [`OrgSessionCheck::checked`] makes one.
#[derive(Debug, Clone, Copy)]
pub struct CheckedOrgSession<'a> {
    session: &'a OrgSession,
}

impl<'a> CheckedOrgSession<'a> {
    /// The session that passed.
    #[must_use]
    pub fn session(&self) -> &'a OrgSession {
        self.session
    }

    /// `session`, taken as checked without its check.
    ///
    /// For tests of what is checked after it, such as the organization's
    /// standing in an [`OrgControl`](crate::domains::organization::members::control::OrgControl).
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(session: &'a OrgSession) -> Self {
        Self { session }
    }
}
