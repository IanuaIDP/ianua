//! Who may export which audit log.
//!
//! There are three logs: a tenant's own, an organization's across its
//! tenants, and the whole platform's. Exporting one is a right of that
//! scope, apart from viewing it: a tenant role's export right, an
//! organization role's, or being an operator. The authority of each scope
//! checks its right and hands out an [`AuditLogAccess`] naming the log, so
//! what is exported, and downloaded, is always a log the caller may export.
//!
//! An organization's log runs across its tenants, and not every member
//! reaches every tenant. So what a member reads of it, on a page, in a
//! calendar or in a file, is the organization's own records and those of
//! the tenants in their [`LogReach`]: Vic, a viewer who reaches no tenant,
//! reads the organization's own records and nothing of any tenant's.

use crate::types::{ActorRef, OrganizationId, TenantId};

/// Selects the platform, organization or tenant boundary an export may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditLogOf {
    /// Every record of the platform, for operators.
    Platform,
    /// An organization's records and its tenants', as far as the reader
    /// reaches.
    Organization(OrganizationId),
    /// One tenant's own records.
    Tenant(TenantId),
}

impl AuditLogOf {
    /// The scope's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Organization(_) => "organization",
            Self::Tenant(_) => "tenant",
        }
    }
}

/// Which tenants' records a reader of an organization's log is shown,
/// beside the organization's own.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LogReach {
    /// Every tenant's: an owner's or an administrator's, and every reader
    /// of a tenant's own log or the platform's, which this does not narrow.
    #[default]
    Every,
    /// These tenants' and no other's. Empty for someone who reaches none.
    Tenants(Vec<TenantId>),
}

impl LogReach {
    /// Whether `tenant`'s records are shown.
    #[must_use]
    pub fn holds(&self, tenant: &TenantId) -> bool {
        match self {
            Self::Every => true,
            Self::Tenants(tenants) => tenants.contains(tenant),
        }
    }

    /// Whether everything `other` shows is shown here too, as someone
    /// handed a file made for `other` must be able to read all of it.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Every, _) => true,
            (Self::Tenants(_), Self::Every) => false,
            (Self::Tenants(tenants), Self::Tenants(wanted)) => {
                wanted.iter().all(|tenant| tenants.contains(tenant))
            }
        }
    }
}

/// What one reader sees of an organization's log: which organization's,
/// and how far into its tenants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgLogView {
    organization: OrganizationId,
    reach: LogReach,
}

impl OrgLogView {
    /// `organization`'s log as far as `reach` shows it.
    #[must_use]
    pub fn new(organization: OrganizationId, reach: LogReach) -> Self {
        Self {
            organization,
            reach,
        }
    }

    /// The organization whose log it is.
    #[must_use]
    pub fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    /// Which tenants' records it shows.
    #[must_use]
    pub fn reach(&self) -> &LogReach {
        &self.reach
    }
}

/// Proof that someone may export an audit log and download the file.
///
/// Only the authorities make one: `TenantAuthority` for its tenant's log,
/// `OrgControl` for its organization's, `OperatorAuthority` for the
/// platform's. Sam may view the audit log but not export it; without it, he
/// asks for an export and downloads every record of his tenant at once.
#[derive(Debug, Clone)]
pub struct AuditLogAccess {
    log: AuditLogOf,
    by: ActorRef,
    reach: LogReach,
}

impl AuditLogAccess {
    /// `by` may export `log`, as its authority checked.
    pub(crate) fn granted(log: AuditLogOf, by: ActorRef) -> Self {
        Self {
            log,
            by,
            reach: LogReach::Every,
        }
    }

    /// This access, shown only what `reach` shows.
    #[must_use]
    pub(crate) fn within(self, reach: LogReach) -> Self {
        Self { reach, ..self }
    }

    /// The log they may export.
    #[must_use]
    pub fn log(&self) -> AuditLogOf {
        self.log
    }

    /// Who may export it.
    #[must_use]
    pub fn by(&self) -> &ActorRef {
        &self.by
    }

    /// Which tenants' records they are shown of it.
    #[must_use]
    pub fn reach(&self) -> &LogReach {
        &self.reach
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader may be handed a file only when they would be shown all of
    /// it: an owner any file, Max a file of his tenant, and neither Max a
    /// file of every tenant's nor Vic, who reaches none, a file of his.
    #[test]
    fn a_reach_covers_only_what_it_shows_in_full() {
        let tenant = TenantId::new();
        let max = LogReach::Tenants(vec![tenant]);
        let vic = LogReach::Tenants(Vec::new());

        assert!(LogReach::Every.covers(&max));
        assert!(max.covers(&max));
        assert!(max.covers(&vic));
        assert!(!max.covers(&LogReach::Every));
        assert!(!vic.covers(&max));
    }
}
