//! Rules that run before a change happens in the company, and decide it.
//!
//! Ann wants no one made an admin on a weekend. Her workflow starts before
//! an admin role is given, checks the day, and ends in Allow or Refuse.
//! The change waits for that answer; a refusal, or no answer in time,
//! stops it. A rule decides only the change it guards: it acts as nobody,
//! and the change itself is still checked as before.

use crate::message;
use crate::shared::errors::DomainError;

/// A change a workflow may decide before it happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum GuardedChange {
    /// Someone added to a group, so given what the group holds.
    AccessGiven,
    /// A role holding an admin right given to someone.
    AdminGiven,
    /// An app opened to workflows, so their runs may call it as the run's
    /// person.
    AppOpenedToWorkflows,
    /// An export of the audit trail asked for: the company's records
    /// leaving it.
    AuditExported,
}

impl GuardedChange {
    /// Every guarded change.
    pub const ALL: [Self; 4] = [
        Self::AccessGiven,
        Self::AdminGiven,
        Self::AppOpenedToWorkflows,
        Self::AuditExported,
    ];

    /// The change's stable name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessGiven => "access_given",
            Self::AdminGiven => "admin_given",
            Self::AppOpenedToWorkflows => "app_opened_to_workflows",
            Self::AuditExported => "audit_exported",
        }
    }

    /// The change `name` names.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for a name no guarded change has.
    pub fn named(name: &str) -> Result<Self, DomainError> {
        Self::ALL
            .into_iter()
            .find(|change| change.as_str() == name)
            .ok_or_else(|| {
                DomainError::invalid(message!(
                    "workflows-no-such-guarded-change",
                    "a workflow may run before access is given, an admin is made, an app is opened to workflows or the audit trail is exported"
                ))
            })
    }
}

/// What a rule decided about the change it guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The change may happen.
    Allow,
    /// The change is stopped.
    Refuse,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each guarded change is found again by its name, and a name no change
    /// has is refused.
    #[test]
    fn a_guarded_change_is_named() {
        for change in GuardedChange::ALL {
            assert_eq!(GuardedChange::named(change.as_str()).unwrap(), change);
        }
        assert!(GuardedChange::named("delete_company").is_err());
    }
}
