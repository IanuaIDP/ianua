//! Versions of a tenant's policy.
//!
//! A tenant keeps one live policy and at most one draft beside it. The live
//! policy keeps deciding requests while the draft is written and reviewed.
//! Approving the draft makes it live, and the policy it replaces becomes a
//! past version. Every version keeps its number, so a decision names the
//! version that made it, an admin compares two versions rule by rule, and a
//! past version can be brought back as a new draft.

use std::fmt;
use std::num::NonZeroU32;

use crate::domains::authorization::policy::action::PolicyAction;
use crate::domains::authorization::policy::set::PolicySet;
use crate::domains::authorization::policy::status::PolicyStatus;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::ValidationError;
use crate::shared::validation::distinct::first_repeat;

/// The number of one version of a tenant's policy, counting from 1.
///
/// Numbers only grow. A draft takes the number after the highest the
/// tenant has used, so a restored version is a new number, never the old
/// one again, and a decision record naming version 7 always means one set
/// of rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PolicyVersion(NonZeroU32);

impl PolicyVersion {
    /// The first version a tenant writes.
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    /// Reads a version number a caller sent, such as one in a URL.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::OutOfRange`] for 0, which no version has.
    pub fn parse(number: u32) -> Result<Self, ValidationError> {
        NonZeroU32::new(number)
            .map(Self)
            .ok_or(ValidationError::OutOfRange {
                field: "policy_version",
                min: 1,
                max: u64::from(u32::MAX),
                actual: 0,
            })
    }

    /// Reads a stored version number.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for 0. Only a corrupt row holds it.
    pub fn from_stored(number: u32) -> Result<Self, DomainError> {
        NonZeroU32::new(number)
            .map(Self)
            .ok_or_else(|| DomainError::corrupt_row("policy version", "version 0"))
    }

    /// The positive sequence used to order revisions of one policy.
    #[must_use]
    pub fn number(self) -> u32 {
        self.0.get()
    }

    /// The version after this one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when this is the last number there is.
    pub fn next(self) -> Result<Self, DomainError> {
        self.0.checked_add(1).map(Self).ok_or_else(|| {
            DomainError::conflict(message!(
                "authorization-the-policy-has-run-out-of",
                "the policy has run out of version numbers"
            ))
        })
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// What a version of the policy was started from.
///
/// A comparison reads it to offer the obvious pair: a draft against the
/// version it copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VersionBase {
    /// Empty, with only a fallback action.
    Blank,
    /// A copy of the version that was live when it was started.
    CopyOf(PolicyVersion),
    /// A copy of a past version, brought back.
    RestoredFrom(PolicyVersion),
}

impl VersionBase {
    /// The name the audit trail records for how the version started.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blank => "blank",
            Self::CopyOf(_) => "copy",
            Self::RestoredFrom(_) => "restore",
        }
    }

    /// The version it copied, when it copied one.
    #[must_use]
    pub fn source(self) -> Option<PolicyVersion> {
        match self {
            Self::Blank => None,
            Self::CopyOf(version) | Self::RestoredFrom(version) => Some(version),
        }
    }

    /// Whether it copied a version older than `version`, or nothing. A
    /// version never starts from itself or from one written after it.
    pub(crate) fn comes_before(self, version: PolicyVersion) -> bool {
        self.source().is_none_or(|source| source < version)
    }
}

/// Where a new draft of a tenant's policy starts.
#[derive(Debug, Clone)]
pub enum DraftStart {
    /// Empty, with this fallback for requests no rule matches.
    Blank(PolicyAction),
    /// As a copy of the live version: the usual way to change the policy.
    FromLive,
    /// As a copy of this past version, to bring it back.
    Restore(PolicyVersion),
}

/// The version a draft replaces when it is approved.
#[derive(Debug)]
pub enum Replacing<'a> {
    /// Nothing is live in the tenant.
    NothingLive,
    /// This version is live. It stops deciding requests and becomes a past
    /// version.
    Live(&'a mut PolicySet),
}

/// What a new draft is copied from, once the history has said it may be.
pub(crate) enum StartingPoint<'a> {
    /// Nothing: an empty draft with this fallback.
    Blank(PolicyAction),
    /// This version, recorded as `base`.
    Copy(&'a PolicySet, VersionBase),
}

/// Every version of one tenant's policy, as the store holds them, read
/// together.
///
/// The live version and the open draft are found here, never named by the
/// caller. Sam opens a second draft while Ann's is in review, or a use case
/// passes only the live version: either way the tenant would end up with
/// two drafts racing to replace one policy.
#[derive(Debug, Clone, Copy)]
pub struct PolicyHistory<'a> {
    versions: &'a [PolicySet],
}

impl<'a> PolicyHistory<'a> {
    /// The tenant's versions, read whole.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when two versions share a number,
    ///   two are live, or two are open as drafts or in review. Only a
    ///   damaged store holds such versions.
    pub fn of(versions: &'a [PolicySet]) -> Result<Self, DomainError> {
        let live = versions.iter().filter(|v| v.status().is_active()).count();
        let open = versions.iter().filter(|v| v.status().is_open()).count();
        RowCheck::of("policy history")
            .holds(
                first_repeat(versions.iter().map(PolicySet::version)).is_none(),
                "two versions with one number",
            )
            .holds(live <= 1, "two live versions")
            .holds(open <= 1, "two open drafts")
            .finish()?;
        Ok(Self { versions })
    }

    /// The version deciding requests now, if any.
    #[must_use]
    pub fn live(&self) -> Option<&'a PolicySet> {
        self.versions.iter().find(|v| v.status().is_active())
    }

    /// The draft being written or reviewed, if any.
    #[must_use]
    pub fn open(&self) -> Option<&'a PolicySet> {
        self.versions.iter().find(|v| v.status().is_open())
    }

    /// The version numbered `number`, if the tenant has one.
    #[must_use]
    pub fn version(&self, number: PolicyVersion) -> Option<&'a PolicySet> {
        self.versions.iter().find(|v| v.version() == number)
    }

    /// The versions that no longer decide anything, newest first.
    #[must_use]
    pub fn past(&self) -> Vec<&'a PolicySet> {
        let mut past: Vec<&PolicySet> = self
            .versions
            .iter()
            .filter(|v| v.status().is_archived())
            .collect();
        past.sort_by_key(|v| std::cmp::Reverse(v.version()));
        past
    }

    /// The number a new draft takes: one past the highest used.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the numbers have run out.
    pub fn next_number(&self) -> Result<PolicyVersion, DomainError> {
        self.versions
            .iter()
            .map(PolicySet::version)
            .max()
            .map_or(Ok(PolicyVersion::FIRST), PolicyVersion::next)
    }

    /// Refuses a new draft while one is open.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] naming the open draft's version and
    ///   status.
    pub(crate) fn ensure_no_open_draft(&self) -> Result<(), DomainError> {
        let Some(open) = self.open() else {
            return Ok(());
        };
        Err(DomainError::conflict(message!(
            "authorization-version-is-edit-it-or-abandon",
            format!(
                "version {} is {}; edit it, or abandon it first",
                open.version(),
                open.status()
            )
        )))
    }

    /// What `start` copies from.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NotFound`] when copying the live version and none is
    ///   live, or restoring a version the tenant does not have.
    /// - [`DomainError::Conflict`] when restoring a version that is live or
    ///   open: it is in use already.
    pub(crate) fn starting_point(
        &self,
        start: DraftStart,
    ) -> Result<StartingPoint<'a>, DomainError> {
        match start {
            DraftStart::Blank(action) => Ok(StartingPoint::Blank(action)),
            DraftStart::FromLive => {
                let live = self.live().ok_or(DomainError::NotFound)?;
                Ok(StartingPoint::Copy(
                    live,
                    VersionBase::CopyOf(live.version()),
                ))
            }
            DraftStart::Restore(number) => {
                let past = self.version(number).ok_or(DomainError::NotFound)?;
                ensure_past(past)?;
                Ok(StartingPoint::Copy(past, VersionBase::RestoredFrom(number)))
            }
        }
    }
}

/// Refuses restoring a version that is still in use.
fn ensure_past(version: &PolicySet) -> Result<(), DomainError> {
    if version.status() == PolicyStatus::Archived {
        return Ok(());
    }
    Err(DomainError::conflict(message!(
        "authorization-version-is-only-a-past-version",
        format!(
            "version {} is {}; only a past version is restored",
            version.version(),
            version.status()
        )
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Version 0 is refused, from a caller and from storage. Version 1 is
    /// the first, and the next after it is 2.
    #[test]
    fn versions_count_from_one() {
        assert!(PolicyVersion::parse(0).is_err());
        assert!(PolicyVersion::from_stored(0).is_err());
        assert_eq!(PolicyVersion::parse(1).unwrap(), PolicyVersion::FIRST);
        assert_eq!(PolicyVersion::FIRST.next().unwrap().number(), 2);
    }

    /// The last number there is has no next one. The draft is refused
    /// rather than wrapping round to reuse version 1.
    #[test]
    fn the_last_version_number_has_no_next() {
        let last = PolicyVersion::parse(u32::MAX).unwrap();

        assert!(matches!(last.next(), Err(DomainError::Conflict(_))));
    }

    /// A draft copied from version 3 and numbered 4 started before itself.
    /// One numbered 3 that claims to copy version 3 did not.
    #[test]
    fn a_version_starts_only_from_an_older_one() {
        let three = PolicyVersion::parse(3).unwrap();
        let four = PolicyVersion::parse(4).unwrap();

        assert!(VersionBase::CopyOf(three).comes_before(four));
        assert!(!VersionBase::RestoredFrom(three).comes_before(three));
        assert!(VersionBase::Blank.comes_before(PolicyVersion::FIRST));
    }

    /// Each way a version starts is recorded under a stable name.
    #[test]
    fn each_start_has_a_stable_name() {
        let one = PolicyVersion::FIRST;

        assert_eq!(VersionBase::Blank.as_str(), "blank");
        assert_eq!(VersionBase::CopyOf(one).as_str(), "copy");
        assert_eq!(VersionBase::RestoredFrom(one).as_str(), "restore");
        assert_eq!(VersionBase::RestoredFrom(one).source(), Some(one));
    }
}
