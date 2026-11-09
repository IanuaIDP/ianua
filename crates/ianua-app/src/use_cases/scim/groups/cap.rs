//! How many members one write of a directory's group may name.
//!
//! Each member named is checked as a user of the tenant and against its
//! separation of duties before anything is written, all inside the one
//! request. Without a cap, a directory sending a group of a million members
//! holds a request, and a database connection, for as long as that takes.

use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::validation::numeric::{validate_count, validate_range};

use crate::error::AppError;
use crate::use_cases::scim::groups::fields::ScimGroupChange;

/// The most members one SCIM group write may name, across all its changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberCap(u32);

impl MemberCap {
    /// What a deployment that sets none allows.
    pub const DEFAULT: Self = Self(1_000);

    /// A cap of `most` members.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when `most` is zero, which would refuse
    ///   every write that names a member.
    pub fn new(most: u32) -> Result<Self, DomainError> {
        validate_range("scim_group_member_cap", most, 1..=u32::MAX)?;
        Ok(Self(most))
    }

    /// The most members one write may name.
    #[must_use]
    pub fn most(self) -> u32 {
        self.0
    }

    /// Refuses `changes` when together they name more members than this
    /// allows. A member named twice counts twice: the cap bounds what the
    /// request carries.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` holding a count refusal when there are too many.
    pub(super) fn ensure_holds(self, changes: &[ScimGroupChange]) -> Result<(), AppError> {
        let named = changes.iter().map(ScimGroupChange::members_named).sum();
        self.ensure_names(named)
    }

    /// Refuses a write naming `named` members when that is more than this
    /// allows.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` holding a count refusal when there are too many.
    pub(super) fn ensure_names(self, named: usize) -> Result<(), AppError> {
        let most = usize::try_from(self.0).unwrap_or(usize::MAX);
        validate_count("members", named, 0..=most)
            .map_err(|refusal| AppError::from_domain(DomainError::from(refusal)))
    }
}

impl Default for MemberCap {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::UserId;

    use super::*;

    fn users(count: usize) -> Vec<UserId> {
        (0..count).map(|_| UserId::new()).collect()
    }

    /// A deployment that sets no cap allows a thousand members a write.
    #[test]
    fn the_default_cap_is_a_thousand() {
        assert_eq!(MemberCap::default().most(), 1_000);
    }

    /// A cap of nobody would refuse every write naming a member. It is
    /// refused as a setting.
    #[test]
    fn a_cap_of_zero_is_refused() {
        assert!(matches!(MemberCap::new(0), Err(DomainError::Validation(_))));
    }

    /// Okta adds two people and removes one under a cap of three. The write
    /// names three, which the cap allows.
    #[test]
    fn changes_naming_as_many_as_the_cap_pass() {
        let cap = MemberCap::new(3).unwrap();
        let changes = [
            ScimGroupChange::AddMembers(users(2)),
            ScimGroupChange::RemoveMembers(users(1)),
        ];

        assert!(cap.ensure_holds(&changes).is_ok());
    }

    /// Adding three members and removing one exceeds a cap of three because
    /// the cap counts members across all changes together.
    #[test]
    fn members_named_across_changes_count_together() {
        let cap = MemberCap::new(3).unwrap();
        let changes = [
            ScimGroupChange::AddMembers(users(3)),
            ScimGroupChange::RemoveMembers(users(1)),
        ];

        assert!(matches!(
            cap.ensure_holds(&changes),
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }
}
