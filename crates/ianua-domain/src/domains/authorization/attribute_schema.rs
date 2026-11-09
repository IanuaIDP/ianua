//! What a person holds, answering who may change the tenant's custom
//! attributes and how much of them they see.
//!
//! Identity owns the attribute schema and cannot read permissions, which
//! live here. It names the rule, and a [`TenantAuthority`](crate::domains::authorization::authority::TenantAuthority) answers it from
//! what the person holds now.

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::permission::{SystemPermission, UserAction};
use crate::domains::identity::attribute::resolved::AttributeClearance;
use crate::domains::identity::attribute::schema_control::SchemaControlCheck;
use crate::domains::identity::sealed::Sealed;
use crate::shared::errors::DomainError;

impl Sealed for TenantAuthority {}

/// Changing the schema needs the right to update users. Reading sensitive
/// attributes needs the right to manage users, the closest right to "may
/// read what is private about a person".
impl SchemaControlCheck for TenantAuthority {
    fn ensure_may_change_schema(&self) -> Result<(), DomainError> {
        self.ensure_holds(SystemPermission::Users(UserAction::Update))
    }

    fn clearance(&self) -> AttributeClearance {
        if self.holds(SystemPermission::Users(UserAction::Manage)) {
            return AttributeClearance::Sensitive;
        }
        AttributeClearance::Directory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authority::anyone_holding;

    /// Viewing users does not authorize schema changes, while permission to
    /// update users does.
    #[test]
    fn changing_the_schema_needs_the_right_to_update_users() {
        let sam = anyone_holding(&[SystemPermission::Users(UserAction::View)]);
        let editor = anyone_holding(&[SystemPermission::Users(UserAction::Update)]);

        assert!(matches!(
            sam.ensure_may_change_schema(),
            Err(DomainError::Forbidden(_))
        ));
        assert!(editor.ensure_may_change_schema().is_ok());
    }

    /// Someone who may update users sees ordinary attributes only. Someone
    /// who manages users also sees the sensitive ones.
    #[test]
    fn only_managing_users_clears_someone_for_sensitive_attributes() {
        let editor = anyone_holding(&[SystemPermission::Users(UserAction::Update)]);
        let manager = anyone_holding(&[SystemPermission::ManageUsers]);

        assert_eq!(editor.clearance(), AttributeClearance::Directory);
        assert_eq!(manager.clearance(), AttributeClearance::Sensitive);
    }
}
