//! What a person holds, answering the rules of the contexts below
//! authorization: signing keys, classification rules, signal streams and
//! directory service accounts.
//!
//! Those contexts cannot read permissions, which live here. Each names the
//! rule a change must pass, and a [`TenantAuthority`](crate::domains::authorization::authority::TenantAuthority) answers it from what
//! the person holds now.

use crate::domains::authentication::directory_service::control::DirectoryControlCheck;
use crate::domains::authentication::directory_service::scope::DirectoryAccess;
use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::permission::{
    AuthConfigAction, ClassificationAction, CryptoAction, SignalsAction, SystemPermission,
    UserAction,
};
use crate::domains::crypto::control::CryptoControlCheck;
use crate::domains::data_classification::control::ClassificationControlCheck;
use crate::domains::signals::control::SignalsControlCheck;
use crate::shared::errors::DomainError;

impl crate::domains::crypto::sealed::Sealed for TenantAuthority {}

impl CryptoControlCheck for TenantAuthority {
    fn ensure_may_change_keys(&self) -> Result<(), DomainError> {
        self.ensure_holds(SystemPermission::Crypto(CryptoAction::Update))
    }
}

impl crate::domains::data_classification::sealed::Sealed for TenantAuthority {}

impl ClassificationControlCheck for TenantAuthority {
    fn ensure_may_change_rules(&self) -> Result<(), DomainError> {
        self.ensure_holds(SystemPermission::Classification(
            ClassificationAction::Update,
        ))
    }
}

/// Handing out directory access needs the right to change sign-in
/// settings, and the right over the users it reaches: viewing them, since
/// a service account only reads.
impl DirectoryControlCheck for TenantAuthority {
    fn ensure_may_grant(&self, access: DirectoryAccess) -> Result<(), DomainError> {
        self.ensure_holds(SystemPermission::AuthConfig(AuthConfigAction::Update))?;
        let over_users = match access {
            DirectoryAccess::ReadOnly => UserAction::View,
        };
        self.ensure_holds(SystemPermission::Users(over_users))
    }
}

impl crate::domains::signals::sealed::Sealed for TenantAuthority {}

impl SignalsControlCheck for TenantAuthority {
    fn ensure_may_change_streams(&self) -> Result<(), DomainError> {
        self.ensure_holds(SystemPermission::Signals(SignalsAction::Update))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authority::anyone_holding;

    /// Fay manages crypto, classification and signals. Each rule lets her
    /// change what it guards, because managing covers updating.
    #[test]
    fn the_full_right_covers_each_change() {
        let fay = anyone_holding(&[
            SystemPermission::ManageCrypto,
            SystemPermission::ManageClassification,
            SystemPermission::ManageSignals,
        ]);

        assert!(fay.ensure_may_change_keys().is_ok());
        assert!(fay.ensure_may_change_rules().is_ok());
        assert!(fay.ensure_may_change_streams().is_ok());
    }

    /// Fay may update sign-in settings and view users. She may hand out
    /// directory access, as may someone who manages users, which covers
    /// viewing them.
    #[test]
    fn directory_access_needs_sign_in_settings_and_the_right_over_users() {
        let viewer = anyone_holding(&[
            SystemPermission::AuthConfig(AuthConfigAction::Update),
            SystemPermission::Users(UserAction::View),
        ]);
        let manager = anyone_holding(&[
            SystemPermission::AuthConfig(AuthConfigAction::Update),
            SystemPermission::Users(UserAction::Manage),
        ]);

        assert!(viewer.ensure_may_grant(DirectoryAccess::ReadOnly).is_ok());
        assert!(manager.ensure_may_grant(DirectoryAccess::ReadOnly).is_ok());
    }

    /// The right over sign-in settings alone cannot grant reads of users,
    /// and the right over users alone cannot without it.
    #[test]
    fn directory_access_needs_both_rights() {
        let sam = anyone_holding(&[SystemPermission::AuthConfig(AuthConfigAction::Update)]);
        let without_settings = anyone_holding(&[SystemPermission::Users(UserAction::Manage)]);

        assert!(matches!(
            sam.ensure_may_grant(DirectoryAccess::ReadOnly),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            without_settings
                .ensure_may_grant(DirectoryAccess::ReadOnly)
                .is_err()
        );
    }

    /// Managing signal streams does not authorize signing-key or classification-rule changes.
    #[test]
    fn one_area_right_changes_nothing_in_another() {
        let sam = anyone_holding(&[SystemPermission::ManageSignals]);

        assert!(matches!(
            sam.ensure_may_change_keys(),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            sam.ensure_may_change_rules(),
            Err(DomainError::Forbidden(_))
        ));
    }
}
