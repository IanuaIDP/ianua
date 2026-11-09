//! Opening an account from another system's records.

use crate::domains::identity::account::address::AccountAddress;
use crate::domains::identity::account::creator::{AccountCreator, AccountOpening};
use crate::domains::identity::account::import::AccountImport;
use crate::domains::identity::account::user::User;
use crate::domains::identity::account::user_profile::UserProfile;
use crate::domains::identity::account::user_status::UserStatus;
use crate::domains::identity::events::profile::UserImported;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::UserId;

impl<T: TenantScope> User<T> {
    /// Opens an account from another system's record of it, as `creator`
    /// allows importing. Raises `identity.user_imported`.
    ///
    /// The account waits on its address, as a registered one does, with
    /// the details and directory records the other system kept. Its
    /// address starts unverified whatever that system said: only a link
    /// followed, an invitation accepted or a provider trusted for the
    /// address proves it here. The caller hands the password hash the
    /// record brought to the credential store.
    ///
    /// Sam may only view users. Without the check, he imports an account
    /// for a mailbox of his own, with a password hash he made, and signs in
    /// once its default roles fill it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `creator` may not import accounts.
    ///   See [`AccountCreator`].
    /// - [`DomainError::Validation`] when the records name the account as
    ///   its own manager.
    pub fn import(
        id: UserId,
        import: AccountImport,
        creator: &impl AccountCreator<T>,
    ) -> Result<Self, DomainError> {
        creator.ensure_may_open(AccountOpening::Import)?;
        if import.records.names_as_own_manager(&id) {
            return Err(DomainError::invalid(message!(
                "identity-a-person-is-never-their-own",
                "a person is never their own manager"
            )));
        }
        let mut user = Self::opened(
            id,
            AccountAddress::unverified(import.email),
            import.display_name,
            UserStatus::PendingVerification,
        );
        user.profile = UserProfile {
            details: import.details,
            records: import.records,
        };
        user.raised.raise(UserImported {
            email: user.email().clone(),
            occurred_at: user.created_at,
        });
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::granter::HeldByGranter;
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::identity::account::profile_values::Department;
    use crate::domains::identity::account::user_profile::{DirectoryRecords, PersonalDetails};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::DisplayNameLimits;
    use crate::test_support::authority::user_adder;
    use crate::test_support::events::raised_names;
    use crate::types::{DisplayName, Email, Setting};

    fn ann_from_the_export() -> AccountImport {
        AccountImport {
            email: Email::new("ann@acme.com").unwrap(),
            display_name: DisplayName::new("Ann", &DisplayNameLimits::default()).unwrap(),
            details: PersonalDetails::default(),
            records: DirectoryRecords {
                department: Setting::Set(Department::new("Finance").unwrap()),
                ..DirectoryRecords::default()
            },
        }
    }

    /// Ann's account comes over from the old provider. It waits on her
    /// address, which is unverified, keeps her department and records
    /// the import.
    #[test]
    fn an_imported_account_waits_on_its_address() {
        let mut account =
            User::<ResolvedTenant>::import(UserId::new(), ann_from_the_export(), &user_adder())
                .unwrap();

        assert_eq!(account.status(), UserStatus::PendingVerification);
        assert!(!account.email_verified());
        assert_eq!(
            account.profile().records.department,
            Setting::Set(Department::new("Finance").unwrap())
        );
        assert_eq!(raised_names(&mut account), ["identity.user_imported"]);
    }

    /// User-view authority cannot open an account from imported records.
    #[test]
    fn someone_who_may_only_view_users_cannot_import() {
        let sam = HeldByGranter::assumed(&[SystemPermission::Users(UserAction::View)], &[]);

        let refused = User::<ResolvedTenant>::import(UserId::new(), ann_from_the_export(), &sam);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Imported records naming the account as its own manager are refused
    /// as invalid.
    #[test]
    fn an_import_naming_the_account_its_own_manager_is_refused() {
        let id = UserId::new();
        let mut import = ann_from_the_export();
        import.records.manager = Setting::Set(id);

        let refused = User::<ResolvedTenant>::import(id, import, &user_adder());

        assert!(matches!(refused, Err(DomainError::Validation(_))));
    }
}
