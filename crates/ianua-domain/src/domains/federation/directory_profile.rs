//! The tenant's directory keeps people's accounts, names, languages,
//! timezones and teams.
//!
//! Okta or an HR system is where a person is hired, a name is changed when
//! someone marries, or a team is reshaped, and SCIM carries that change
//! here. Nobody is signed in when it arrives, so the switched-on SCIM
//! endpoint is what may make it. A profile hands out nothing: the address,
//! which can take an account over, goes through its own proof, and SCIM
//! addresses stay unverified. An account it opens waits on its address, and
//! the groups it keeps bring only the roles a person gave them.

use crate::domains::authorization::directory::TenantDirectory;
use crate::domains::federation::scim::ScimEndpoint;
use crate::domains::identity::account::control::ProfileEditor;
use crate::domains::identity::account::creator::{AccountCreator, AccountOpening};
use crate::domains::identity::sealed::Sealed;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::UserId;

impl<T: TenantScope> Sealed for ScimEndpoint<T> {}

impl<T: TenantScope> ProfileEditor<T> for ScimEndpoint<T> {
    fn ensure_may_edit(&self, _account: &UserId) -> Result<(), DomainError> {
        ensure_switched_on(self)
    }
}

/// The directory registers the people it adds. It invites nobody: an
/// invitation is a person asking someone in.
impl<T: TenantScope> AccountCreator<T> for ScimEndpoint<T> {
    fn ensure_may_open(&self, opening: AccountOpening) -> Result<(), DomainError> {
        match opening {
            AccountOpening::Registration => ensure_switched_on(self),
            AccountOpening::Invitation | AccountOpening::Import => {
                Err(DomainError::forbidden(message!(
                    "federation-the-directory-registers-the-people-it",
                    "the directory registers the people it adds; it invites and imports nobody"
                )))
            }
        }
    }
}

impl<T: TenantScope> TenantDirectory<T> for ScimEndpoint<T> {
    fn ensure_speaks(&self) -> Result<(), DomainError> {
        ensure_switched_on(self)
    }
}

/// Refuses an endpoint the tenant switched off.
fn ensure_switched_on<T: TenantScope>(endpoint: &ScimEndpoint<T>) -> Result<(), DomainError> {
    if !endpoint.enabled() {
        return Err(DomainError::forbidden(message!(
            "federation-scim-is-switched-off-so-the-2",
            "SCIM is switched off, so the directory speaks for nobody"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::Group;
    use crate::domains::federation::fixtures::{federation_admin, switched_on_directory};
    use crate::domains::identity::account::user::User;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::DisplayNameLimits;
    use crate::test_support::builders::{label, user};
    use crate::types::{DisplayName, Email};

    fn renamed(
        account: &mut User<ResolvedTenant>,
        by: &ScimEndpoint<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let name = DisplayName::new("Ann Smith", &DisplayNameLimits::default()).unwrap();
        account.rename(name, by)
    }

    fn hired(by: &ScimEndpoint<ResolvedTenant>) -> Result<User<ResolvedTenant>, DomainError> {
        User::register(
            UserId::new(),
            Email::new("new.hire@acme.test").unwrap(),
            DisplayName::new("New Hire", &DisplayNameLimits::default()).unwrap(),
            by,
        )
    }

    /// Ann marries and her name changes in Okta. SCIM renames her here.
    /// Once an admin switches SCIM off, the directory renames nobody.
    #[test]
    fn the_switched_on_directory_keeps_names() {
        let mut ann = user(UserId::new(), "ann@acme.test");
        let mut scim = switched_on_directory();

        let while_on = renamed(&mut ann, &scim);
        scim.disable(&federation_admin()).unwrap();
        let while_off = renamed(&mut ann, &scim);

        assert!(while_on.is_ok());
        assert!(matches!(while_off, Err(DomainError::Forbidden(_))));
    }

    /// A directory can register a hire and create a group while SCIM is
    /// enabled. Disabling it forbids both operations.
    #[test]
    fn a_switched_off_directory_adds_nobody_and_makes_no_group() {
        let mut scim = switched_on_directory();
        let hired_while_on = hired(&scim);
        let group_while_on = Group::<ResolvedTenant>::from_directory(label("Synced"), &scim);

        scim.disable(&federation_admin()).unwrap();

        assert!(hired_while_on.is_ok() && group_while_on.is_ok());
        assert!(matches!(hired(&scim), Err(DomainError::Forbidden(_))));
        assert!(matches!(
            Group::<ResolvedTenant>::from_directory(label("Synced"), &scim),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// An enabled SCIM directory is forbidden from inviting Mallory's
    /// account.
    #[test]
    fn the_directory_invites_nobody() {
        let invited = User::<ResolvedTenant>::invite(
            UserId::new(),
            Email::new("mallory@evil.test").unwrap(),
            DisplayName::new("Mallory", &DisplayNameLimits::default()).unwrap(),
            &switched_on_directory(),
        );

        assert!(matches!(invited, Err(DomainError::Forbidden(_))));
    }
}
