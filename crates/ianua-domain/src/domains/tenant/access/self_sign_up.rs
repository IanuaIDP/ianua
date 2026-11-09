//! A tenant's word that it takes sign-ups from anyone.
//!
//! Most tenants let in only the people an admin adds or invites. One that
//! switched self-registration on lets a stranger open an account of their
//! own, which waits for them to confirm their address. The tenant gives
//! that word here, while it is open, for its own accounts only.

use std::marker::PhantomData;

use crate::domains::identity::account::creator::{AccountCreator, AccountOpening};
use crate::domains::identity::sealed::Sealed;
use crate::domains::tenant::lifecycle::Tenant;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;

/// Proof that tenant `T` takes sign-ups from anyone now.
///
/// Only [`Tenant::admits_self_sign_up`] makes one, and its field is
/// private. So no caller registers an account on its own word that the
/// tenant is open to sign-ups.
#[derive(Debug)]
pub struct SelfSignUp<T: TenantScope> {
    _scope: PhantomData<T>,
}

impl Tenant {
    /// The proof that this tenant, which `scope` stands for, takes sign-ups
    /// from anyone now.
    ///
    /// Mallory finds the sign-up form of a tenant that only invites. Without
    /// this, she opens an account there and the default roles fill it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `scope` stands for another tenant.
    /// - [`DomainError::Forbidden`] when the tenant is suspended, archived or
    ///   deleted.
    /// - [`DomainError::Forbidden`] when its sign-in settings take no
    ///   sign-ups.
    pub fn admits_self_sign_up<T: TenantScope>(
        &self,
        scope: &T,
    ) -> Result<SelfSignUp<T>, DomainError> {
        if scope.tenant_id() != self.id() {
            return Err(DomainError::forbidden(message!(
                "tenant-a-tenant-speaks-only-for-its",
                "a tenant speaks only for its own sign-ups"
            )));
        }
        if !self.status().is_open() {
            return Err(DomainError::forbidden(message!(
                "tenant-the-workspace-is-not-open",
                "the workspace is not open"
            )));
        }
        if !self.auth_config().self_registration() {
            return Err(DomainError::forbidden(message!(
                "tenant-this-workspace-does-not-allow-sign",
                "this workspace does not allow sign-up"
            )));
        }
        Ok(SelfSignUp {
            _scope: PhantomData,
        })
    }
}

impl<T: TenantScope> Sealed for SelfSignUp<T> {}

/// A stranger registers themselves. Nobody is invited this way: an
/// invitation is a person asking someone in.
impl<T: TenantScope> AccountCreator<T> for SelfSignUp<T> {
    fn ensure_may_open(&self, opening: AccountOpening) -> Result<(), DomainError> {
        match opening {
            AccountOpening::Registration => Ok(()),
            AccountOpening::Invitation | AccountOpening::Import => {
                Err(DomainError::forbidden(message!(
                    "tenant-signing-up-opens-only-the-person",
                    "signing up opens only the person's own account"
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::session::tests::signed_in_session;
    use crate::domains::identity::account::import::AccountImport;
    use crate::domains::identity::account::user::User;
    use crate::domains::identity::account::user_profile::{DirectoryRecords, PersonalDetails};
    use crate::domains::tenant::access::auth_config::{
        SelfRegistration, TenantAuthConfig, TenantAuthSettings,
    };
    use crate::domains::tenant::access::sign_in_gate::{SavedFrom, SignInChange};
    use crate::domains::tenant::fixtures::{ADMIN, ProvedJustNow, active, holder_of, holding};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::DisplayNameLimits;
    use crate::types::{ActedBy, DisplayName, Email, TenantId, UserId};

    fn scope_of(tenant: &Tenant) -> ResolvedTenant {
        ResolvedTenant::new(*tenant.id(), tenant.slug().clone())
    }

    /// Acme, whose admin Ann switched self-registration on.
    fn taking_sign_ups() -> Tenant {
        let mut tenant = active();
        let session = signed_in_session();
        let ann = holder_of(&session, "ann@acme.test");
        let open = TenantAuthConfig::new(TenantAuthSettings {
            self_registration: SelfRegistration::Open,
            ..TenantAuthSettings::default()
        })
        .unwrap();
        let change = SignInChange {
            config: open,
            saved_from: SavedFrom::from_session(&session),
        };
        tenant
            .update_auth_config(
                holding(&ann, &tenant, ADMIN),
                &ProvedJustNow::by(&ann),
                change,
            )
            .unwrap();
        tenant
    }

    fn mallory(
        by: &SelfSignUp<ResolvedTenant>,
        opening: AccountOpening,
    ) -> Result<User<ResolvedTenant>, DomainError> {
        let email = Email::new("mallory@evil.test").unwrap();
        let name = DisplayName::new("Mallory", &DisplayNameLimits::default()).unwrap();
        match opening {
            AccountOpening::Registration => User::register(UserId::new(), email, name, by),
            AccountOpening::Invitation => User::invite(UserId::new(), email, name, by),
            AccountOpening::Import => User::import(
                UserId::new(),
                AccountImport {
                    email,
                    display_name: name,
                    details: PersonalDetails::default(),
                    records: DirectoryRecords::default(),
                },
                by,
            ),
        }
    }

    /// A tenant with self-registration disabled refuses to issue sign-up
    /// authority for its own scope.
    #[test]
    fn a_tenant_that_only_invites_takes_no_sign_ups() {
        let acme = active();

        let refused = acme.admits_self_sign_up(&scope_of(&acme));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Acme takes sign-ups. Mallory registers herself and waits on her
    /// address. She may not use the same word to invite someone in, or to
    /// bring accounts over from another system.
    #[test]
    fn a_tenant_taking_sign_ups_lets_a_person_register_only_themselves() {
        let acme = taking_sign_ups();
        let word = acme.admits_self_sign_up(&scope_of(&acme)).unwrap();

        assert!(mallory(&word, AccountOpening::Registration).is_ok());
        for opening in [AccountOpening::Invitation, AccountOpening::Import] {
            assert!(matches!(
                mallory(&word, opening),
                Err(DomainError::Forbidden(_))
            ));
        }
    }

    /// A tenant allowing self-registration cannot issue sign-up authority
    /// for another tenant's scope.
    #[test]
    fn one_tenant_speaks_for_no_other_tenants_sign_ups() {
        let acme = taking_sign_ups();
        let globex = ResolvedTenant::new(TenantId::new(), acme.slug().clone());

        let refused = acme.admits_self_sign_up(&globex);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Suspending a tenant blocks sign-up authority even when its
    /// self-registration setting remains enabled.
    #[test]
    fn a_suspended_tenant_takes_no_sign_ups() {
        let mut acme = taking_sign_ups();
        acme.suspend(ActedBy::Platform).unwrap();

        let refused = acme.admits_self_sign_up(&scope_of(&acme));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }
}
