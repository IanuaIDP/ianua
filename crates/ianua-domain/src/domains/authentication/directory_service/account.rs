//! The account an application such as Jira, GitLab or SSSD binds to the
//! tenant's LDAP directory as, instead of borrowing a person's password.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::directory_service::bind::ServiceAccountBind;
use crate::domains::authentication::directory_service::control::DirectoryControlCheck;
use crate::domains::authentication::directory_service::scope::{
    ServiceAccountName, ServiceAccountScope,
};
use crate::domains::authentication::events::service_account::{
    DirectoryServiceAccountCreated, DirectoryServiceAccountDeleted,
    DirectoryServiceAccountScopeChanged, DirectoryServiceAccountSecretRotated,
    DirectoryServiceAccountStatusChanged,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{DirectoryServiceAccountId, EventLabel, TokenHash};

/// Whether a service account may bind.
///
/// Valid transitions:
/// - `Active` → `Disabled`, when an admin switches it off.
/// - `Disabled` → `Active`, when an admin switches it on again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ServiceAccountStatus {
    /// It binds.
    Active,
    /// It binds no more, and binds made before stop counting.
    Disabled,
}

/// Rejected service account status transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot move a service account from {from:?} to {to:?}")]
pub struct InvalidServiceAccountTransition {
    /// The current state.
    pub from: ServiceAccountStatus,
    /// The attempted target state.
    pub to: ServiceAccountStatus,
}

impl ServiceAccountStatus {
    /// Moves to `to` when the transition is allowed.
    ///
    /// # Errors
    ///
    /// - [`InvalidServiceAccountTransition`] when it is not.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidServiceAccountTransition> {
        match (self, to) {
            (Self::Active, Self::Disabled) | (Self::Disabled, Self::Active) => Ok(to),
            (Self::Active, Self::Active) | (Self::Disabled, Self::Disabled) => {
                Err(InvalidServiceAccountTransition { from: self, to })
            }
        }
    }

    /// The stable name records carry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

crate::shared::model::transition::refusal_is_a_domain_error!(InvalidServiceAccountTransition);

/// An account an application binds to the directory as.
///
/// It holds no person: what it may do comes from its
/// [`ServiceAccountScope`], not from roles. Only the hash of its secret is
/// kept; the secret is shown once, when it is made or replaced.
///
/// It belongs to one tenant. It is read and written only through stores
/// opened for the resolved tenant. See [`crate::isolation`].
#[derive(Debug)]
pub struct DirectoryServiceAccount<T: TenantScope> {
    id: DirectoryServiceAccountId,
    name: ServiceAccountName,
    secret_hash: TokenHash,
    scope: ServiceAccountScope,
    status: ServiceAccountStatus,
    created_at: OffsetDateTime,
    secret_changed_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// A service account about to be made.
pub struct NewServiceAccount {
    /// The name it binds with, unique within the tenant.
    pub name: ServiceAccountName,
    /// One-way hash of its secret.
    pub secret_hash: TokenHash,
    /// What it may do, and where.
    pub scope: ServiceAccountScope,
}

/// Persisted state for repository hydration.
pub struct DirectoryServiceAccountRow {
    /// The persisted identity used to bind grants and audit records to this service account.
    pub id: DirectoryServiceAccountId,
    /// The name it binds with.
    pub name: ServiceAccountName,
    /// One-way hash of its secret.
    pub secret_hash: TokenHash,
    /// What it may do, and where.
    pub scope: ServiceAccountScope,
    /// Whether it may bind.
    pub status: ServiceAccountStatus,
    /// When it was made.
    pub created_at: OffsetDateTime,
    /// When its secret was last set.
    pub secret_changed_at: OffsetDateTime,
}

impl<T: TenantScope> DirectoryServiceAccount<T> {
    /// Makes an active service account, as `by` decides.
    ///
    /// Raises `authentication.directory_service_account_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not hand out the access
    ///   `new.scope` gives. See [`DirectoryControlCheck`].
    pub fn create(
        new: NewServiceAccount,
        by: &impl DirectoryControlCheck,
    ) -> Result<Self, DomainError> {
        by.ensure_may_grant(new.scope.access())?;
        let now = crate::shared::clock::now();
        let mut account = Self {
            id: DirectoryServiceAccountId::new(),
            name: new.name,
            secret_hash: new.secret_hash,
            scope: new.scope,
            status: ServiceAccountStatus::Active,
            created_at: now,
            secret_changed_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        account.raised.raise(DirectoryServiceAccountCreated {
            account_id: account.id,
            name: account.label(),
            access: account.scope.access(),
            occurred_at: now,
        });
        Ok(account)
    }

    /// Rebuilds a service account from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row's secret was set
    ///   before the account was made.
    pub fn reconstitute(row: DirectoryServiceAccountRow) -> Result<Self, DomainError> {
        RowCheck::of("directory service account")
            .holds(
                row.created_at <= row.secret_changed_at,
                "secret set before the account was made",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            name: row.name,
            secret_hash: row.secret_hash,
            scope: row.scope,
            status: row.status,
            created_at: row.created_at,
            secret_changed_at: row.secret_changed_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The stable identity used to bind grants and audit records to this service account.
    #[must_use]
    pub fn id(&self) -> &DirectoryServiceAccountId {
        &self.id
    }

    /// The name it binds with.
    #[must_use]
    pub fn name(&self) -> &ServiceAccountName {
        &self.name
    }

    /// One-way hash of its secret.
    #[must_use]
    pub fn secret_hash(&self) -> &TokenHash {
        &self.secret_hash
    }

    /// What it may do, and where.
    #[must_use]
    pub fn scope(&self) -> &ServiceAccountScope {
        &self.scope
    }

    /// Whether it may bind.
    #[must_use]
    pub fn status(&self) -> ServiceAccountStatus {
        self.status
    }

    /// When it was made.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When its secret was last set.
    #[must_use]
    pub fn secret_changed_at(&self) -> OffsetDateTime {
        self.secret_changed_at
    }

    /// Replaces its secret with the one hashing to `secret_hash`, as `by`
    /// decides. Every bind made with the old one stops counting.
    ///
    /// Jira's configuration file leaked. Without rotation, the only way to
    /// shut the leaked secret out is to delete the account and set Jira up
    /// again.
    ///
    /// Raises `authentication.directory_service_account_secret_rotated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not hand out the access
    ///   this account has.
    pub fn rotate_secret(
        &mut self,
        secret_hash: TokenHash,
        by: &impl DirectoryControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_grant(self.scope.access())?;
        self.secret_hash = secret_hash;
        self.secret_changed_at = crate::shared::clock::now();
        self.raised.raise(DirectoryServiceAccountSecretRotated {
            account_id: self.id,
            name: self.label(),
            occurred_at: self.secret_changed_at,
        });
        Ok(())
    }

    /// Replaces what it may do, and where, with `scope`, as `by` decides.
    ///
    /// `by` must be able to hand out the access it gets.
    ///
    /// Raises `authentication.directory_service_account_scope_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not hand out the access.
    pub fn change_scope(
        &mut self,
        scope: ServiceAccountScope,
        by: &impl DirectoryControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_grant(scope.access())?;
        self.scope = scope;
        self.raised.raise(DirectoryServiceAccountScopeChanged {
            account_id: self.id,
            name: self.label(),
            access: self.scope.access(),
            base_dns: self.scope.base_dns().len(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Switches it off, as `by` decides. It binds no more, and every bind
    /// made before stops counting.
    ///
    /// Raises `authentication.directory_service_account_status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not hand out the access
    ///   this account has.
    /// - [`DomainError::InvalidTransition`] when it is off already.
    pub fn disable(&mut self, by: &impl DirectoryControlCheck) -> Result<(), DomainError> {
        self.move_to(ServiceAccountStatus::Disabled, by)
    }

    /// Switches it on again, as `by` decides.
    ///
    /// Raises `authentication.directory_service_account_status_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not hand out the access
    ///   this account has.
    /// - [`DomainError::InvalidTransition`] when it is on already.
    pub fn enable(&mut self, by: &impl DirectoryControlCheck) -> Result<(), DomainError> {
        self.move_to(ServiceAccountStatus::Active, by)
    }

    /// Deletes it, as `by` decides. Once it is removed from storage it binds
    /// no more, and every connection bound as it reads nothing more at its
    /// next request.
    ///
    /// Jira is retired. Without this, its account lingers switched off,
    /// one switch away from binding again with a secret still sitting in an
    /// old configuration file.
    ///
    /// Raises `authentication.directory_service_account_deleted`, taken once
    /// the account is removed from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not hand out the access
    ///   this account has.
    pub fn delete(&mut self, by: &impl DirectoryControlCheck) -> Result<(), DomainError> {
        by.ensure_may_grant(self.scope.access())?;
        self.raised.raise(DirectoryServiceAccountDeleted {
            account_id: self.id,
            name: self.label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// The bind made with the secret hashing to `presented`.
    ///
    /// The hashes are compared in constant time, as every `TokenHash` is.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the account is switched off, or
    ///   `presented` is not its secret.
    pub fn bind(&self, presented: &TokenHash) -> Result<ServiceAccountBind<T>, DomainError> {
        if self.status != ServiceAccountStatus::Active {
            return Err(DomainError::forbidden(message!(
                "authentication-this-service-account-is-switched-off",
                "this service account is switched off"
            )));
        }
        if *presented != self.secret_hash {
            return Err(DomainError::forbidden(message!(
                "authentication-the-service-account-s-secret-is",
                "the service account's secret is wrong"
            )));
        }
        Ok(ServiceAccountBind::made(self))
    }

    /// Moves to `to`, as `by` decides, and raises the move.
    fn move_to(
        &mut self,
        to: ServiceAccountStatus,
        by: &impl DirectoryControlCheck,
    ) -> Result<(), DomainError> {
        by.ensure_may_grant(self.scope.access())?;
        self.status = self.status.try_transition(to)?;
        self.raised.raise(DirectoryServiceAccountStatusChanged {
            account_id: self.id,
            name: self.label(),
            status: self.status,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// How a record names it.
    fn label(&self) -> EventLabel {
        EventLabel::of(self.name.as_str())
    }
}

impl<T: TenantScope> Raises for DirectoryServiceAccount<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::domains::authentication::directory_service::scope::{BaseDn, DirectoryAccess};
    use crate::domains::identity::sealed::Sealed;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};

    /// Someone who may hand out directory access.
    pub(crate) struct Grants;

    impl Sealed for Grants {}

    impl DirectoryControlCheck for Grants {
        fn ensure_may_grant(&self, _access: DirectoryAccess) -> Result<(), DomainError> {
            Ok(())
        }
    }

    /// Someone who may not hand out directory access.
    struct Refuses;

    impl Sealed for Refuses {}

    impl DirectoryControlCheck for Refuses {
        fn ensure_may_grant(&self, _access: DirectoryAccess) -> Result<(), DomainError> {
            Err(DomainError::forbidden("may not hand out this access"))
        }
    }

    pub(crate) fn scope(access: DirectoryAccess) -> ServiceAccountScope {
        ServiceAccountScope::new(access, vec![BaseDn::new("dc=acme,dc=com").unwrap()]).unwrap()
    }

    pub(crate) fn secret(value: &str) -> TokenHash {
        TokenHash::from_stored(value.to_owned())
    }

    /// Jira's read-only account.
    pub(crate) fn jira() -> DirectoryServiceAccount<ResolvedTenant> {
        DirectoryServiceAccount::create(
            NewServiceAccount {
                name: ServiceAccountName::new("jira").unwrap(),
                secret_hash: secret("jira-secret"),
                scope: scope(DirectoryAccess::ReadOnly),
            },
            &Grants,
        )
        .unwrap()
    }

    /// An admin makes Jira's account. It is active, binds with its secret,
    /// and its making is recorded with its access.
    #[test]
    fn a_new_service_account_is_active_and_recorded() {
        let mut account = jira();

        let events = raised(&mut account);

        assert_eq!(account.status(), ServiceAccountStatus::Active);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.directory_service_account_created"
        );
        assert_eq!(events[0].payload().get("access"), Some("read_only"));
    }

    /// Someone who may not hand out directory access makes no account.
    #[test]
    fn a_maker_without_the_right_is_refused() {
        let refused = DirectoryServiceAccount::<ResolvedTenant>::create(
            NewServiceAccount {
                name: ServiceAccountName::new("sync").unwrap(),
                secret_hash: secret("s"),
                scope: scope(DirectoryAccess::ReadOnly),
            },
            &Refuses,
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Someone without the right cannot change Jira's scope, rotate its
    /// secret, or switch it off or on; its secret still admits a bind.
    #[test]
    fn an_account_is_changed_only_by_someone_with_the_right() {
        let mut account = jira();
        let wider = ServiceAccountScope::new(
            DirectoryAccess::ReadOnly,
            vec![BaseDn::new("dc=other,dc=com").unwrap()],
        )
        .unwrap();

        assert!(matches!(
            account.change_scope(wider, &Refuses),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            account.rotate_secret(secret("sams"), &Refuses),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            account.disable(&Refuses),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            account.enable(&Refuses),
            Err(DomainError::Forbidden(_))
        ));
        assert_eq!(account.scope().base_dns()[0].as_str(), "dc=acme,dc=com");
        assert!(account.bind(&secret("jira-secret")).is_ok());
    }

    /// Jira binds with its secret. A wrong secret binds nothing.
    #[test]
    fn a_service_account_binds_only_with_its_secret() {
        let account = jira();

        assert!(account.bind(&secret("jira-secret")).is_ok());
        assert!(matches!(
            account.bind(&secret("guess")),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A disabled directory account refuses a bind with its secret.
    #[test]
    fn a_switched_off_account_binds_nothing() {
        let mut account = jira();
        account.disable(&Grants).unwrap();

        assert!(account.bind(&secret("jira-secret")).is_err());
    }

    /// An account switched off and on again binds, and both moves are
    /// recorded. Switching it off twice is refused.
    #[test]
    fn a_service_account_is_switched_off_and_on() {
        let mut account = jira();
        let by = Grants;
        raised_names(&mut account);

        account.disable(&by).unwrap();
        let twice = account.disable(&by);
        account.enable(&by).unwrap();

        assert!(matches!(twice, Err(DomainError::InvalidTransition(_))));
        assert!(account.bind(&secret("jira-secret")).is_ok());
        let events = raised(&mut account);
        assert_eq!(events[0].payload().get("status"), Some("disabled"));
        assert_eq!(events[1].payload().get("status"), Some("active"));
    }

    /// Jira's configuration leaked. The admin rotates its secret: the old
    /// one binds nothing, the new one binds.
    #[test]
    fn a_rotated_secret_replaces_the_old_one() {
        let mut account = jira();

        account.rotate_secret(secret("new"), &Grants).unwrap();

        assert!(account.bind(&secret("jira-secret")).is_err());
        assert!(account.bind(&secret("new")).is_ok());
    }

    /// Jira is retired. Ann deletes its account, and the deletion is
    /// recorded naming it.
    #[test]
    fn a_deleted_account_is_recorded() {
        let mut account = jira();
        raised_names(&mut account);

        account.delete(&Grants).unwrap();

        let events = raised(&mut account);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.directory_service_account_deleted"
        );
    }

    /// Someone without the right cannot delete Jira's account, and the
    /// refusal raises no event.
    #[test]
    fn an_account_is_deleted_only_by_someone_with_the_right() {
        let mut account = jira();
        raised_names(&mut account);

        let refused = account.delete(&Refuses);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(raised_names(&mut account).is_empty());
    }

    /// A stored account whose secret was set before it was made is refused
    /// as corrupt.
    #[test]
    fn a_stored_account_with_its_secret_set_before_it_was_made_is_refused() {
        let now = crate::shared::clock::now();

        let stored =
            DirectoryServiceAccount::<ResolvedTenant>::reconstitute(DirectoryServiceAccountRow {
                id: DirectoryServiceAccountId::new(),
                name: ServiceAccountName::new("jira").unwrap(),
                secret_hash: secret("s"),
                scope: scope(DirectoryAccess::ReadOnly),
                status: ServiceAccountStatus::Active,
                created_at: now,
                secret_changed_at: now - time::Duration::SECOND,
            });

        assert!(refused_as_corrupt(&stored));
    }
}
