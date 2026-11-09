//! An application bound to the directory as a service account, and what
//! each of its requests may do.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::directory_service::account::{
    DirectoryServiceAccount, ServiceAccountStatus,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::DirectoryServiceAccountId;

/// A bind as a service account, made with its secret just now.
///
/// Only [`DirectoryServiceAccount::bind`] makes one. It carries no person,
/// so it answers no rule that asks for one: what it may do is its account's
/// scope, read again for every request. LDAP keeps a bind for the whole
/// connection, so a secret rotated or an account switched off after the
/// bind ends what the connection may do at its next request.
#[derive(Debug)]
pub struct ServiceAccountBind<T: TenantScope> {
    account: DirectoryServiceAccountId,
    bound_at: OffsetDateTime,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> ServiceAccountBind<T> {
    /// A bind as `account`, made now. Only its account makes one, once the
    /// secret matched.
    pub(crate) fn made(account: &DirectoryServiceAccount<T>) -> Self {
        Self {
            account: *account.id(),
            bound_at: crate::shared::clock::now(),
            _scope: PhantomData,
        }
    }

    /// The account bound as.
    #[must_use]
    pub fn account(&self) -> &DirectoryServiceAccountId {
        &self.account
    }

    /// When the bind was made.
    #[must_use]
    pub fn bound_at(&self) -> OffsetDateTime {
        self.bound_at
    }

    /// Whether this bind still counts, with `account` loaded fresh: it is
    /// the account bound as, still switched on, and its secret has not
    /// changed since.
    ///
    /// Jira's secret leaked and the admin rotated it. Without this, the
    /// connection Mallory bound with the leaked secret before the rotation
    /// keeps reading the directory until it closes.
    #[must_use]
    pub fn still_admits(&self, account: &DirectoryServiceAccount<T>) -> bool {
        *account.id() == self.account
            && account.status() == ServiceAccountStatus::Active
            && account.secret_changed_at() <= self.bound_at
    }

    /// Refuses reading the entry `entry_dn` unless this bind still counts
    /// and `account`'s scope, read now, reaches it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the bind no longer counts. See
    ///   [`still_admits`](Self::still_admits).
    /// - [`DomainError::Forbidden`] when the entry is outside its base DNs.
    pub fn ensure_may_read(
        &self,
        account: &DirectoryServiceAccount<T>,
        entry_dn: &str,
    ) -> Result<(), DomainError> {
        if !self.still_admits(account) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-service-account-s-bind-no",
                "the service account's bind no longer counts; bind again"
            )));
        }
        if !account.scope().reaches(entry_dn) {
            return Err(DomainError::forbidden(message!(
                "authentication-the-service-account-may-not-do",
                "the service account may not do this to this entry"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::domains::authentication::directory_service::account::tests::{Grants, jira, secret};

    /// Jira binds and searches under `dc=acme,dc=com`. The search is let
    /// through.
    #[test]
    fn a_bound_service_reads_within_its_scope() {
        let account = jira();
        let bind = account.bind(&secret("jira-secret")).unwrap();

        assert!(
            bind.ensure_may_read(&account, "uid=ann,dc=acme,dc=com")
                .is_ok()
        );
    }

    /// A bind reads nothing outside its permitted subtree.
    #[test]
    fn a_bound_service_does_nothing_outside_its_scope() {
        let account = jira();
        let bind = account.bind(&secret("jira-secret")).unwrap();

        assert!(
            bind.ensure_may_read(&account, "uid=x,dc=other,dc=com")
                .is_err()
        );
    }

    /// Rotating the secret invalidates an earlier bind and refuses its next read.
    #[test]
    fn rotating_the_secret_ends_binds_made_before() {
        let mut account = jira();
        let bind = account.bind(&secret("jira-secret")).unwrap();
        let _later = crate::shared::clock::freeze(bind.bound_at() + time::Duration::MINUTE);
        account.rotate_secret(secret("new"), &Grants).unwrap();

        assert!(!bind.still_admits(&account));
        assert!(
            bind.ensure_may_read(&account, "uid=ann,dc=acme,dc=com")
                .is_err()
        );
    }

    /// Disabling a directory account invalidates its existing bind.
    #[test]
    fn switching_the_account_off_ends_its_binds() {
        let mut account = jira();
        let bind = account.bind(&secret("jira-secret")).unwrap();

        account.disable(&Grants).unwrap();

        assert!(!bind.still_admits(&account));
    }

    /// A bind for Jira is not admitted by another service account.
    #[test]
    fn a_bind_counts_only_for_its_own_account() {
        let jira_account = jira();
        let other = jira();
        let bind = jira_account.bind(&secret("jira-secret")).unwrap();

        assert!(!bind.still_admits(&other));
    }
}
