//! Who acts on the platform's operator plane.
//!
//! Operators belong to no tenant and hold no tenant rights. What lets one
//! act is that they are a platform operator, signed in now, whose account
//! is still active. Every change to operators and to impersonation grants
//! names that operator.

use time::OffsetDateTime;

use crate::domains::audit::access::{AuditLogAccess, AuditLogOf};
use crate::domains::operator::api_key::OperatorApiKey;
use crate::domains::operator::events::DeadJobRetried;
use crate::domains::operator::identity::Operator;
use crate::domains::scheduling::job::{RetryOrder, ScheduledJob};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::RaisedEvents;
use crate::types::{ActorRef, Expiry, OperatorId};

/// Proof that an operator gave their password just now.
///
/// Only [`Operator::sign_in_with_password`] makes one, after checking the
/// password against the account, so no caller writes an operator id in by
/// hand.
#[derive(Debug)]
pub struct OperatorSignIn {
    operator: OperatorId,
}

impl OperatorSignIn {
    /// A sign-in this crate checked for `operator`.
    pub(crate) fn of(operator: OperatorId) -> Self {
        Self { operator }
    }

    /// The operator who signed in.
    #[must_use]
    pub fn operator(&self) -> &OperatorId {
        &self.operator
    }
}

/// What an operator acts through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActsThrough {
    /// Their password, given just now.
    Password,
    /// One of their API keys, which works until it ends.
    Key {
        /// When the key stops working, or that it never does.
        ends: Expiry,
    },
}

/// A platform operator acting now: signed in, with an active account.
///
/// Bob's account was disabled an hour ago. Without this, the session he
/// still holds makes Carol's account an operator again, or grants him
/// impersonation in Acme. Its fields are private, and only [`Self::of`]
/// and [`Self::of_key`] make one, from the account and its sign-in or key.
#[derive(Debug, Clone)]
pub struct OperatorAuthority {
    operator: OperatorId,
    through: ActsThrough,
}

impl OperatorAuthority {
    /// `operator`, acting on the strength of `sign_in`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `sign_in` is another operator's.
    /// - [`DomainError::Forbidden`] when the account is disabled.
    pub fn of(operator: &Operator, sign_in: &OperatorSignIn) -> Result<Self, DomainError> {
        if sign_in.operator() != operator.id() {
            return Err(DomainError::forbidden(message!(
                "operator-the-sign-in-is-for-another",
                "the sign-in is for another operator"
            )));
        }
        ensure_active(operator)?;
        Ok(Self {
            operator: *operator.id(),
            through: ActsThrough::Password,
        })
    }

    /// `operator`, acting through `key`, one of their own API keys, at
    /// `now`.
    ///
    /// A key acts for the operator who made it, and only while both work.
    /// Bob's key leaks into a CI log. Once he revokes it, or an admin
    /// disables Bob, whoever copied it acts as nobody.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `key` is another operator's.
    /// - [`DomainError::Forbidden`] when `key` was revoked or has expired.
    /// - [`DomainError::Forbidden`] when the account is disabled.
    pub fn of_key(
        operator: &Operator,
        key: &OperatorApiKey,
        now: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        if key.operator_id() != operator.id() {
            return Err(DomainError::forbidden(message!(
                "operator-the-key-is-another-operator-s",
                "the key is another operator's"
            )));
        }
        if !key.works_at(now) {
            return Err(DomainError::forbidden(message!(
                "authorization-the-key-no-longer-works",
                "the key no longer works"
            )));
        }
        ensure_active(operator)?;
        Ok(Self {
            operator: *operator.id(),
            through: ActsThrough::Key {
                ends: key.expires_at(),
            },
        })
    }

    /// `operator`, acting as a test says, without a sign-in.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(operator: OperatorId) -> Self {
        Self {
            operator,
            through: ActsThrough::Password,
        }
    }

    /// The operator acting.
    #[must_use]
    pub fn operator(&self) -> &OperatorId {
        &self.operator
    }

    /// The operator acting, as the actor an audit record names.
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        ActorRef::Operator(self.operator)
    }

    /// The proof that they may export the whole platform's audit log, which
    /// every operator may: operators hold no finer rights, and each may
    /// read every record already.
    #[must_use]
    pub fn audit_log_export(&self) -> AuditLogAccess {
        AuditLogAccess::granted(AuditLogOf::Platform, self.actor())
    }

    /// The word to put a dead job back on the queue, which every operator
    /// may give: operators hold no finer rights.
    #[must_use]
    pub fn job_retry(&self) -> RetryOrder {
        RetryOrder::granted()
    }

    /// The record that this operator put `job` back on the queue, naming it
    /// by its id and kind and never what it carries.
    #[must_use]
    pub fn dead_job_retried(&self, job: &ScheduledJob) -> Vec<DomainEvent> {
        let mut raised = RaisedEvents::default();
        raised.raise_platform(DeadJobRetried {
            job_id: *job.id(),
            job_type: job.job_type().clone(),
            tenant_id: job.tenant_id().copied(),
            attempts: job.attempt(),
            retried_by: self.operator,
            occurred_at: job.run_at(),
        });
        raised.take()
    }

    /// Refuses a change to the account `target` when it is the acting
    /// operator's own.
    ///
    /// An operator does not make, disable or enable their own account.
    /// Bob, disabled for misuse, would otherwise enable himself from a
    /// session he opened before, and an operator disabling themselves by
    /// mistake could leave the platform with nobody to run it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `target` is the acting operator.
    pub(crate) fn ensure_manages_another(&self, target: &OperatorId) -> Result<(), DomainError> {
        if self.operator == *target {
            return Err(DomainError::forbidden(message!(
                "operator-an-operator-s-own-account-is",
                "an operator's own account is changed by another operator"
            )));
        }
        Ok(())
    }

    /// Refuses `ends` for something made through a key that ends sooner. A
    /// leaked key would otherwise make a new key that outlives it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the operator acts through a key
    ///   that ends before `ends`, or `ends` is never.
    pub(crate) fn ensure_outlasts(&self, ends: Expiry) -> Result<(), DomainError> {
        let ActsThrough::Key { ends: ceiling } = self.through else {
            return Ok(());
        };
        let Some(ceiling) = ceiling.instant() else {
            return Ok(());
        };
        if ends.instant().is_none_or(|at| at > ceiling) {
            return Err(DomainError::forbidden(message!(
                "operator-a-key-made-through-a-key",
                "a key made through a key ends no later than that key"
            )));
        }
        Ok(())
    }
}

/// Refuses an operator whose account is disabled.
fn ensure_active(operator: &Operator) -> Result<(), DomainError> {
    if !operator.is_active() {
        return Err(DomainError::forbidden(message!(
            "operator-a-disabled-operator-cannot-act",
            "a disabled operator cannot act"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::operator::api_key::tests::key_of;
    use crate::domains::operator::identity::OperatorRow;
    use crate::domains::operator::status::OperatorStatus;
    use crate::test_support::fakes::FakeHasher;
    use crate::types::{Email, PasswordHash};

    /// An active operator whose address starts with `name`.
    pub(crate) fn operator_named(name: &str) -> Operator {
        Operator::reconstitute(OperatorRow {
            id: OperatorId::new(),
            email: Email::new(format!("{name}@ianua.dev")).unwrap(),
            password_hash: PasswordHash::from_stored("fake$correct horse".to_owned()),
            status: OperatorStatus::Active,
            created_at: crate::shared::clock::now(),
        })
        .unwrap()
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// Bob gives his password and acts as himself.
    #[test]
    fn an_operator_who_signed_in_acts() {
        let bob = operator_named("bob");
        let sign_in = bob
            .sign_in_with_password("correct horse", &FakeHasher)
            .unwrap();

        let authority = OperatorAuthority::of(&bob, &sign_in).unwrap();

        assert_eq!(authority.operator(), bob.id());
    }

    /// Carol's password sign-in proof cannot produce authority for Bob's account.
    #[test]
    fn a_sign_in_acts_only_for_its_own_operator() {
        let bob = operator_named("bob");
        let carol = operator_named("carol");
        let carols = carol
            .sign_in_with_password("correct horse", &FakeHasher)
            .unwrap();

        let acting = OperatorAuthority::of(&bob, &carols);

        assert!(matches!(acting, Err(DomainError::Forbidden(_))));
    }

    /// Disabling Bob's account prevents its existing password sign-in proof
    /// from producing operator authority.
    #[test]
    fn a_disabled_operator_does_not_act() {
        let mut bob = operator_named("bob");
        let sign_in = bob
            .sign_in_with_password("correct horse", &FakeHasher)
            .unwrap();
        let carol = OperatorAuthority::assumed(OperatorId::new());
        bob.disable(&carol).unwrap();

        let acting = OperatorAuthority::of(&bob, &sign_in);

        assert!(matches!(acting, Err(DomainError::Forbidden(_))));
    }

    /// Bob's CLI calls the platform with his own working key. It acts as
    /// Bob.
    #[test]
    fn an_operator_acts_through_their_own_key() {
        let bob = operator_named("bob");
        let key = key_of(&bob, Expiry::Never);

        let authority = OperatorAuthority::of_key(&bob, &key, now()).unwrap();

        assert_eq!(authority.operator(), bob.id());
    }

    /// Carol's API key cannot produce authority for Bob's account.
    #[test]
    fn a_key_acts_only_for_the_operator_who_made_it() {
        let bob = operator_named("bob");
        let carols = key_of(&operator_named("carol"), Expiry::Never);

        let acting = OperatorAuthority::of_key(&bob, &carols, now());

        assert!(matches!(acting, Err(DomainError::Forbidden(_))));
    }

    /// Revoking Bob's key prevents it from producing operator authority.
    #[test]
    fn a_revoked_key_acts_for_nobody() {
        let bob = operator_named("bob");
        let mut key = key_of(&bob, Expiry::Never);
        key.revoke(&OperatorAuthority::assumed(*bob.id()), bob.label())
            .unwrap();

        let acting = OperatorAuthority::of_key(&bob, &key, now());

        assert!(matches!(acting, Err(DomainError::Forbidden(_))));
    }

    /// A key produces authority one second before expiry but is rejected
    /// at the exact expiry instant.
    #[test]
    fn an_expired_key_acts_for_nobody() {
        let bob = operator_named("bob");
        let ends = now() + Duration::days(1);
        let key = key_of(&bob, Expiry::At(ends));

        let before = OperatorAuthority::of_key(&bob, &key, ends - Duration::seconds(1));
        let at = OperatorAuthority::of_key(&bob, &key, ends);

        assert!(before.is_ok());
        assert!(matches!(at, Err(DomainError::Forbidden(_))));
    }

    /// Disabling Bob's account prevents its unrevoked, nonexpiring key
    /// from producing operator authority.
    #[test]
    fn a_disabled_operators_key_acts_for_nobody() {
        let mut bob = operator_named("bob");
        let key = key_of(&bob, Expiry::Never);
        let carol = OperatorAuthority::assumed(OperatorId::new());
        bob.disable(&carol).unwrap();

        let acting = OperatorAuthority::of_key(&bob, &key, now());

        assert!(matches!(acting, Err(DomainError::Forbidden(_))));
    }
}
