//! Removing one of the signed-in person's own passkeys.
//!
//! Removing a passkey changes how the account signs in, so it is recorded
//! on the account, and devices and sessions from before it stop counting,
//! except the session it was removed from. Nothing stops a person removing
//! their last passkey.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, PasskeyId};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::PasskeyStore;
use crate::ports::identity::UserStore;
use crate::ports::shared::SessionStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::passkeys::lookup::owned_passkey;

/// The ports [`DeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeletePorts {
    /// The tenant's passkeys.
    pub passkey_store: Arc<dyn PasskeyStore>,
    /// The tenant's users, whose change of how they sign in is kept.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's sessions, to keep the one the passkey is removed from.
    pub session_store: Arc<dyn SessionStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Removes one of the signed-in person's passkeys.
pub struct DeleteUseCase {
    ports: DeletePorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: DeletePorts) -> Self {
        Self { ports }
    }

    /// Deletes `passkey`, and keeps the person's change and the session
    /// kept through it.
    async fn remove(
        &self,
        tenant: &ScopedTenant,
        person: &SignedInAccount,
        passkey: &PasskeyCredential<ResolvedTenant>,
    ) -> Result<(), AppError> {
        self.ports
            .passkey_store
            .delete(tenant, passkey.id())
            .await
            .or_internal()?;
        self.ports
            .user_store
            .save(tenant, &person.account)
            .await
            .or_internal()?;
        self.ports
            .session_store
            .save(tenant, &person.session)
            .await
            .or_internal()
    }
}

impl Command for DeleteUseCase {
    type Caller = CallerContext;
    type Input = PasskeyId;
    type Output = Result<(), AppError>;

    /// Removes the passkey `passkey_id` of the person signed in to
    /// `caller`'s session, records the change of how their account signs
    /// in, keeps that session through it, and records
    /// `authentication.passkey_removed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session no longer
    ///   counts.
    /// - `AppError::NotFound` when the person has no such passkey, which
    ///   is also the answer for someone else's.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        passkey_id: PasskeyId,
    ) -> Result<(), AppError> {
        let mut person = self.ports.tenant_authorities.signed_in(caller).await?;
        let tenant = caller.tenant();
        let store = self.ports.passkey_store.as_ref();
        let mut passkey = owned_passkey(store, &tenant, person.account.id(), &passkey_id).await?;
        passkey
            .remove(&person.signed_in)
            .map_err(AppError::from_domain)?;
        person.account.record_credential_change();
        person
            .session
            .keep_through_own_removal(&person.account, &person.signed_in)
            .map_err(AppError::from_domain)?;
        self.remove(&tenant, &person, &passkey).await?;
        auditor
            .dispatch_by(
                &ActorRef::User(*passkey.user_id()),
                passkey.take_events(&tenant),
            )
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{CredentialChange, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{FakePasskeyStore, FakeSessionStore};
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with, test_session_id,
    };

    struct Fixture {
        ann: UserId,
        store: Arc<FakePasskeyStore>,
        users: Arc<FakeUserStore>,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn ann_with_two_passkeys() -> Self {
            let ann = UserId::new();
            Self {
                ann,
                store: Arc::new(FakePasskeyStore::with_passkeys(ann, 2)),
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                sessions: Arc::new(FakeSessionStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn delete_through(
            &self,
            authorities: FakeTenantAuthorities,
            user_id: UserId,
            passkey_id: PasskeyId,
        ) -> Result<(), AppError> {
            let use_case = DeleteUseCase::new(DeletePorts {
                passkey_store: self.store.clone(),
                user_store: self.users.clone(),
                session_store: self.sessions.clone(),
                tenant_authorities: Arc::new(authorities),
                ..DeletePorts::fakes()
            });
            let caller = test_ctx_with(
                test_ctx().organization_id(),
                test_ctx().tenant_id(),
                user_id,
            );
            block_on(use_case.execute(&caller, &test_auditor(self.audit.clone()), passkey_id))
        }

        fn delete_as(&self, user_id: UserId, passkey_id: PasskeyId) -> Result<(), AppError> {
            self.delete_through(FakeTenantAuthorities::holding(&[]), user_id, passkey_id)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann removes one of her two passkeys. One is left, the change of how
    /// her account signs in is kept, and the removal recorded.
    #[test]
    fn a_person_removes_their_passkey() {
        let fixture = Fixture::ann_with_two_passkeys();

        fixture
            .delete_as(fixture.ann, fixture.store.first_id())
            .unwrap();

        assert_eq!(fixture.store.count(), 1);
        let ann = block_on(fixture.users.find_by_id(&test_ctx().tenant(), &fixture.ann))
            .unwrap()
            .unwrap();
        assert!(matches!(
            ann.credentials_changed_at(),
            CredentialChange::At { .. }
        ));
        assert_eq!(fixture.recorded(), vec!["authentication.passkey_removed"]);
    }

    /// Ann removes a passkey she lost, from her laptop's session. The
    /// change ends her sessions from before it, but the laptop's is kept
    /// through it.
    #[test]
    fn the_session_a_passkey_was_removed_from_is_kept() {
        let fixture = Fixture::ann_with_two_passkeys();

        fixture
            .delete_as(fixture.ann, fixture.store.first_id())
            .unwrap();

        let ann = block_on(fixture.users.find_by_id(&test_ctx().tenant(), &fixture.ann))
            .unwrap()
            .unwrap();
        let laptop = fixture.sessions.get_session(&test_session_id()).unwrap();
        assert_eq!(laptop.kept_through(), ann.credentials_changed_at());
        assert_ne!(laptop.kept_through(), CredentialChange::Never);
    }

    /// Deleting another person's passkey returns NotFound, retains both
    /// stored keys and records no removal.
    #[test]
    fn another_persons_passkey_is_not_found() {
        let fixture = Fixture::ann_with_two_passkeys();

        let result = fixture.delete_as(UserId::new(), fixture.store.first_id());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.store.count(), 2);
        assert!(fixture.recorded().is_empty());
    }

    /// Deleting an unknown passkey returns NotFound without recording an event.
    #[test]
    fn an_unknown_passkey_is_not_found() {
        let fixture = Fixture::ann_with_two_passkeys();

        let result = fixture.delete_as(fixture.ann, PasskeyId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A signed-out caller is unauthenticated and leaves both passkeys stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::ann_with_two_passkeys();

        let result = fixture.delete_through(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            fixture.ann,
            fixture.store.first_id(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.store.count(), 2);
    }
}
