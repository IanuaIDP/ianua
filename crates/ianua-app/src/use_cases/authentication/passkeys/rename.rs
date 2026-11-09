//! Renaming one of the signed-in person's own passkeys.
//!
//! The name is how a person tells their keys apart when they remove one, so
//! only the holder renames them, from their own sign-in.

use std::sync::Arc;

use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, Label, PasskeyId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::PasskeyStore;
use crate::use_case::Command;
use crate::use_cases::authentication::passkeys::lookup::owned_passkey;

/// Which of their passkeys the person renames, and to what.
pub struct RenameRequest {
    /// The passkey to rename.
    pub passkey_id: PasskeyId,
    /// Its new name.
    pub name: Label,
}

/// The ports [`RenameUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenamePorts {
    /// The tenant's passkeys.
    pub passkey_store: Arc<dyn PasskeyStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Renames one of the signed-in person's passkeys.
pub struct RenameUseCase {
    ports: RenamePorts,
}

impl RenameUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenamePorts) -> Self {
        Self { ports }
    }
}

impl Command for RenameUseCase {
    type Caller = CallerContext;
    type Input = RenameRequest;
    type Output = Result<(), AppError>;

    /// Renames the passkey of the person signed in to `caller`'s session
    /// and records `authentication.passkey_renamed`.
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
        request: RenameRequest,
    ) -> Result<(), AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let tenant = caller.tenant();
        let store = self.ports.passkey_store.as_ref();
        let mut passkey =
            owned_passkey(store, &tenant, person.account.id(), &request.passkey_id).await?;
        passkey
            .rename(request.name, &person.signed_in)
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &passkey).await.or_internal()?;
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
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::FakePasskeyStore;
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with,
    };

    struct Fixture {
        ann: UserId,
        store: Arc<FakePasskeyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn ann_with_a_passkey() -> Self {
            let ann = UserId::new();
            Self {
                ann,
                store: Arc::new(FakePasskeyStore::with_passkeys(ann, 1)),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn rename_as(&self, user_id: UserId, passkey_id: PasskeyId) -> Result<(), AppError> {
            self.rename_through(FakeTenantAuthorities::holding(&[]), user_id, passkey_id)
        }

        fn rename_through(
            &self,
            authorities: FakeTenantAuthorities,
            user_id: UserId,
            passkey_id: PasskeyId,
        ) -> Result<(), AppError> {
            let use_case = RenameUseCase::new(RenamePorts {
                passkey_store: self.store.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            let request = RenameRequest {
                passkey_id,
                name: Label::new("name", "Work YubiKey").unwrap(),
            };
            block_on(use_case.execute(&caller(user_id), &test_auditor(self.audit.clone()), request))
        }

        fn name_of_anns(&self) -> String {
            block_on(self.store.list_by_user(&test_ctx().tenant(), &self.ann)).unwrap()[0]
                .name()
                .as_str()
                .to_owned()
        }
    }

    fn caller(user_id: UserId) -> CallerContext {
        test_ctx_with(
            test_ctx().organization_id(),
            test_ctx().tenant_id(),
            user_id,
        )
    }

    /// Ann renames her key "Work YubiKey". The new name is kept and the
    /// rename recorded.
    #[test]
    fn a_person_renames_their_passkey() {
        let fixture = Fixture::ann_with_a_passkey();

        fixture
            .rename_as(fixture.ann, fixture.store.first_id())
            .unwrap();

        assert_eq!(fixture.name_of_anns(), "Work YubiKey");
        assert_eq!(
            *fixture.audit.records.lock().unwrap(),
            vec!["authentication.passkey_renamed"]
        );
    }

    /// Renaming another person's passkey returns NotFound and preserves its name.
    #[test]
    fn another_persons_passkey_is_not_found() {
        let fixture = Fixture::ann_with_a_passkey();

        let result = fixture.rename_as(UserId::new(), fixture.store.first_id());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.name_of_anns(), "key_0");
    }

    /// Renaming an unknown passkey returns NotFound.
    #[test]
    fn an_unknown_passkey_is_not_found() {
        let fixture = Fixture::ann_with_a_passkey();

        let result = fixture.rename_as(fixture.ann, PasskeyId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller is unauthenticated and leaves the passkey's name unchanged.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::ann_with_a_passkey();

        let result = fixture.rename_through(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            fixture.ann,
            fixture.store.first_id(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.name_of_anns(), "key_0");
    }
}
