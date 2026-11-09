//! A member renaming one of their own passkeys.
//!
//! The name is how a member tells their keys apart when they remove one, so
//! only the member, from their own sign-in, renames it.

use std::sync::Arc;

use ianua_domain::domains::organization::events::access::OrgPasskeyRenamed;
use ianua_domain::types::{ActorRef, Label, PasskeyId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgPasskeyStore;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::member_passkey;

/// Which of the member's passkeys to rename, and to what.
pub struct OrgRenameRequest {
    /// The passkey to rename.
    pub passkey_id: PasskeyId,
    /// Its new name.
    pub name: Label,
}

/// The ports [`OrgRenameUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgRenamePorts {
    /// Members' passkeys.
    pub passkey_store: Arc<dyn OrgPasskeyStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Renames one of the signed-in member's passkeys.
pub struct OrgRenameUseCase {
    ports: OrgRenamePorts,
}

impl OrgRenameUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgRenamePorts) -> Self {
        Self { ports }
    }
}

impl Command for OrgRenameUseCase {
    type Caller = OrgCaller;
    type Input = OrgRenameRequest;
    type Output = Result<(), AppError>;

    /// Renames the passkey `request.passkey_id` of the member signed in to
    /// `caller`'s session, and records `organization.org_passkey_renamed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session no longer
    ///   counts, or they act through a key.
    /// - `AppError::Forbidden` when the session is another member's.
    /// - `AppError::NotFound` when the member has no such passkey, which is
    ///   also the answer for someone else's.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: OrgRenameRequest,
    ) -> Result<(), AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        let signed_in = actor.signed_in()?;
        let member = actor.member();
        let store = self.ports.passkey_store.as_ref();
        let mut passkey = member_passkey(store, member.id(), &request.passkey_id).await?;
        passkey
            .rename(request.name, &signed_in)
            .map_err(AppError::from_domain)?;
        store
            .save(member.organization_id(), member.id(), &passkey)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OrgUser(*member.id()),
                vec![OrgPasskeyRenamed::observed(member, &passkey)],
            )
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::passkey::KeyAttestation;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::isolation::organization::scope::ResolvedOrganization;
    use ianua_domain::types::OrgUserId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::authentication::yubikey;
    use crate::test_support::organization::FakeOrgPasskeyStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Fixture {
        passkey: PasskeyId,
        store: Arc<FakeOrgPasskeyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn owned_by(owner: OrgUserId) -> Self {
            let key = yubikey::<ResolvedOrganization>(owner, KeyAttestation::Unattested);
            let passkey = *key.id();
            Self {
                passkey,
                store: Arc::new(FakeOrgPasskeyStore::holding(
                    test_org_caller().organization_id(),
                    [key],
                )),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn olivias() -> Self {
            Self::owned_by(*test_org_caller().member())
        }

        fn rename(&self, actors: FakeOrgActors) -> Result<(), AppError> {
            let use_case = OrgRenameUseCase::new(OrgRenamePorts {
                passkey_store: self.store.clone(),
                org_actors: Arc::new(actors),
            });
            block_on(use_case.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                OrgRenameRequest {
                    passkey_id: self.passkey,
                    name: Label::new("name", "Work laptop").unwrap(),
                },
            ))
        }

        fn name(&self) -> String {
            self.store
                .stored(&self.passkey)
                .unwrap()
                .name()
                .as_str()
                .to_owned()
        }
    }

    /// Olivia renames her own passkey. The new name is kept and the change
    /// recorded.
    #[test]
    fn a_member_renames_her_own_passkey() {
        let fixture = Fixture::olivias();

        fixture
            .rename(FakeOrgActors::in_role(OrgRole::Member))
            .unwrap();

        assert_eq!(fixture.name(), "Work laptop");
        assert_eq!(
            *fixture.audit.records.lock().unwrap(),
            vec!["organization.org_passkey_renamed"]
        );
    }

    /// Another member's passkey is treated as not found when an owner tries
    /// to rename it, and its name stays unchanged.
    #[test]
    fn another_members_passkey_cannot_be_renamed() {
        let fixture = Fixture::owned_by(OrgUserId::new());

        let result = fixture.rename(FakeOrgActors::in_role(OrgRole::Owner));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.name(), "YubiKey");
    }

    /// A signed-out session cannot rename a passkey, whose name stays unchanged.
    #[test]
    fn a_signed_out_member_is_refused() {
        let fixture = Fixture::olivias();

        let result = fixture.rename(FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.name(), "YubiKey");
    }

    /// An API key cannot authorize a passkey rename in place of a session.
    #[test]
    fn a_key_caller_is_refused() {
        let fixture = Fixture::olivias();

        let result = fixture.rename(FakeOrgActors::through_key(OrgRole::Member, Vec::new()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
