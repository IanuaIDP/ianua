//! A member removing one of their own passkeys.
//!
//! Removing a passkey changes how the member signs in, so it is recorded on
//! the member, and devices and sessions from before it stop counting, except
//! the session it was removed from.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::domains::authentication::keeper::AccountKeeper;
use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, PasskeyId, PrincipalId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgPasskeyStore, OrgSessionStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::{existing_member, member_passkey, owned_org_session};

/// The ports [`OrgDeleteUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgDeletePorts {
    /// Members' passkeys.
    pub passkey_store: Arc<dyn OrgPasskeyStore>,
    /// The members, whose change of how they sign in is kept.
    pub members: Arc<dyn OrgUserStore>,
    /// Members' sessions, to keep the one the passkey is removed from.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
}

/// Removes one of the signed-in member's passkeys.
pub struct OrgDeleteUseCase {
    ports: OrgDeletePorts,
}

impl OrgDeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgDeletePorts) -> Self {
        Self { ports }
    }

    /// Deletes `passkey`, and keeps the member's change and the session
    /// kept through it.
    async fn remove(
        &self,
        member: &OrgUser,
        session: &OrgSession,
        passkey: &PasskeyCredential<ResolvedOrganization>,
    ) -> Result<(), AppError> {
        self.ports
            .passkey_store
            .delete(passkey.id())
            .await
            .or_internal()?;
        self.ports.members.save(member).await.or_internal()?;
        self.ports.sessions.save(session).await.or_internal()
    }
}

impl Command for OrgDeleteUseCase {
    type Caller = OrgCaller;
    type Input = PasskeyId;
    type Output = Result<(), AppError>;

    /// Removes the passkey `passkey_id` of the member signed in to
    /// `caller`'s session, records the change of how they sign in, keeps
    /// that session through it, and records
    /// `organization.org_passkey_removed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session no longer
    ///   counts, or they act through a key.
    /// - `AppError::Forbidden` when the session is another member's.
    /// - `AppError::NotFound` when the member has no such passkey, which is
    ///   also the answer for someone else's, or the session is gone.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        passkey_id: PasskeyId,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let signed_in = actor.signed_in()?;
        let members = self.ports.members.as_ref();
        let mut member = existing_member(members, organization.id(), actor.member().id()).await?;
        let store = self.ports.passkey_store.as_ref();
        let passkey = member_passkey(store, member.id(), &passkey_id).await?;
        AccountKeeper::<ResolvedOrganization>::ensure_may(
            &signed_in,
            &PrincipalId::from(*passkey.user_id()),
            AccountAction::ChangeSignIn,
        )
        .map_err(AppError::from_domain)?;
        let mut session =
            owned_org_session(self.ports.sessions.as_ref(), &organization, &actor).await?;
        member.record_passkey_removed(&passkey);
        session
            .keep_through_own_removal(&member, &signed_in)
            .map_err(AppError::from_domain)?;
        self.remove(&member, &session, &passkey).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*member.id()), member.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::passkey::KeyAttestation;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{CredentialChange, OrgUserId, SessionId};
    use time::Duration;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal, caller_session};
    use crate::test_support::authentication::yubikey;
    use crate::test_support::organization::{
        FakeOrgPasskeyStore, FakeOrgUserStore, RecordingOrgSessionStore, org_session_idle_for,
        stored_caller,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_org_caller, test_session_id,
    };

    struct Fixture {
        passkey: PasskeyId,
        store: Arc<FakeOrgPasskeyStore>,
        members: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        phone: SessionId,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// A passkey of `owner`, with Olivia signed in on her laptop, the
        /// session she acts through, and on her phone since a minute ago.
        fn owned_by(owner: OrgUserId) -> Self {
            let key = yubikey::<ResolvedOrganization>(owner, KeyAttestation::Unattested);
            let olivia = stored_caller(OrgRole::Member, "irrelevant");
            let members = FakeOrgUserStore::empty();
            block_on(members.save(&olivia)).unwrap();
            let phone =
                org_session_idle_for(*olivia.id(), *olivia.organization_id(), Duration::MINUTE);
            Self {
                passkey: *key.id(),
                store: Arc::new(FakeOrgPasskeyStore::holding(
                    test_org_caller().organization_id(),
                    [key],
                )),
                members: Arc::new(members),
                phone: *phone.id(),
                sessions: Arc::new(RecordingOrgSessionStore::holding([
                    caller_session(&olivia),
                    phone,
                ])),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn olivias() -> Self {
            Self::owned_by(*test_org_caller().member())
        }

        fn delete(&self, actors: FakeOrgActors) -> Result<(), AppError> {
            let use_case = OrgDeleteUseCase::new(OrgDeletePorts {
                passkey_store: self.store.clone(),
                members: self.members.clone(),
                sessions: self.sessions.clone(),
                org_actors: Arc::new(actors),
                ..OrgDeletePorts::fakes()
            });
            block_on(use_case.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                self.passkey,
            ))
        }

        fn credentials_changed(&self) -> bool {
            let olivia = block_on(self.members.find_by_id(test_org_caller().member()))
                .unwrap()
                .unwrap();
            olivia.credentials_changed_at() != CredentialChange::Never
        }

        fn olivia(&self) -> OrgUser {
            block_on(self.members.find_by_id(test_org_caller().member()))
                .unwrap()
                .unwrap()
        }

        fn session(&self, id: &SessionId) -> OrgSession {
            block_on(self.sessions.find_by_id(id)).unwrap().unwrap()
        }
    }

    /// Olivia removes a passkey she lost from her laptop's session. The
    /// laptop's session is kept through the change; the one on her phone,
    /// from before it, is not.
    #[test]
    fn the_session_a_passkey_was_removed_from_is_kept() {
        let fixture = Fixture::olivias();

        fixture
            .delete(FakeOrgActors::in_role(OrgRole::Member))
            .unwrap();

        let olivia = fixture.olivia();
        let laptop = fixture.session(&test_session_id());
        assert_eq!(laptop.kept_through(), olivia.credentials_changed_at());
        assert!(laptop.counts_for(&olivia));
        assert!(!fixture.session(&fixture.phone).counts_for(&olivia));
    }

    /// Olivia removes her own passkey. It is gone, the change of how she
    /// signs in is recorded on her, and the removal is recorded.
    #[test]
    fn a_member_removes_her_own_passkey() {
        let fixture = Fixture::olivias();

        fixture
            .delete(FakeOrgActors::in_role(OrgRole::Member))
            .unwrap();

        assert_eq!(fixture.store.count(), 0);
        assert!(fixture.credentials_changed());
        assert_eq!(
            *fixture.audit.records.lock().unwrap(),
            vec!["organization.org_passkey_removed"]
        );
    }

    /// An owner cannot remove another member's passkey; it is treated as
    /// not found and remains stored.
    #[test]
    fn another_members_passkey_cannot_be_removed() {
        let fixture = Fixture::owned_by(OrgUserId::new());

        let result = fixture.delete(FakeOrgActors::in_role(OrgRole::Owner));

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.store.count(), 1);
    }

    /// A signed-out session cannot remove the member's stored passkey.
    #[test]
    fn a_signed_out_member_is_refused() {
        let fixture = Fixture::olivias();

        let result = fixture.delete(FakeOrgActors::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.store.count(), 1);
    }

    /// An API key cannot authorize passkey removal, and the key remains stored.
    #[test]
    fn a_key_caller_is_refused() {
        let fixture = Fixture::olivias();

        let result = fixture.delete(FakeOrgActors::through_key(OrgRole::Member, Vec::new()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.store.count(), 1);
    }
}
