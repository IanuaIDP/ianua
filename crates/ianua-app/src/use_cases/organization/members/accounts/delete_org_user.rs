//! Removing a member from the organization for good.
//!
//! Every session of theirs ends and every delegation they granted, in any
//! tenant of the organization, is revoked before the record goes. The
//! organization always keeps an active owner, and nobody removes
//! themselves.

use std::sync::Arc;

use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::owners::Owners;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, OrgUserId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSessionStore, OrgUserStore};
use crate::services::authorization::grant_revocation::OrgGrantRevocation;
use crate::use_case::Command;
use crate::use_cases::organization::attributed::attributed;
use crate::use_cases::organization::lookup::{current_owners, existing_member};
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_member;

/// The ports [`DeleteOrgUserUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DeleteOrgUserPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Members' sessions, ended before the record goes.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Revokes what the member granted, in every tenant.
    pub grant_revocation: OrgGrantRevocation,
}

/// Removes a member from the organization.
pub struct DeleteOrgUserUseCase {
    ports: DeleteOrgUserPorts,
}

impl DeleteOrgUserUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: DeleteOrgUserPorts) -> Self {
        Self { ports }
    }

    /// Revokes everything `member` granted, in every tenant.
    async fn revoke_grants(
        &self,
        member: &OrgUser,
        caller: &OrgCaller,
    ) -> Result<Vec<DomainEvent>, AppError> {
        self.ports
            .grant_revocation
            .revoke_all_granted_by(
                member.organization_id(),
                member.id(),
                &ActorRef::OrgUser(*caller.member()),
            )
            .await
            .or_internal()
    }
}

impl Command for DeleteOrgUserUseCase {
    type Caller = OrgCaller;
    type Input = OrgUserId;
    type Output = Result<(), AppError>;

    /// Removes the member `id`, ends their sessions, revokes what they
    /// granted and records `organization.org_user_deleted`, with a record
    /// for each delegation revoked.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller names themselves, may not
    ///   remove members, or removes an owner without being one.
    /// - `AppError::Conflict` when the member is the last active owner.
    /// - `AppError::NotFound` when the organization has no such member.
    /// - `AppError::Internal` on persistence, revocation or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        id: OrgUserId,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let users = self.ports.org_users.as_ref();
        let owners = current_owners(users, organization.id()).await?;
        let mut member = existing_member(users, organization.id(), &id).await?;
        member
            .remove(&control, Owners::of(&owners))
            .map_err(AppError::from_domain)?;
        let revoked = self.revoke_grants(&member, caller).await?;
        sign_out_member(self.ports.org_sessions.as_ref(), member.id()).await?;
        users.delete(member.id()).await.or_internal()?;
        let by = ActorRef::OrgUser(*caller.member());
        let events = attributed(&by, member.take_events(), revoked);
        auditor.dispatch(&events).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::OrganizationId;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        DelegatedGrant, FakeOrgUserStore, RecordingOrgSessionStore, delegation_granted_by,
        org_user_store_with, stored_caller, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: DeleteOrgUserUseCase,
        users: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        sam: OrgUserId,
        oscar: OrgUserId,
        granted: DelegatedGrant,
    }

    impl Setup {
        /// Sam, a member who granted a delegation, Oscar, an owner, and the
        /// caller, an owner too.
        fn with(actors: FakeOrgActors) -> Self {
            let organization_id = test_org_caller().organization_id();
            let sam = test_org_user(organization_id, "sam@acme.test", OrgRole::Member);
            let oscar = test_org_user(organization_id, "oscar@acme.test", OrgRole::Owner);
            let (sam_id, oscar_id) = (*sam.id(), *oscar.id());
            let users = Arc::new(org_user_store_with([
                sam,
                oscar,
                stored_caller(OrgRole::Owner, "pw"),
            ]));
            let sessions = Arc::new(RecordingOrgSessionStore::new());
            let granted = delegation_granted_by(organization_id, sam_id);
            Self {
                uc: DeleteOrgUserUseCase::new(DeleteOrgUserPorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                    org_sessions: sessions.clone(),
                    grant_revocation: granted.revocation(),
                }),
                users,
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
                sam: sam_id,
                oscar: oscar_id,
                granted,
            }
        }

        fn owner() -> Self {
            Self::with(FakeOrgActors::in_role(OrgRole::Owner))
        }

        fn delete(&self, member: OrgUserId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                member,
            ))
        }

        fn holds(&self, member: OrgUserId) -> bool {
            block_on(self.users.find_by_id(&member)).unwrap().is_some()
        }
    }

    /// Olivia removes Sam. What he granted in every tenant is revoked.
    #[test]
    fn removing_a_member_revokes_what_they_granted_in_every_tenant() {
        let setup = Setup::owner();

        setup.delete(setup.sam).unwrap();

        assert!(setup.granted.is_revoked());
    }

    /// Olivia removes Sam. His record goes, he is signed out everywhere,
    /// and the removal is recorded.
    #[test]
    fn removing_a_member_deletes_them_and_signs_them_out_everywhere() {
        let setup = Setup::owner();

        setup.delete(setup.sam).unwrap();

        assert!(!setup.holds(setup.sam));
        assert!(setup.sessions.revoked(&setup.sam));
        assert_eq!(
            setup.audit.records.lock().unwrap()[0],
            "organization.org_user_deleted"
        );
    }

    /// Olivia removes Oscar, another owner, while she stays one herself.
    #[test]
    fn an_owner_removes_another_owner_while_one_remains() {
        let setup = Setup::owner();

        setup.delete(setup.oscar).unwrap();

        assert!(!setup.holds(setup.oscar));
    }

    /// Removing the last stored active owner conflicts, and his account remains.
    #[test]
    fn removing_the_last_active_owner_is_refused() {
        let setup = Setup::owner();
        block_on(setup.users.delete(test_org_caller().member())).unwrap();

        let result = setup.delete(setup.oscar);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(setup.holds(setup.oscar));
    }

    /// An owner cannot remove their own account, which remains stored.
    #[test]
    fn removing_oneself_is_refused() {
        let setup = Setup::owner();
        let olivia = *test_org_caller().member();

        let result = setup.delete(olivia);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.holds(olivia));
    }

    /// A plain member cannot remove an owner; the owner stays and the
    /// fixture's existing delegation remains unrevoked.
    #[test]
    fn a_member_without_the_remove_right_is_refused() {
        let setup = Setup::with(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.delete(setup.oscar);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(setup.holds(setup.oscar));
        assert!(!setup.granted.is_revoked());
    }

    /// Another organization's member is not found for deletion; her account
    /// stays and her sessions are not revoked.
    #[test]
    fn a_member_of_another_organization_is_not_found() {
        let setup = Setup::owner();
        let elsewhere = test_org_user(OrganizationId::new(), "eve@other.test", OrgRole::Member);
        let eve = *elsewhere.id();
        block_on(setup.users.save(&elsewhere)).unwrap();

        let result = setup.delete(eve);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.holds(eve));
        assert!(!setup.sessions.revoked(&eve));
    }

    /// A signed-out caller cannot remove Sam, whose account remains stored.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.delete(setup.sam);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.holds(setup.sam));
    }

    /// Refused organization authority prevents removing Sam.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::with(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.delete(setup.sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
