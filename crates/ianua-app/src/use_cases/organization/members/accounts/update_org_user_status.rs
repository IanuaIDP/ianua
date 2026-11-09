//! Locking, deactivating or letting a member back in.
//!
//! A member locked or deactivated is signed out everywhere at once, and
//! every delegation they granted, in any tenant of the organization, is
//! revoked with them: their agents must not keep acting for someone who
//! can no longer act. The organization always keeps an active owner.

use std::sync::Arc;

use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
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

/// Whose status changes, and to what.
pub struct UpdateOrgUserStatusRequest {
    /// The member whose status changes.
    pub member: OrgUserId,
    /// The status to move them to.
    pub status: OrgUserStatus,
}

/// The ports [`UpdateOrgUserStatusUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateOrgUserStatusPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Members' sessions, ended when a member is shut out.
    pub org_sessions: Arc<dyn OrgSessionStore>,
    /// Revokes what a shut-out member granted, in every tenant.
    pub grant_revocation: OrgGrantRevocation,
}

/// Moves a member to another status.
pub struct UpdateOrgUserStatusUseCase {
    ports: UpdateOrgUserStatusPorts,
}

impl UpdateOrgUserStatusUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UpdateOrgUserStatusPorts) -> Self {
        Self { ports }
    }

    /// Revokes what `member` granted, unless they may still sign in.
    async fn revoke_grants_of_shut_out(
        &self,
        member: &OrgUser,
        caller: &OrgCaller,
    ) -> Result<Vec<DomainEvent>, AppError> {
        if member.status().can_authenticate() {
            return Ok(Vec::new());
        }
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

    /// Signs `member` out everywhere when they are locked or deactivated.
    async fn sign_out_shut_out(&self, member: &OrgUser) -> Result<(), AppError> {
        if !matches!(
            member.status(),
            OrgUserStatus::Deactivated | OrgUserStatus::Locked
        ) {
            return Ok(());
        }
        sign_out_member(self.ports.org_sessions.as_ref(), member.id()).await
    }
}

impl Command for UpdateOrgUserStatusUseCase {
    type Caller = OrgCaller;
    type Input = UpdateOrgUserStatusRequest;
    type Output = Result<(), AppError>;

    /// Moves `request.member` to `request.status` and records
    /// `organization.org_user_status_changed`, with a record for each
    /// delegation revoked. A member locked or deactivated is signed out and
    /// loses what they granted.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without member-update rights or for a nonowner changing an owner.
    /// - `AppError::Conflict` for shutting out the last active owner; `Domain` for an invalid status transition.
    /// - `AppError::NotFound` for a missing organization member; `Internal` on persistence, revocation or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: UpdateOrgUserStatusRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let users = self.ports.org_users.as_ref();
        let owners = current_owners(users, organization.id()).await?;
        let mut member = existing_member(users, organization.id(), &request.member).await?;
        member
            .change_status(request.status, &control, Owners::of(&owners))
            .map_err(AppError::from_domain)?;
        let revoked = self.revoke_grants_of_shut_out(&member, caller).await?;
        users.save(&member).await.or_internal()?;
        self.sign_out_shut_out(&member).await?;
        let by = ActorRef::OrgUser(*caller.member());
        let events = attributed(&by, member.take_events(), revoked);
        auditor.dispatch(&events).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        DelegatedGrant, FakeOrgUserStore, RecordingOrgSessionStore, delegation_granted_by,
        org_user_store_with, stored_caller, test_org_member_at, unconfirmed_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: UpdateOrgUserStatusUseCase,
        users: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        events: Arc<FakeEventDispatcher>,
        sam: OrgUserId,
        granted: DelegatedGrant,
    }

    impl Setup {
        /// Sam, a member of Acme who granted a delegation in one of its
        /// tenants, standing at `status`, and the caller, an owner.
        fn with(actors: FakeOrgActors, status: OrgUserStatus) -> Self {
            let organization_id = test_org_caller().organization_id();
            let sam = test_org_member_at(organization_id, "sam@acme.test", status);
            Self::holding(actors, sam)
        }

        /// Sam, still waiting to confirm his address, and the caller, an
        /// owner.
        fn waiting() -> Self {
            let organization_id = test_org_caller().organization_id();
            let sam = unconfirmed_org_user(organization_id, "sam@acme.test");
            Self::holding(FakeOrgActors::in_role(OrgRole::Owner), sam)
        }

        /// `sam`, who granted a delegation in one of Acme's tenants, and
        /// the caller, acting as `actors` says.
        fn holding(actors: FakeOrgActors, sam: OrgUser) -> Self {
            let organization_id = test_org_caller().organization_id();
            let sam_id = *sam.id();
            let users = Arc::new(org_user_store_with([
                sam,
                stored_caller(OrgRole::Owner, "pw"),
            ]));
            let sessions = Arc::new(RecordingOrgSessionStore::new());
            let granted = delegation_granted_by(organization_id, sam_id);
            Self {
                uc: UpdateOrgUserStatusUseCase::new(UpdateOrgUserStatusPorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                    org_sessions: sessions.clone(),
                    grant_revocation: granted.revocation(),
                }),
                users,
                sessions,
                events: Arc::new(FakeEventDispatcher::new()),
                sam: sam_id,
                granted,
            }
        }

        /// Whether `event_type` was recorded: the event the token cache
        /// drops the member's cached callers by.
        fn recorded(&self, event_type: &str) -> bool {
            self.events
                .records
                .lock()
                .unwrap()
                .iter()
                .any(|recorded| recorded == event_type)
        }

        fn owner(status: OrgUserStatus) -> Self {
            Self::with(FakeOrgActors::in_role(OrgRole::Owner), status)
        }

        fn change(&self, member: OrgUserId, status: OrgUserStatus) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.events.clone()),
                UpdateOrgUserStatusRequest { member, status },
            ))
        }
    }

    /// Their agents must not go on acting for Sam once he can no longer
    /// act. Deactivating him revokes what he granted.
    #[test]
    fn deactivating_a_member_revokes_what_they_granted_in_every_tenant() {
        let setup = Setup::owner(OrgUserStatus::Active);

        setup.change(setup.sam, OrgUserStatus::Deactivated).unwrap();

        assert!(setup.granted.is_revoked());
    }

    /// Olivia deactivates Sam. It is saved and he is signed out everywhere.
    #[test]
    fn deactivating_a_member_saves_it_and_signs_them_out_everywhere() {
        let setup = Setup::owner(OrgUserStatus::Active);

        setup.change(setup.sam, OrgUserStatus::Deactivated).unwrap();

        assert_eq!(
            setup.users.get_status(&setup.sam),
            Some(OrgUserStatus::Deactivated)
        );
        assert!(setup.sessions.revoked(&setup.sam));
        assert!(setup.recorded("organization.org_user_status_changed"));
    }

    /// Olivia locks Sam. He is signed out everywhere.
    #[test]
    fn locking_a_member_signs_them_out_everywhere() {
        let setup = Setup::owner(OrgUserStatus::Active);

        setup.change(setup.sam, OrgUserStatus::Locked).unwrap();

        assert!(setup.sessions.revoked(&setup.sam));
        assert!(setup.recorded("organization.org_user_status_changed"));
    }

    /// Sam waits to confirm his address on a deployment where no link can
    /// reach him. Olivia lets him in by hand: he is active, his address
    /// stays unconfirmed, and the change is recorded. Nothing here asks for
    /// mail, so it works the same with a mail server or without one.
    #[test]
    fn an_owner_lets_a_waiting_member_in_and_the_address_stays_unconfirmed() {
        let setup = Setup::waiting();

        setup.change(setup.sam, OrgUserStatus::Active).unwrap();

        let sam = block_on(setup.users.find_by_id(&setup.sam))
            .unwrap()
            .unwrap();
        assert_eq!(sam.status(), OrgUserStatus::Active);
        assert!(!sam.email_verified());
        assert!(setup.recorded("organization.org_user_status_changed"));
    }

    /// Olivia unlocks Sam. His status is active again and no session is
    /// touched.
    #[test]
    fn unlocking_a_member_leaves_their_sessions_alone() {
        let setup = Setup::owner(OrgUserStatus::Locked);

        setup.change(setup.sam, OrgUserStatus::Active).unwrap();

        assert_eq!(
            setup.users.get_status(&setup.sam),
            Some(OrgUserStatus::Active)
        );
        assert!(!setup.sessions.revoked(&setup.sam));
    }

    /// Deactivating the only owner conflicts, leaving her account active.
    #[test]
    fn deactivating_the_last_owner_is_refused() {
        let setup = Setup::owner(OrgUserStatus::Active);
        let olivia = *test_org_caller().member();

        let result = setup.change(olivia, OrgUserStatus::Deactivated);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.users.get_status(&olivia), Some(OrgUserStatus::Active));
    }

    /// A plain member cannot lock another member; the target's sessions
    /// are not revoked.
    #[test]
    fn a_member_without_the_update_right_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::in_role(OrgRole::Member),
            OrgUserStatus::Active,
        );

        let result = setup.change(setup.sam, OrgUserStatus::Locked);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!setup.sessions.revoked(&setup.sam));
    }

    /// An unknown member id returns not found and leaves Sam's sessions alone.
    #[test]
    fn a_member_of_another_organization_is_not_found() {
        let setup = Setup::owner(OrgUserStatus::Active);

        let result = setup.change(OrgUserId::new(), OrgUserStatus::Deactivated);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(!setup.sessions.revoked(&setup.sam));
    }

    /// A signed-out caller must authenticate before locking a member.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::refusing(Refusal::SignedOut),
            OrgUserStatus::Active,
        );

        let result = setup.change(setup.sam, OrgUserStatus::Locked);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents locking Sam.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::with(
            FakeOrgActors::refusing(Refusal::Forbidden),
            OrgUserStatus::Active,
        );

        let result = setup.change(setup.sam, OrgUserStatus::Locked);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
