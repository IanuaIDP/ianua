//! An owner handing the organization over to another member in one step.
//!
//! The heir becomes an owner and the owner who leaves stays on as an admin,
//! so the organization keeps exactly as many owners as it had. Only the
//! owner themselves, signed in, hands their ownership over. Both members'
//! sessions end, since the role they carry was read when they signed in.

use std::sync::Arc;

use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, OrgUserId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgSessionStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_held_member;
use crate::use_cases::organization::sign_in::sessions::sign_out::sign_out_member;

/// Who takes the organization over.
pub struct TransferOwnershipRequest {
    /// The member who becomes an owner in the caller's place.
    pub heir: OrgUserId,
}

/// The ports [`TransferOwnershipUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct TransferOwnershipPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Members' sessions, ended because they carry the old roles.
    pub org_sessions: Arc<dyn OrgSessionStore>,
}

/// Hands the caller's ownership of the organization to another member.
pub struct TransferOwnershipUseCase {
    ports: TransferOwnershipPorts,
}

/// Both members held in a stable order for one atomic handover.
struct HeldMembers {
    owner: OrgUser,
    heir: OrgUser,
}

impl TransferOwnershipUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: TransferOwnershipPorts) -> Self {
        Self { ports }
    }

    /// Holds both records in id order so competing handovers cannot use an
    /// already transferred ownership or deadlock while holding opposite ends.
    async fn held_members(
        &self,
        caller: &OrgCaller,
        heir: &OrgUserId,
    ) -> Result<HeldMembers, AppError> {
        let owner = caller.member();
        let (first, second) = if owner.as_uuid() <= heir.as_uuid() {
            (owner, heir)
        } else {
            (heir, owner)
        };
        let users = self.ports.org_users.as_ref();
        let organization = caller.organization_id();
        users.hold_ownership(&organization).await.or_internal()?;
        let first = existing_held_member(users, &organization, first).await?;
        let second = existing_held_member(users, &organization, second).await?;
        if first.id() == owner {
            return Ok(HeldMembers {
                owner: first,
                heir: second,
            });
        }
        Ok(HeldMembers {
            owner: second,
            heir: first,
        })
    }

    /// Ends the sessions of both members whose role changed.
    async fn sign_out_both(&self, owner: &OrgUserId, heir: &OrgUserId) -> Result<(), AppError> {
        let sessions = self.ports.org_sessions.as_ref();
        sign_out_member(sessions, owner).await?;
        sign_out_member(sessions, heir).await
    }
}

impl Command for TransferOwnershipUseCase {
    type Caller = OrgCaller;
    type Input = TransferOwnershipRequest;
    type Output = Result<(), AppError>;

    /// Makes `request.heir` an owner and the caller an admin, ends both
    /// members' sessions, and records `organization.org_user_role_changed`
    /// for each and `organization.ownership_transferred` once.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for a nonowner or key-based caller.
    /// - `AppError::NotFound` for a missing organization member; `Domain` for transfer to oneself.
    /// - `AppError::Conflict` for an inactive heir or existing owner; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: TransferOwnershipRequest,
    ) -> Result<(), AppError> {
        let (_, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let users = self.ports.org_users.as_ref();
        let HeldMembers {
            mut owner,
            mut heir,
        } = self.held_members(caller, &request.heir).await?;
        owner
            .hand_ownership_to(&mut heir, &control)
            .map_err(AppError::from_domain)?;
        users.save(&owner).await.or_internal()?;
        users.save(&heir).await.or_internal()?;
        self.sign_out_both(owner.id(), heir.id()).await?;
        let mut events = owner.take_events();
        events.extend(heir.take_events());
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), events)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::types::{OrganizationId, Scope};

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgUserStore, RecordingOrgSessionStore, org_user_store_with, stored_caller,
        test_org_member_at, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: TransferOwnershipUseCase,
        users: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn holding(actors: FakeOrgActors, members: Vec<OrgUser>) -> Self {
            let users = Arc::new(org_user_store_with(members));
            let sessions = Arc::new(RecordingOrgSessionStore::new());
            Self {
                uc: TransferOwnershipUseCase::new(TransferOwnershipPorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                    org_sessions: sessions.clone(),
                    ..TransferOwnershipPorts::fakes()
                }),
                users,
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn transfer(&self, heir: OrgUserId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                TransferOwnershipRequest { heir },
            ))
        }

        fn role_of(&self, member: &OrgUserId) -> OrgRole {
            block_on(self.users.find_by_id(member))
                .unwrap()
                .unwrap()
                .role()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn in_acme(email: &str, role: OrgRole) -> OrgUser {
        test_org_user(test_org_caller().organization_id(), email, role)
    }

    /// Olivia, the owner, and Sam, a member, as stored, with Olivia acting
    /// as `actors` says.
    fn olivia_and_sam(actors: FakeOrgActors, olivias_role: OrgRole) -> (Setup, OrgUserId) {
        let sam = in_acme("sam@acme.test", OrgRole::Member);
        let sam_id = *sam.id();
        let setup = Setup::holding(actors, vec![stored_caller(olivias_role, "pw"), sam]);
        (setup, sam_id)
    }

    /// Olivia hands Acme to Sam. He is the owner, she an admin, both their
    /// sessions end, and both role changes and the hand-over are recorded.
    #[test]
    fn an_owner_hands_the_organization_to_a_member() {
        let (setup, sam) = olivia_and_sam(FakeOrgActors::in_role(OrgRole::Owner), OrgRole::Owner);
        let olivia = *test_org_caller().member();

        setup.transfer(sam).unwrap();

        assert_eq!(setup.role_of(&sam), OrgRole::Owner);
        assert_eq!(setup.role_of(&olivia), OrgRole::Admin);
        assert!(setup.sessions.revoked(&sam));
        assert!(setup.sessions.revoked(&olivia));
        assert_eq!(
            setup.recorded(),
            [
                "organization.org_user_role_changed",
                "organization.org_user_role_changed",
                "organization.ownership_transferred",
            ]
        );
    }

    /// Stale owner authority cannot transfer a currently stored admin's
    /// role; the heir stays a member with sessions open and no audit record.
    #[test]
    fn stale_owner_authority_cannot_transfer_a_members_current_admin_role() {
        let (setup, sam) = olivia_and_sam(FakeOrgActors::in_role(OrgRole::Owner), OrgRole::Admin);

        let result = setup.transfer(sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.role_of(&sam), OrgRole::Member);
        assert!(!setup.sessions.revoked(&sam));
        assert!(setup.recorded().is_empty());
    }

    /// An admin cannot transfer ownership; Sam stays a member with sessions
    /// open and no handover is recorded.
    #[test]
    fn an_admin_cannot_hand_over_ownership() {
        let (setup, sam) = olivia_and_sam(FakeOrgActors::in_role(OrgRole::Admin), OrgRole::Admin);

        let result = setup.transfer(sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.role_of(&sam), OrgRole::Member);
        assert!(!setup.sessions.revoked(&sam));
        assert!(setup.recorded().is_empty());
    }

    /// A member-update API key cannot transfer ownership; the owner keeps
    /// her role and no handover is recorded.
    #[test]
    fn a_key_cannot_hand_over_ownership() {
        let scope = Scope::new("org:members:update").unwrap();
        let (setup, sam) = olivia_and_sam(
            FakeOrgActors::through_key(OrgRole::Owner, vec![scope]),
            OrgRole::Owner,
        );

        let result = setup.transfer(sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.role_of(test_org_caller().member()), OrgRole::Owner);
        assert!(setup.recorded().is_empty());
    }

    /// Another organization's member is not found as an heir and keeps
    /// her member role.
    #[test]
    fn a_member_of_another_organization_is_not_found() {
        let eve = test_org_user(OrganizationId::new(), "eve@other.test", OrgRole::Member);
        let eve_id = *eve.id();
        let setup = Setup::holding(
            FakeOrgActors::in_role(OrgRole::Owner),
            vec![stored_caller(OrgRole::Owner, "pw"), eve],
        );

        let result = setup.transfer(eve_id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.role_of(&eve_id), OrgRole::Member);
    }

    /// Olivia names Bob, whose account was deactivated. An inactive member
    /// takes nothing over, so it conflicts and Olivia stays the owner.
    #[test]
    fn an_inactive_heir_is_refused() {
        let bob = test_org_member_at(
            test_org_caller().organization_id(),
            "bob@acme.test",
            OrgUserStatus::Deactivated,
        );
        let bob_id = *bob.id();
        let setup = Setup::holding(
            FakeOrgActors::in_role(OrgRole::Owner),
            vec![stored_caller(OrgRole::Owner, "pw"), bob],
        );

        let result = setup.transfer(bob_id);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.role_of(test_org_caller().member()), OrgRole::Owner);
    }

    /// Olivia names herself as heir. It is refused as invalid.
    #[test]
    fn handing_ownership_to_oneself_is_refused() {
        let setup = Setup::holding(
            FakeOrgActors::in_role(OrgRole::Owner),
            vec![stored_caller(OrgRole::Owner, "pw")],
        );

        let result = setup.transfer(*test_org_caller().member());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A signed-out caller must authenticate before handing over ownership.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::holding(FakeOrgActors::refusing(Refusal::SignedOut), Vec::new());

        let result = setup.transfer(OrgUserId::new());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
