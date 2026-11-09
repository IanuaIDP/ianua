//! Changing the name a member is shown by: their own, or another member's
//! for an owner.

use std::sync::Arc;

use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, DisplayName, OrgUserId};

use crate::acting::OrgActors;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrgUserStore;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_member;

/// Whose name changes, and to what.
pub struct ChangeOrgUserDisplayNameRequest {
    /// The member renamed: the caller themselves, or another member.
    pub member: OrgUserId,
    /// The new name.
    pub display_name: DisplayName,
}

/// The ports [`ChangeOrgUserDisplayNameUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeOrgUserDisplayNamePorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
}

/// Renames a member.
pub struct ChangeOrgUserDisplayNameUseCase {
    ports: ChangeOrgUserDisplayNamePorts,
}

impl ChangeOrgUserDisplayNameUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: ChangeOrgUserDisplayNamePorts) -> Self {
        Self { ports }
    }
}

impl Command for ChangeOrgUserDisplayNameUseCase {
    type Caller = OrgCaller;
    type Input = ChangeOrgUserDisplayNameRequest;
    type Output = Result<(), AppError>;

    /// Gives `request.member` the new name and records
    /// `organization.org_user_display_name_changed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller renames someone else without
    ///   the right to update members, or an owner without being one.
    /// - `AppError::NotFound` when the organization has no such member.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: ChangeOrgUserDisplayNameRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let users = self.ports.org_users.as_ref();
        let mut member = existing_member(users, organization.id(), &request.member).await?;
        member
            .change_display_name(request.display_name, &control)
            .map_err(AppError::from_domain)?;
        users.save(&member).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), member.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::config::DomainLimits;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgUserStore, org_user_store_with, stored_caller, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: ChangeOrgUserDisplayNameUseCase,
        users: Arc<FakeOrgUserStore>,
        audit: Arc<FakeEventDispatcher>,
        owner: OrgUserId,
    }

    impl Setup {
        fn as_caller(actors: FakeOrgActors) -> Self {
            let organization_id = test_org_caller().organization_id();
            let owner = test_org_user(organization_id, "olivia@acme.test", OrgRole::Owner);
            let owner_id = *owner.id();
            let users = Arc::new(org_user_store_with([
                stored_caller(OrgRole::Member, "pw"),
                owner,
            ]));
            Self {
                uc: ChangeOrgUserDisplayNameUseCase::new(ChangeOrgUserDisplayNamePorts {
                    org_actors: Arc::new(actors),
                    org_users: users.clone(),
                }),
                users,
                audit: Arc::new(FakeEventDispatcher::new()),
                owner: owner_id,
            }
        }

        fn rename(&self, member: OrgUserId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_org_caller(),
                &test_auditor(self.audit.clone()),
                ChangeOrgUserDisplayNameRequest {
                    member,
                    display_name: name("New Name"),
                },
            ))
        }

        fn name_of(&self, member: OrgUserId) -> String {
            block_on(self.users.find_by_id(&member))
                .unwrap()
                .unwrap()
                .display_name()
                .as_str()
                .to_owned()
        }
    }

    fn name(value: &str) -> DisplayName {
        DisplayName::new(value, &DomainLimits::default().display_name).unwrap()
    }

    /// Sam, a plain member, renames himself. The name is saved and the
    /// change recorded.
    #[test]
    fn a_member_renames_themselves_and_it_is_recorded() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        setup.rename(*test_org_caller().member()).unwrap();

        assert_eq!(setup.name_of(*test_org_caller().member()), "New Name");
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_display_name_changed"]
        );
    }

    /// Olivia's co-owner renames her. An owner may edit an owner.
    #[test]
    fn an_owner_renames_another_owner() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        setup.rename(setup.owner).unwrap();

        assert_eq!(setup.name_of(setup.owner), "New Name");
    }

    /// A plain member cannot rename an owner; her name stays unchanged
    /// and no rename is recorded.
    #[test]
    fn a_member_renaming_an_owner_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Member));

        let result = setup.rename(setup.owner);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.name_of(setup.owner), "Someone");
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A member id the organization does not have is not found.
    #[test]
    fn an_unknown_member_is_not_found() {
        let setup = Setup::as_caller(FakeOrgActors::in_role(OrgRole::Owner));

        let result = setup.rename(OrgUserId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out caller must authenticate before changing a display name.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = setup.rename(*test_org_caller().member());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents changing a display name.
    #[test]
    fn a_caller_the_organization_turns_away_is_refused() {
        let setup = Setup::as_caller(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = setup.rename(*test_org_caller().member());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
