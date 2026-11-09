//! Create SCIM group: the directory makes a group it keeps, at the top of
//! the tree with no roles, and puts its users in it.
//!
//! What belonging grants stays the tenant's to set: a person gives the
//! group roles, or moves it under another, each checked there.

use std::sync::Arc;

use ianua_domain::domains::authorization::group::Group;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::UserId;

use crate::acting::ScimAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::ScimCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{GroupMembershipStore, GroupStore};
use crate::ports::federation::ScimStore;
use crate::ports::identity::UserStore;
use crate::ports::limits::{LimitEnforcer, PlanLimitsSource, ResourceKind};
use crate::services::limits::room::{PlanSources, ensure_room_for_tenant};
use crate::use_case::Command;
use crate::use_cases::scim::groups::cap::MemberCap;
use crate::use_cases::scim::groups::fields::{ScimGroup, ScimGroupFields};
use crate::use_cases::scim::groups::roster::{ensure_display_name_free, joined, tenant_users};
use crate::use_cases::scim::sync::record_synced;

/// The ports [`CreateScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreateScimPorts {
    /// Signs the directory in with its token.
    pub scim_authorities: Arc<dyn ScimAuthorities>,
    /// Records when the directory last synced.
    pub scim_store: Arc<dyn ScimStore>,
    /// Saves groups and finds names already taken.
    pub group_store: Arc<dyn GroupStore>,
    /// Saves who is in them.
    pub membership_store: Arc<dyn GroupMembershipStore>,
    /// Confirms each member is a user of the tenant.
    pub user_store: Arc<dyn UserStore>,
    /// Reads the tenant's plan.
    pub plan_limits: Arc<dyn PlanLimitsSource>,
    /// Holds the tenant to its plan's group limit.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
}

impl PlanSources for CreateScimPorts {
    fn plan_limits(&self) -> &dyn PlanLimitsSource {
        self.plan_limits.as_ref()
    }

    fn limit_enforcer(&self) -> &dyn LimitEnforcer {
        self.limit_enforcer.as_ref()
    }
}

/// Makes groups in a tenant for its directory.
pub struct CreateScimUseCase {
    ports: CreateScimPorts,
    cap: MemberCap,
}

impl CreateScimUseCase {
    /// A use case working through `ports`, making groups that name at most
    /// `cap` members.
    #[must_use]
    pub fn new(ports: CreateScimPorts, cap: MemberCap) -> Self {
        Self { ports, cap }
    }
}

impl Command for CreateScimUseCase {
    type Caller = ScimCaller;
    type Input = ScimGroupFields;
    type Output = Result<ScimGroup, AppError>;

    /// Makes the group `fields` describes with its users, records
    /// `authorization.group_created` and each member added by the system,
    /// and the sync.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the directory's token is missing,
    ///   not the tenant's current one, or SCIM is switched off.
    /// - `AppError::Forbidden` at the plan's group limit.
    /// - `AppError::Conflict` if a group already has the name.
    /// - `AppError::Domain` if a member is not a user of the tenant, or, as a
    ///   count refusal, when the group names more members than the cap
    ///   allows.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &ScimCaller,
        auditor: &RequestAuditor,
        fields: ScimGroupFields,
    ) -> Result<ScimGroup, AppError> {
        let ScimGroupFields { name, members } = fields;
        let tenant = caller.tenant();
        let endpoint = self.ports.scim_authorities.endpoint(caller).await?;
        self.cap.ensure_names(members.len())?;
        ensure_room_for_tenant(self.ports.plan_room(), tenant, ResourceKind::Groups).await?;
        let groups = self.ports.group_store.as_ref();
        ensure_display_name_free(groups, tenant, &name, None).await?;
        let members = distinct(members);
        let joining = tenant_users(self.ports.user_store.as_ref(), tenant, &members).await?;
        let mut group = Group::from_directory(name, &endpoint).map_err(AppError::from_domain)?;

        groups.save(tenant, &group).await.or_internal()?;
        let memberships = self.ports.membership_store.as_ref();
        let added = joined(memberships, tenant, &endpoint, &group, joining).await?;
        let events: Vec<_> = group.take_events(tenant).into_iter().chain(added).collect();
        record_synced(
            self.ports.scim_store.as_ref(),
            tenant,
            endpoint,
            auditor,
            events,
        )
        .await?;
        Ok(ScimGroup { group, members })
    }
}

/// `members` with each user once, in the order first named.
fn distinct(members: Vec<UserId>) -> Vec<UserId> {
    let mut seen = Vec::with_capacity(members.len());
    for member in members {
        if !seen.contains(&member) {
            seen.push(member);
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::GroupOrigin;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::types::{Label, TenantId};

    use super::*;
    use crate::test_support::authorization::{FakeGroupMembershipStore, FakeGroupStore};
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::scim::{
        SignInRefusal, kept_group, refused_sign_in, scim_caller, signed_in,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    struct Acme {
        groups: Arc<FakeGroupStore>,
        memberships: Arc<FakeGroupMembershipStore>,
        users: Arc<FakeUserStore>,
    }

    fn acme() -> Acme {
        Acme {
            groups: Arc::new(FakeGroupStore::empty()),
            memberships: Arc::new(FakeGroupMembershipStore::empty()),
            users: Arc::new(FakeUserStore::empty()),
        }
    }

    impl Acme {
        fn user(&self, email: &str) -> UserId {
            let id = UserId::new();
            self.users.add_active_user(id, email);
            id
        }

        fn ports(&self) -> CreateScimPorts {
            CreateScimPorts {
                scim_authorities: signed_in(),
                group_store: self.groups.clone(),
                membership_store: self.memberships.clone(),
                user_store: self.users.clone(),
                ..CreateScimPorts::fakes()
            }
        }

        fn create_with(
            &self,
            ports: CreateScimPorts,
            caller: &ScimCaller,
            members: Vec<UserId>,
        ) -> Result<ScimGroup, AppError> {
            self.create_capped(ports, MemberCap::default(), caller, members)
        }

        fn create_capped(
            &self,
            ports: CreateScimPorts,
            cap: MemberCap,
            caller: &ScimCaller,
            members: Vec<UserId>,
        ) -> Result<ScimGroup, AppError> {
            let use_case = CreateScimUseCase::new(ports, cap);
            let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
            let fields = ScimGroupFields {
                name: Label::new("displayName", "Engineering").unwrap(),
                members,
            };
            block_on(use_case.execute(caller, &auditor, fields))
        }

        fn create(&self, members: Vec<UserId>) -> Result<ScimGroup, AppError> {
            self.create_with(self.ports(), &scim_caller(), members)
        }
    }

    /// Okta makes Engineering with Ada and Grace in it. The directory keeps
    /// the group, and both are members.
    #[test]
    fn a_group_is_created_with_its_members() {
        let acme = acme();
        let ada = acme.user("ada@acme.com");
        let grace = acme.user("grace@acme.com");

        let created = acme.create(vec![ada, grace, ada]).unwrap();

        assert_eq!(created.group.origin(), GroupOrigin::Directory);
        assert_eq!(created.members, [ada, grace]);
        assert_eq!(acme.memberships.count(), 2);
    }

    /// Creating a group with three members under a cap of two returns a
    /// domain error without saving a group or memberships.
    #[test]
    fn a_group_naming_more_members_than_the_cap_is_refused() {
        let acme = acme();
        let members = vec![
            acme.user("ada@acme.com"),
            acme.user("grace@acme.com"),
            acme.user("alan@acme.com"),
        ];

        let result = acme.create_capped(
            acme.ports(),
            MemberCap::new(2).unwrap(),
            &scim_caller(),
            members,
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(acme.groups.count(), 0);
        assert_eq!(acme.memberships.count(), 0);
    }

    /// Okta makes Engineering, but Acme already has a group by that name.
    /// Nothing new is made.
    #[test]
    fn a_second_group_with_the_same_name_is_a_conflict() {
        let acme = Acme {
            groups: Arc::new(FakeGroupStore::holding(
                test_ctx().tenant_id(),
                [kept_group("Engineering", GroupOrigin::Dashboard)],
            )),
            ..acme()
        };

        let result = acme.create(Vec::new());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(acme.groups.count(), 1);
    }

    /// Creating a group with another tenant's user returns a domain error
    /// without saving the group.
    #[test]
    fn a_member_of_another_tenant_is_refused() {
        let acme = acme();
        let alan = UserId::new();
        acme.users.add_in(
            TenantId::new(),
            stored_user(alan, "alan@globex.com", UserStatus::Active),
        );

        let result = acme.create(vec![alan]);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(acme.groups.count(), 0);
    }

    /// Creating a group at the tenant's plan limit is forbidden and leaves
    /// the group store empty.
    #[test]
    fn a_group_is_refused_at_the_tenants_group_limit() {
        let acme = acme();
        let ports = CreateScimPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..acme.ports()
        };

        let result = acme.create_with(ports, &scim_caller(), Vec::new());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(acme.groups.count(), 0);
    }

    /// Missing, invalid or rotated tokens and disabled SCIM each return an
    /// unauthenticated error without creating a group.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        for refusal in SignInRefusal::ALL {
            let acme = acme();
            let (scim_authorities, caller) = refused_sign_in(refusal);
            let ports = CreateScimPorts {
                scim_authorities,
                ..acme.ports()
            };

            let result = acme.create_with(ports, &caller, Vec::new());

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
            assert_eq!(acme.groups.count(), 0);
        }
    }
}
