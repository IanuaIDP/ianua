//! Update SCIM group: the directory renames a group it keeps and changes
//! who is in it.
//!
//! The changes are worked out together first, so the group ends as they
//! leave it in order, and every check runs before anything is written:
//! each new member is a user of the tenant who may sit in the group under
//! the tenant's separation of duties, and nobody leaving takes the last
//! administrator's rights with them.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::authorization::group::{Group, GroupMembership};
use ianua_domain::domains::federation::scim::ScimEndpoint;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{EventLabel, GroupId, Label, PrincipalRef, UserId};

use crate::acting::ScimAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::ScimCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{
    AccessRecordStore, GroupMembershipStore, GroupStore, SeparationRuleStore,
};
use crate::ports::federation::ScimStore;
use crate::ports::identity::UserStore;
use crate::services::authorization::duties::DutySources;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::scim::groups::cap::MemberCap;
use crate::use_cases::scim::groups::fields::{ScimGroup, ScimGroupChange};
use crate::use_cases::scim::groups::roster::{
    Member, Withdrawn, cleared_before_joining, directory_group, ensure_display_name_free,
    ensure_joining_keeps_duties, ensure_leaves_an_administrator, in_force, joined, member_labels,
    tenant_users, user_members,
};
use crate::use_cases::scim::sync::record_synced;

/// The changes a directory asks for, to which group.
pub struct UpdateScimRequest {
    /// The group being changed.
    pub group_id: GroupId,
    /// The changes, applied in order.
    pub changes: Vec<ScimGroupChange>,
}

/// The ports [`UpdateScimUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdateScimPorts {
    /// Signs the directory in with its token.
    pub scim_authorities: Arc<dyn ScimAuthorities>,
    /// Records when the directory last synced.
    pub scim_store: Arc<dyn ScimStore>,
    /// Loads and saves groups, and finds names already taken.
    pub group_store: Arc<dyn GroupStore>,
    /// Reads, saves and ends memberships.
    pub membership_store: Arc<dyn GroupMembershipStore>,
    /// Confirms each new member is a user of the tenant.
    pub user_store: Arc<dyn UserStore>,
    /// The tenant's records of who holds what, for its administrators and
    /// its separation of duties.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// The tenant's separation rules, which each new member is held to.
    pub separation_rules: Arc<dyn SeparationRuleStore>,
}

/// Renames groups a tenant's directory keeps, and changes who is in them.
pub struct UpdateScimUseCase {
    ports: UpdateScimPorts,
    cap: MemberCap,
}

/// The directory acting in one tenant.
struct Acting<'a> {
    tenant: &'a ScopedTenant,
    endpoint: &'a ScimEndpoint<ResolvedTenant>,
}

/// A group's changes once checked: what they leave it as, who leaves and
/// who joins.
struct Checked {
    planned: Planned,
    leaving: Vec<UserId>,
    joining: Vec<Member>,
}

/// What a group's changes, applied in order, leave it as.
struct Planned {
    name: Label,
    members: Vec<UserId>,
}

impl Planned {
    /// The group named `name` and holding `current`, once `changes` apply.
    fn of(name: &Label, current: &[UserId], changes: Vec<ScimGroupChange>) -> Self {
        let mut planned = Self {
            name: name.clone(),
            members: current.to_vec(),
        };
        for change in changes {
            planned.apply(change);
        }
        planned
    }

    fn apply(&mut self, change: ScimGroupChange) {
        match change {
            ScimGroupChange::Rename(name) => self.name = name,
            ScimGroupChange::AddMembers(joining) => self.add(joining),
            ScimGroupChange::RemoveMembers(leaving) => {
                self.members.retain(|member| !leaving.contains(member));
            }
            ScimGroupChange::ReplaceMembers(members) => {
                self.members.clear();
                self.add(members);
            }
        }
    }

    fn add(&mut self, joining: Vec<UserId>) {
        for member in joining {
            if !self.members.contains(&member) {
                self.members.push(member);
            }
        }
    }

    /// Who is in the group after the changes and not before.
    fn joining(&self, current: &[UserId]) -> Vec<UserId> {
        self.members
            .iter()
            .filter(|member| !current.contains(member))
            .copied()
            .collect()
    }

    /// Who was in the group before the changes and not after.
    fn leaving(&self, current: &[UserId]) -> Vec<UserId> {
        current
            .iter()
            .filter(|member| !self.members.contains(member))
            .copied()
            .collect()
    }
}

impl UpdateScimUseCase {
    /// A use case working through `ports`, taking writes that name at most
    /// `cap` members.
    #[must_use]
    pub fn new(ports: UpdateScimPorts, cap: MemberCap) -> Self {
        Self { ports, cap }
    }

    /// Renames `group`, ends the memberships of those leaving and adds those
    /// joining, as `checked` says, and gives back what that raised and the
    /// members the group is left with.
    async fn raised_by(
        &self,
        acting: &Acting<'_>,
        group: &mut Group<ResolvedTenant>,
        held: &mut [GroupMembership<ResolvedTenant>],
        checked: Checked,
    ) -> Result<(Vec<DomainEvent>, Vec<UserId>), AppError> {
        let Checked {
            planned,
            leaving,
            joining,
        } = checked;
        let mut events = self.renamed(acting, group, planned.name).await?;
        events.extend(self.left(acting, group, held, &leaving).await?);
        let memberships = self.ports.membership_store.as_ref();
        events.extend(cleared_before_joining(memberships, acting.tenant, group, &joining).await?);
        events.extend(joined(memberships, acting.tenant, acting.endpoint, group, joining).await?);
        Ok((events, planned.members))
    }

    /// The memberships `group` holds in force now, and what `changes` leave
    /// it as once checked. A place that ran out counts for nothing: a
    /// directory naming its member again gives a fresh one, and one no
    /// longer naming them leaves its end to the sweep.
    async fn held_and_checked(
        &self,
        tenant: &ScopedTenant,
        group: &Group<ResolvedTenant>,
        changes: Vec<ScimGroupChange>,
    ) -> Result<(Vec<GroupMembership<ResolvedTenant>>, Checked), AppError> {
        let held = self
            .ports
            .membership_store
            .find_by_group(tenant, group.id())
            .await
            .or_internal()?;
        let held = in_force(held);
        let checked = self
            .checked(tenant, group, &user_members(&held), changes)
            .await?;
        Ok((held, checked))
    }

    /// What `changes` leave `group`, holding `current`, as, once every new
    /// member is a user of the tenant who may sit in it under the tenant's
    /// separation of duties, and the members leaving leave it an
    /// administrator.
    async fn checked(
        &self,
        tenant: &ScopedTenant,
        group: &Group<ResolvedTenant>,
        current: &[UserId],
        changes: Vec<ScimGroupChange>,
    ) -> Result<Checked, AppError> {
        let planned = Planned::of(group.name(), current, changes);
        let leaving = planned.leaving(current);
        let users = self.ports.user_store.as_ref();
        let joining = tenant_users(users, tenant, &planned.joining(current)).await?;
        let records = self.ports.access_records.as_ref();
        let duties = DutySources::of(records, self.ports.separation_rules.as_ref());
        ensure_joining_keeps_duties(duties, tenant, group, &joining).await?;
        let withdrawn = Withdrawn {
            group: group.id(),
            leaving: &leaving,
        };
        ensure_leaves_an_administrator(records, tenant, withdrawn).await?;
        Ok(Checked {
            planned,
            leaving,
            joining,
        })
    }

    /// Renames `group` to `name`, or does nothing when it has that name.
    async fn renamed(
        &self,
        acting: &Acting<'_>,
        group: &mut Group<ResolvedTenant>,
        name: Label,
    ) -> Result<Vec<DomainEvent>, AppError> {
        if group.name() == &name {
            return Ok(Vec::new());
        }
        let groups = self.ports.group_store.as_ref();
        ensure_display_name_free(groups, acting.tenant, &name, Some(group.id())).await?;
        group
            .rename_by_directory(name, acting.endpoint)
            .map_err(AppError::from_domain)?;
        groups.save(acting.tenant, group).await.or_internal()?;
        Ok(group.take_events(acting.tenant))
    }

    /// Ends the membership in `group` of each of `leaving`, removing them
    /// together, and returns what each membership raised.
    async fn left(
        &self,
        acting: &Acting<'_>,
        group: &Group<ResolvedTenant>,
        held: &mut [GroupMembership<ResolvedTenant>],
        leaving: &[UserId],
    ) -> Result<Vec<DomainEvent>, AppError> {
        if leaving.is_empty() {
            return Ok(Vec::new());
        }
        let labels = member_labels(self.ports.user_store.as_ref(), acting.tenant, leaving).await?;
        let ending = Ending {
            group,
            endpoint: acting.endpoint,
            leaving,
            labels: &labels,
        };
        let ended = ending.ended(held)?;
        self.ports
            .membership_store
            .delete_all(acting.tenant, group.id(), &ended)
            .await
            .or_internal()?;
        Ok(held
            .iter_mut()
            .flat_map(|membership| membership.take_events(acting.tenant))
            .collect())
    }
}

/// The directory ending some members' place in a group.
struct Ending<'a> {
    group: &'a Group<ResolvedTenant>,
    endpoint: &'a ScimEndpoint<ResolvedTenant>,
    leaving: &'a [UserId],
    labels: &'a HashMap<UserId, EventLabel>,
}

impl Ending<'_> {
    /// Ends each membership among `held` that belongs to someone leaving,
    /// and returns who they were.
    fn ended(
        &self,
        held: &mut [GroupMembership<ResolvedTenant>],
    ) -> Result<Vec<PrincipalRef>, AppError> {
        let mut ended = Vec::with_capacity(self.leaving.len());
        for membership in held.iter_mut() {
            let PrincipalRef::User(user) = *membership.principal() else {
                continue;
            };
            if !self.leaving.contains(&user) {
                continue;
            }
            membership
                .end_by_directory(self.group, self.endpoint, self.label_of(&user))
                .map_err(AppError::from_domain)?;
            ended.push(PrincipalRef::User(user));
        }
        Ok(ended)
    }

    /// The address of `user`, or their id when the account is gone.
    fn label_of(&self, user: &UserId) -> EventLabel {
        self.labels
            .get(user)
            .cloned()
            .unwrap_or_else(|| EventLabel::of(&user.to_string()))
    }
}

impl Command for UpdateScimUseCase {
    type Caller = ScimCaller;
    type Input = UpdateScimRequest;
    type Output = Result<ScimGroup, AppError>;

    /// Applies `request.changes` to the group, records the rename and each
    /// member added or removed by the system, and the sync.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the directory's token is missing,
    ///   not the tenant's current one, or SCIM is switched off.
    /// - `AppError::NotFound` when the tenant has no such group, or a person
    ///   keeps it in the dashboard.
    /// - `AppError::Conflict` when another group has the new name, the
    ///   members leaving take the last administrator's rights away, or a
    ///   member joining would break one of the tenant's separation rules.
    /// - `AppError::Domain` when a new member is not a user of the tenant,
    ///   or, as a count refusal, when the changes name more members than
    ///   the cap allows.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &ScimCaller,
        auditor: &RequestAuditor,
        request: UpdateScimRequest,
    ) -> Result<ScimGroup, AppError> {
        let UpdateScimRequest { group_id, changes } = request;
        let tenant = caller.tenant();
        let endpoint = self.ports.scim_authorities.endpoint(caller).await?;
        self.cap.ensure_holds(&changes)?;
        let mut group = directory_group(self.ports.group_store.as_ref(), tenant, &group_id).await?;
        let (mut held, checked) = self.held_and_checked(tenant, &group, changes).await?;
        let acting = Acting {
            tenant,
            endpoint: &endpoint,
        };
        let (events, members) = self
            .raised_by(&acting, &mut group, &mut held, checked)
            .await?;
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

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::group::{GroupOrigin, GroupPlace, GroupRow};
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::authorization::role::Role;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::validation::ValidationError;
    use ianua_domain::types::{Expiry, RoleId, TenantId};
    use time::Duration;

    use super::*;
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupMembershipStore, FakeGroupStore,
        FakeRoleAssignmentStore, FakeRoleStore, FakeSeparationRuleStore, separation_between,
        stored_assignment, stored_membership, stored_membership_until, stored_role,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::scim::{
        SignInRefusal, kept_group, refused_sign_in, scim_caller, signed_in,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Acme {
        groups: Arc<FakeGroupStore>,
        memberships: Arc<FakeGroupMembershipStore>,
        users: Arc<FakeUserStore>,
        roles: Arc<FakeRoleStore>,
        sink: Arc<FakeEventDispatcher>,
        engineering: GroupId,
    }

    fn acme_with(engineering: Group<ResolvedTenant>) -> Acme {
        let id = *engineering.id();
        let tenant = test_ctx().tenant_id();
        Acme {
            groups: Arc::new(FakeGroupStore::holding(
                tenant,
                [engineering, kept_group("Sales", GroupOrigin::Directory)],
            )),
            memberships: Arc::new(FakeGroupMembershipStore::empty()),
            users: Arc::new(FakeUserStore::empty()),
            roles: Arc::new(FakeRoleStore::empty()),
            sink: Arc::new(FakeEventDispatcher::new()),
            engineering: id,
        }
    }

    fn acme() -> Acme {
        acme_with(kept_group("Engineering", GroupOrigin::Directory))
    }

    fn owners_group() -> (Group<ResolvedTenant>, FakeRoleStore) {
        let owner = stored_role("Owner", SystemPermission::all().to_vec(), Vec::new());
        let role_id: RoleId = *owner.id();
        let now = clock::now();
        let group = Group::reconstitute(GroupRow {
            id: GroupId::new(),
            name: Label::new("displayName", "Engineering").unwrap(),
            origin: GroupOrigin::Directory,
            place: GroupPlace::TopLevel,
            role_ids: vec![role_id],
            created_at: now,
            updated_at: now,
        })
        .unwrap();
        (
            group,
            FakeRoleStore::holding(test_ctx().tenant_id(), [owner]),
        )
    }

    impl Acme {
        fn member(&self, email: &str) -> UserId {
            let id = UserId::new();
            self.users.add_active_user(id, email);
            block_on(self.memberships.save(
                &test_ctx().tenant(),
                &stored_membership(PrincipalRef::User(id), self.engineering),
            ))
            .unwrap();
            id
        }

        fn user(&self, email: &str) -> UserId {
            let id = UserId::new();
            self.users.add_active_user(id, email);
            id
        }

        fn ports(&self) -> UpdateScimPorts {
            let sources = AccessSources {
                roles: self.roles.clone(),
                groups: self.groups.clone(),
                memberships: self.memberships.clone(),
                ..AccessSources::default()
            };
            UpdateScimPorts {
                scim_authorities: signed_in(),
                group_store: self.groups.clone(),
                membership_store: self.memberships.clone(),
                user_store: self.users.clone(),
                access_records: Arc::new(FakeAccessRecordStore::reading(sources)),
                ..UpdateScimPorts::fakes()
            }
        }

        /// Gives the user the requester role and separates it from the approver role.
        fn separating(
            &self,
            user: UserId,
            requester: &Role<ResolvedTenant>,
            approver: &Role<ResolvedTenant>,
        ) -> UpdateScimPorts {
            let tenant = test_ctx().tenant_id();
            let requesting = stored_assignment(PrincipalRef::User(user), *requester.id());
            let sources = AccessSources {
                roles: self.roles.clone(),
                assignments: Arc::new(FakeRoleAssignmentStore::holding(tenant, [requesting])),
                groups: self.groups.clone(),
                memberships: self.memberships.clone(),
                ..AccessSources::default()
            };
            let rule = separation_between("payments", requester, approver);
            UpdateScimPorts {
                access_records: Arc::new(FakeAccessRecordStore::reading(sources)),
                separation_rules: Arc::new(FakeSeparationRuleStore::holding(tenant, [rule])),
                ..self.ports()
            }
        }

        fn update_with(
            &self,
            ports: UpdateScimPorts,
            caller: &ScimCaller,
            changes: Vec<ScimGroupChange>,
        ) -> Result<ScimGroup, AppError> {
            self.update_capped(ports, MemberCap::default(), caller, changes)
        }

        fn update_capped(
            &self,
            ports: UpdateScimPorts,
            cap: MemberCap,
            caller: &ScimCaller,
            changes: Vec<ScimGroupChange>,
        ) -> Result<ScimGroup, AppError> {
            let use_case = UpdateScimUseCase::new(ports, cap);
            let auditor = test_auditor(self.sink.clone());
            let request = UpdateScimRequest {
                group_id: self.engineering,
                changes,
            };
            block_on(use_case.execute(caller, &auditor, request))
        }

        fn update(&self, changes: Vec<ScimGroupChange>) -> Result<ScimGroup, AppError> {
            self.update_with(self.ports(), &scim_caller(), changes)
        }

        fn members(&self) -> Vec<UserId> {
            let held = block_on(
                self.memberships
                    .find_by_group(&test_ctx().tenant(), &self.engineering),
            )
            .unwrap();
            user_members(&held)
        }
    }

    fn name(text: &str) -> Label {
        Label::new("displayName", text).unwrap()
    }

    /// Okta makes Grace and Alan Engineering's whole team. Ada leaves, Grace
    /// stays, Alan joins.
    #[test]
    fn replacing_members_leaves_exactly_the_new_ones() {
        let acme = acme();
        acme.member("ada@acme.com");
        let grace = acme.member("grace@acme.com");
        let alan = acme.user("alan@acme.com");

        let updated = acme
            .update(vec![ScimGroupChange::ReplaceMembers(vec![grace, alan])])
            .unwrap();

        assert_eq!(updated.members, [grace, alan]);
        assert_eq!(acme.members(), [grace, alan]);
    }

    /// Okta adds Grace to Engineering and takes Ada out, in one call. The
    /// group ends with Grace alone.
    #[test]
    fn members_are_added_and_removed_in_order() {
        let acme = acme();
        let ada = acme.member("ada@acme.com");
        let grace = acme.user("grace@acme.com");

        acme.update(vec![
            ScimGroupChange::AddMembers(vec![grace]),
            ScimGroupChange::RemoveMembers(vec![ada]),
        ])
        .unwrap();

        assert_eq!(acme.members(), [grace]);
    }

    /// Okta takes Ada and Grace out of Engineering in one call. Both leave,
    /// and each leaving is recorded.
    #[test]
    fn members_leave_together_and_each_is_recorded() {
        let acme = acme();
        let ada = acme.member("ada@acme.com");
        let grace = acme.member("grace@acme.com");

        acme.update(vec![ScimGroupChange::RemoveMembers(vec![ada, grace])])
            .unwrap();

        assert!(acme.members().is_empty());
        let removed = acme
            .sink
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|kind| kind.as_str() == "authorization.group_member_removed")
            .count();
        assert_eq!(removed, 2);
    }

    /// Okta adds Grace and Alan to Engineering in one call. Both join.
    #[test]
    fn members_join_together() {
        let acme = acme();
        let grace = acme.user("grace@acme.com");
        let alan = acme.user("alan@acme.com");

        acme.update(vec![ScimGroupChange::AddMembers(vec![grace, alan])])
            .unwrap();

        assert_eq!(acme.members(), [grace, alan]);
    }

    /// Adding a user whose stored membership expired restores their place
    /// and records the old membership's expiry before the new membership.
    #[test]
    fn a_member_whose_place_ran_out_is_added_again_and_the_end_recorded() {
        let acme = acme();
        let ada = acme.user("ada@acme.com");
        let ran_out = stored_membership_until(
            PrincipalRef::User(ada),
            acme.engineering,
            Expiry::At(clock::now() - Duration::days(1)),
        );
        block_on(acme.memberships.save(&test_ctx().tenant(), &ran_out)).unwrap();

        acme.update(vec![ScimGroupChange::AddMembers(vec![ada])])
            .unwrap();

        assert_eq!(acme.members(), [ada]);
        let records = acme.sink.records.lock().unwrap().clone();
        let expired = records
            .iter()
            .position(|name| name == "authorization.group_membership_expired");
        let added = records
            .iter()
            .position(|name| name == "authorization.group_member_added");
        assert!(expired.is_some() && expired < added, "{records:?}");
    }

    /// Adding three members under a cap of two returns the count validation
    /// error and leaves the group empty.
    #[test]
    fn a_write_naming_more_members_than_the_cap_is_refused() {
        let acme = acme();
        let joining = vec![
            acme.user("ada@acme.com"),
            acme.user("grace@acme.com"),
            acme.user("alan@acme.com"),
        ];

        let result = acme.update_capped(
            acme.ports(),
            MemberCap::new(2).unwrap(),
            &scim_caller(),
            vec![ScimGroupChange::AddMembers(joining)],
        );

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(
                ValidationError::Count {
                    max: 2,
                    actual: 3,
                    ..
                }
            )))
        ));
        assert!(acme.members().is_empty());
    }

    /// Okta renames Engineering to Platform. The group carries the new name.
    #[test]
    fn a_group_is_renamed() {
        let acme = acme();

        let updated = acme
            .update(vec![ScimGroupChange::Rename(name("Platform"))])
            .unwrap();

        assert_eq!(updated.group.name().as_str(), "Platform");
    }

    /// Adding a requester to a group granting the separated approver role
    /// returns a conflict and leaves the group empty.
    #[test]
    fn a_member_who_would_break_a_separation_is_refused() {
        let tenant = test_ctx().tenant_id();
        let requester = stored_role("Requester", Vec::new(), Vec::new());
        let approver = stored_role("Approver", Vec::new(), Vec::new());
        let now = clock::now();
        let engineering = Group::reconstitute(GroupRow {
            id: GroupId::new(),
            name: name("Engineering"),
            origin: GroupOrigin::Directory,
            place: GroupPlace::TopLevel,
            role_ids: vec![*approver.id()],
            created_at: now,
            updated_at: now,
        })
        .unwrap();
        let acme = Acme {
            roles: Arc::new(FakeRoleStore::holding(
                tenant,
                [requester.clone(), approver.clone()],
            )),
            ..acme_with(engineering)
        };
        let ada = acme.user("ada@acme.com");
        let ports = acme.separating(ada, &requester, &approver);

        let result = acme.update_with(
            ports,
            &scim_caller(),
            vec![ScimGroupChange::AddMembers(vec![ada])],
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(acme.members().is_empty());
    }

    /// Okta renames Engineering to Sales, a name Acme already uses. It is a
    /// conflict, and Engineering keeps its name.
    #[test]
    fn renaming_onto_another_groups_name_is_a_conflict() {
        let acme = acme();

        let result = acme.update(vec![ScimGroupChange::Rename(name("Sales"))]);

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Adding another tenant's user returns a domain error and leaves the
    /// group empty.
    #[test]
    fn a_member_of_another_tenant_is_refused() {
        let acme = acme();
        let alan = UserId::new();
        acme.users.add_in(
            TenantId::new(),
            stored_user(alan, "alan@globex.com", UserStatus::Active),
        );

        let result = acme.update(vec![ScimGroupChange::AddMembers(vec![alan])]);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(acme.members().is_empty());
    }

    /// Adding a member to a group maintained through the dashboard returns
    /// not found to the directory and leaves the group empty.
    #[test]
    fn a_group_the_directory_does_not_keep_is_not_found() {
        let acme = acme_with(kept_group("Admins", GroupOrigin::Dashboard));
        let mallory = acme.user("mallory@acme.com");

        let result = acme.update(vec![ScimGroupChange::AddMembers(vec![mallory])]);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(acme.members().is_empty());
    }

    /// Removing the sole administrator from the group granting their owner
    /// role returns a conflict and preserves their membership.
    #[test]
    fn the_last_administrator_does_not_leave() {
        let (owners, roles) = owners_group();
        let acme = Acme {
            roles: Arc::new(roles),
            ..acme_with(owners)
        };
        let ada = acme.member("ada@acme.com");

        let result = acme.update(vec![ScimGroupChange::RemoveMembers(vec![ada])]);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(acme.members(), [ada]);
    }

    /// Missing, invalid or rotated tokens and disabled SCIM each return an
    /// unauthenticated error and preserve the member being removed.
    #[test]
    fn a_directory_that_is_not_signed_in_is_refused() {
        for refusal in SignInRefusal::ALL {
            let acme = acme();
            let ada = acme.member("ada@acme.com");
            let (scim_authorities, caller) = refused_sign_in(refusal);
            let ports = UpdateScimPorts {
                scim_authorities,
                ..acme.ports()
            };

            let result = acme.update_with(
                ports,
                &caller,
                vec![ScimGroupChange::RemoveMembers(vec![ada])],
            );

            assert!(
                matches!(result, Err(AppError::Unauthenticated)),
                "{refusal:?}"
            );
            assert_eq!(acme.members(), [ada]);
        }
    }
}
