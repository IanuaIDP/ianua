//! What a connection's group mapping gives a person at sign-in, and what it
//! takes back, for the groups their provider names for them now.
//!
//! Every sign-in through the connection brings the person in step with the
//! provider's word. First what the mapping gave them that no group of theirs
//! brings any more is taken back: the role revoked, the membership ended.
//! Then each role and group the mapping brings that they do not hold yet is
//! given, and noted on their holdings for the connection. A role or group
//! they hold already, given by a person, is left as it is and never noted,
//! so the mapping only ever takes back what it gave.
//!
//! The domain checks each grant again as it goes out, so a role or group
//! widened to a built-in permission after it was mapped is not given. A
//! grant the tenant's separation of duties forbids alongside what the
//! person holds is left out too. Either way the sign-in goes on without it.
//!
//! A SCIM directory keeps its own groups and ends a membership of one as
//! soon as it says so. What a connection's mapping gave rests on the
//! provider's word at sign-in, which SCIM never carries, so it is settled
//! at the person's next sign-in.

use ianua_domain::domains::authorization::group::{Group, GroupMembership, GroupPlace};
use ianua_domain::domains::authorization::group_tree::{Conferred, GroupTree};
use ianua_domain::domains::authorization::role::Role;
use ianua_domain::domains::authorization::role_assignment::RoleAssignment;
use ianua_domain::domains::federation::connection::{
    FederatedIdpConnection, MappedHoldings, MappedPerson, MappedWithdrawal, ProviderGroupName,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{EventLabel, GroupId, PrincipalRef, RoleId, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{
    AccessRecordStore, AccessRecords, GroupMembershipStore, Holders, RoleAssignmentStore,
    SeparationRuleStore,
};
use crate::ports::federation::MappedHoldingsStore;
use crate::services::authorization::duties::{DutySources, Granting};
use crate::services::authorization::provider_grants::duties_allow;
use crate::tenancy::ScopedTenant;
use crate::use_cases::authorization::holdings::lapsed::{RanOut, place_cleared, role_cleared};

/// Where the roles and groups a connection's mapping hands out are read and
/// recorded: who holds what, the tenant's separation rules, and what the
/// mapping gave each person.
pub(in crate::use_cases::authentication::federation) struct MappedAccess<'a> {
    /// Who holds what in the tenant, read for the person signing in.
    pub(in crate::use_cases::authentication::federation) records: &'a dyn AccessRecordStore,
    /// The tenant's separation rules.
    pub(in crate::use_cases::authentication::federation) rules: &'a dyn SeparationRuleStore,
    /// Records the roles given and taken back.
    pub(in crate::use_cases::authentication::federation) assignments: &'a dyn RoleAssignmentStore,
    /// Records the memberships given and ended.
    pub(in crate::use_cases::authentication::federation) memberships: &'a dyn GroupMembershipStore,
    /// What each connection's mapping gave each person.
    pub(in crate::use_cases::authentication::federation) holdings: &'a dyn MappedHoldingsStore,
}

/// A person signing in through a connection, and the groups their provider
/// names for them.
pub(in crate::use_cases::authentication::federation) struct GroupedArrival<'a> {
    /// The tenant signed in to.
    pub(in crate::use_cases::authentication::federation) tenant: &'a ScopedTenant,
    /// The connection signed in through.
    pub(in crate::use_cases::authentication::federation) connection:
        &'a FederatedIdpConnection<ResolvedTenant>,
    /// The account signed in to.
    pub(in crate::use_cases::authentication::federation) user: UserId,
    /// How the records name them, their address.
    pub(in crate::use_cases::authentication::federation) label: EventLabel,
    /// The groups the provider names for them.
    pub(in crate::use_cases::authentication::federation) groups: &'a [ProviderGroupName],
}

impl GroupedArrival<'_> {
    /// The person, as a holder of roles and groups.
    fn principal(&self) -> PrincipalRef {
        PrincipalRef::User(self.user)
    }

    /// The person's run-out hold looked for before a grant, named as the
    /// records name them.
    fn ran_out<'p>(&self, principal: &'p PrincipalRef) -> RanOut<'p> {
        RanOut {
            principal,
            label: self.label.clone(),
            now: clock::now(),
        }
    }
}

/// What bringing a person in step raised: the ends of holds that ran out
/// and the sweep had not cleared, which the platform records, and the rest,
/// which are the person's.
#[derive(Default)]
pub(in crate::use_cases::authentication::federation) struct Settled {
    /// The ends of run-out holds a fresh grant cleared, the platform's.
    pub(in crate::use_cases::authentication::federation) ended: Vec<DomainEvent>,
    /// What giving and taking back raised, the person's.
    pub(in crate::use_cases::authentication::federation) raised: Vec<DomainEvent>,
}

impl Settled {
    /// What only the person's changes raised.
    fn raised(raised: Vec<DomainEvent>) -> Self {
        Self {
            ended: Vec::new(),
            raised,
        }
    }

    /// Adds what `more` raised after what this raised.
    fn extend(&mut self, more: Self) {
        self.ended.extend(more.ended);
        self.raised.extend(more.raised);
    }
}

impl MappedAccess<'_> {
    /// Brings `arrival`'s person in step with the groups their provider
    /// names now: takes back what the mapping gave and no group of theirs
    /// brings any more, then gives what their groups bring and they do not
    /// hold. Returns what both raised, the withdrawals first, apart from the
    /// ends of run-out holds the grants cleared, which the platform records.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage failure, or records that name a
    ///   role or group that is not there.
    pub(in crate::use_cases::authentication::federation) async fn settle(
        &self,
        arrival: &GroupedArrival<'_>,
    ) -> Result<Settled, AppError> {
        let mut records = self.records_of(arrival).await?;
        let mut holdings = self.holdings_of(arrival).await?;
        let mut person = MappedPerson {
            holdings: &mut holdings,
            groups: arrival.groups,
            label: arrival.label.clone(),
        };
        let withdrawal = arrival
            .connection
            .mapped_withdrawal(&mut person)
            .map_err(AppError::from_domain)?;
        let mut raised = self
            .roles_taken_back(arrival, &mut records, &withdrawal)
            .await?;
        raised.extend(self.groups_left(arrival, &mut records, &withdrawal).await?);
        let mut settled = Settled::raised(raised);
        settled.extend(self.given(arrival, &records, &mut person).await?);
        self.holdings
            .save(arrival.tenant, &holdings)
            .await
            .or_internal()?;
        Ok(settled)
    }

    /// The share of the tenant's access records a sign-in weighs: the
    /// person's own assignments and memberships with the groups above, and
    /// the roles and groups their provider groups map to. Nobody else's
    /// records are read, so a sign-in costs the same in any size of tenant.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the records cannot be read.
    async fn records_of(&self, arrival: &GroupedArrival<'_>) -> Result<AccessRecords, AppError> {
        let grants = arrival.connection.mapped_grants(arrival.groups);
        let principal = arrival.principal();
        let holders = Holders {
            principals: std::slice::from_ref(&principal),
            groups: grants.groups(),
            roles: grants.roles(),
        };
        let held = self
            .records
            .load_held_by_all(arrival.tenant, holders)
            .await
            .or_internal()?;
        Ok(held.into_records())
    }

    /// What the connection's mapping gave `arrival`'s person so far, or
    /// nothing when it never gave them anything.
    async fn holdings_of(
        &self,
        arrival: &GroupedArrival<'_>,
    ) -> Result<MappedHoldings<ResolvedTenant>, AppError> {
        let connection_id = arrival.connection.id();
        let found = self
            .holdings
            .find(arrival.tenant, connection_id, &arrival.user)
            .await
            .or_internal()?;
        Ok(found.unwrap_or_else(|| MappedHoldings::none(*connection_id, arrival.user)))
    }

    /// Revokes each role `withdrawal` takes back that the person still
    /// holds, and returns what that raised.
    async fn roles_taken_back(
        &self,
        arrival: &GroupedArrival<'_>,
        records: &mut AccessRecords,
        withdrawal: &MappedWithdrawal<ResolvedTenant>,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let principal = arrival.principal();
        let mut raised = Vec::new();
        for role_id in withdrawal.roles() {
            let held = records
                .assignments
                .iter_mut()
                .find(|held| *held.principal() == principal && held.role_id() == role_id);
            let Some(assignment) = held else {
                continue;
            };
            let role = role_in(records.roles.as_slice(), role_id)?;
            withdrawal
                .take_role(assignment, role)
                .map_err(AppError::from_domain)?;
            self.assignments
                .delete(arrival.tenant, &principal, role_id)
                .await
                .or_internal()?;
            raised.extend(assignment.take_events(arrival.tenant));
        }
        Ok(raised)
    }

    /// Ends each membership `withdrawal` takes the person out of that they
    /// still hold, and returns what that raised.
    async fn groups_left(
        &self,
        arrival: &GroupedArrival<'_>,
        records: &mut AccessRecords,
        withdrawal: &MappedWithdrawal<ResolvedTenant>,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let principal = arrival.principal();
        let mut raised = Vec::new();
        for group_id in withdrawal.groups() {
            let held = records
                .memberships
                .iter_mut()
                .find(|held| *held.principal() == principal && held.group_id() == group_id);
            let Some(membership) = held else {
                continue;
            };
            let group = group_in(records.groups.as_slice(), group_id)?;
            withdrawal
                .take_group(membership, group)
                .map_err(AppError::from_domain)?;
            self.memberships
                .delete(arrival.tenant, &principal, group_id)
                .await
                .or_internal()?;
            raised.extend(membership.take_events(arrival.tenant));
        }
        Ok(raised)
    }

    /// Gives each role and group the person's provider groups bring, and
    /// returns what that raised.
    async fn given(
        &self,
        arrival: &GroupedArrival<'_>,
        records: &AccessRecords,
        person: &mut MappedPerson<'_, ResolvedTenant>,
    ) -> Result<Settled, AppError> {
        let grants = arrival.connection.mapped_grants(arrival.groups);
        let mut raised = Settled::default();
        for role_id in grants.roles() {
            raised.extend(self.role_given(arrival, records, role_id, person).await?);
        }
        for group_id in grants.groups() {
            raised.extend(
                self.group_joined(arrival, records, group_id, person)
                    .await?,
            );
        }
        Ok(raised)
    }

    /// Gives the person `role_id`, unless they hold it, it is gone, the
    /// tenant's separation of duties forbids it or the domain refuses it,
    /// and returns what giving it raised, with the end of a hold of it that
    /// ran out and the sweep had not cleared, cleared first.
    async fn role_given(
        &self,
        arrival: &GroupedArrival<'_>,
        records: &AccessRecords,
        role_id: &RoleId,
        person: &mut MappedPerson<'_, ResolvedTenant>,
    ) -> Result<Settled, AppError> {
        let (tenant, principal) = (arrival.tenant, arrival.principal());
        let held = self
            .assignments
            .exists(tenant, &principal, role_id)
            .await
            .or_internal()?;
        let Some(role) = records.roles.iter().find(|role| role.id() == role_id) else {
            return Ok(Settled::default());
        };
        let granting = Granting::Role {
            principal,
            role: role_id,
        };
        if held || !duties_allow(self.duties(), tenant, granting).await? {
            return Ok(Settled::default());
        }
        let assigned = arrival.connection.mapped_assignment(role, person);
        let Some(assignment) = left_out_when_refused(assigned) else {
            return Ok(Settled::default());
        };
        self.role_kept(arrival, role, assignment).await
    }

    /// Saves `assignment` over any hold of `role` that ran out, and returns
    /// the end of that hold and what the assignment raised.
    async fn role_kept(
        &self,
        arrival: &GroupedArrival<'_>,
        role: &Role<ResolvedTenant>,
        mut assignment: RoleAssignment<ResolvedTenant>,
    ) -> Result<Settled, AppError> {
        let (tenant, principal) = (arrival.tenant, arrival.principal());
        let ended =
            role_cleared(self.assignments, tenant, role, arrival.ran_out(&principal)).await?;
        self.assignments
            .save(tenant, &assignment)
            .await
            .or_internal()?;
        Ok(Settled {
            ended,
            raised: assignment.take_events(tenant),
        })
    }

    /// Puts the person in `group_id`, unless they sit in it, it is gone, the
    /// tenant's separation of duties forbids it or the domain refuses it,
    /// and returns what joining raised, with the end of a place in it that
    /// ran out and the sweep had not cleared, cleared first.
    async fn group_joined(
        &self,
        arrival: &GroupedArrival<'_>,
        records: &AccessRecords,
        group_id: &GroupId,
        person: &mut MappedPerson<'_, ResolvedTenant>,
    ) -> Result<Settled, AppError> {
        let (tenant, principal) = (arrival.tenant, arrival.principal());
        let sits = self
            .memberships
            .exists(tenant, &principal, group_id)
            .await
            .or_internal()?;
        let Some(group) = records.groups.iter().find(|group| group.id() == group_id) else {
            return Ok(Settled::default());
        };
        let conferred = conferred_by(records, group_id)?;
        let granting = Granting::Membership {
            principal,
            conferred: &conferred,
        };
        if sits || !duties_allow(self.duties(), tenant, granting).await? {
            return Ok(Settled::default());
        }
        let joined = arrival
            .connection
            .mapped_membership(group, &conferred, person);
        let Some(membership) = left_out_when_refused(joined) else {
            return Ok(Settled::default());
        };
        self.place_kept(arrival, group, membership).await
    }

    /// Saves `membership` over any place in `group` that ran out, and
    /// returns the end of that place and what the membership raised.
    async fn place_kept(
        &self,
        arrival: &GroupedArrival<'_>,
        group: &Group<ResolvedTenant>,
        mut membership: GroupMembership<ResolvedTenant>,
    ) -> Result<Settled, AppError> {
        let (tenant, principal) = (arrival.tenant, arrival.principal());
        let ended =
            place_cleared(self.memberships, tenant, group, arrival.ran_out(&principal)).await?;
        self.memberships
            .save(tenant, &membership)
            .await
            .or_internal()?;
        Ok(Settled {
            ended,
            raised: membership.take_events(tenant),
        })
    }

    /// The rules and records separation of duties is checked against.
    fn duties(&self) -> DutySources<'_> {
        DutySources::of(self.records, self.rules)
    }
}

/// The role with `role_id` among `roles`.
///
/// # Errors
///
/// - `AppError::Internal` when an assignment names a role that is not
///   there.
fn role_in<'r>(
    roles: &'r [Role<ResolvedTenant>],
    role_id: &RoleId,
) -> Result<&'r Role<ResolvedTenant>, AppError> {
    roles
        .iter()
        .find(|role| role.id() == role_id)
        .ok_or_else(|| AppError::internal_msg("an assignment names a role that is not there"))
}

/// The group with `group_id` among `groups`.
///
/// # Errors
///
/// - `AppError::Internal` when a membership names a group that is not
///   there.
fn group_in<'r>(
    groups: &'r [Group<ResolvedTenant>],
    group_id: &GroupId,
) -> Result<&'r Group<ResolvedTenant>, AppError> {
    groups
        .iter()
        .find(|group| group.id() == group_id)
        .ok_or_else(|| AppError::internal_msg("a membership names a group that is not there"))
}

/// What sitting in `group_id` brings, through the groups above it, by the
/// tenant's `records`.
///
/// # Errors
///
/// - `AppError::Domain` when the domain cannot work it out from the
///   records' group tree.
fn conferred_by(records: &AccessRecords, group_id: &GroupId) -> Result<Conferred, AppError> {
    GroupTree::new(&records.groups)
        .conferred(GroupPlace::Under(*group_id), &records.roles)
        .map_err(AppError::from_domain)
}

/// The grant `made`, or none when the domain refused it, with a warning:
/// a role or group widened to a built-in permission after it was mapped.
fn left_out_when_refused<G>(made: Result<G, DomainError>) -> Option<G> {
    match made {
        Ok(grant) => Some(grant),
        Err(refused) => {
            tracing::warn!(%refused, "a grant the provider's groups map to was left out");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole};
    use ianua_domain::domains::federation::connection::{
        GroupMapping, GroupRule, GroupRules, MappedGrant,
    };
    use ianua_domain::types::{ConnectionId, Expiry, Label};
    use time::Duration;

    use super::*;
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeGroupStore, FakeRoleAssignmentStore,
        FakeRoleStore, FakeSeparationRuleStore, separation_between, stored_assignment,
        stored_assignment_until, stored_group,
    };
    use crate::test_support::federation::{
        FakeMappedHoldings, test_saml_connection, test_saml_settings,
    };
    use crate::test_support::{block_on, test_ctx};

    fn role(name: &str, system_permissions: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: Label::new("name", name).unwrap(),
            system_permissions,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    /// The names of `events`, in order.
    fn names(events: &[DomainEvent]) -> Vec<String> {
        events
            .iter()
            .map(|event| event.event_type().as_str().to_owned())
            .collect()
    }

    fn team(name: &str) -> Group<ResolvedTenant> {
        stored_group(name, GroupPlace::TopLevel, Vec::new())
    }

    fn provider_group(name: &str) -> ProviderGroupName {
        ProviderGroupName::new(name).unwrap()
    }

    /// Okta's connection, mapping each of its groups named in `rules` to
    /// what it brings.
    fn okta(rules: Vec<(&str, MappedGrant)>) -> FederatedIdpConnection<ResolvedTenant> {
        let rules = rules
            .into_iter()
            .map(|(name, grant)| GroupRule {
                provider_group: provider_group(name),
                grant,
            })
            .collect();
        let rules = GroupRules::new(Label::new("claim", "groups").unwrap(), rules).unwrap();
        test_saml_connection(
            ConnectionId::new(),
            test_saml_settings(),
            GroupMapping::On(rules),
        )
    }

    /// Acme's records, which Ann's sign-ins read and write.
    struct Acme {
        sources: AccessSources,
        records: FakeAccessRecordStore,
        rules: FakeSeparationRuleStore,
        holdings: FakeMappedHoldings,
        ann: UserId,
    }

    impl Acme {
        fn holding(roles: Vec<Role<ResolvedTenant>>, groups: Vec<Group<ResolvedTenant>>) -> Self {
            let tenant = test_ctx().tenant_id();
            let sources = AccessSources {
                roles: Arc::new(FakeRoleStore::holding(tenant, roles)),
                assignments: Arc::new(FakeRoleAssignmentStore::empty()),
                groups: Arc::new(FakeGroupStore::holding(tenant, groups)),
                ..AccessSources::default()
            };
            Self {
                records: FakeAccessRecordStore::reading(sources.clone()),
                sources,
                rules: FakeSeparationRuleStore::empty(),
                holdings: FakeMappedHoldings::empty(),
                ann: UserId::new(),
            }
        }

        /// Ann, already given `role` by an admin.
        fn given_by_admin(self, role: &Role<ResolvedTenant>) -> Self {
            let held = stored_assignment(PrincipalRef::User(self.ann), *role.id());
            block_on(self.sources.assignments.save(&test_ctx().tenant(), &held)).unwrap();
            self
        }

        /// Ann signs in through `connection`, her provider naming `groups`.
        /// What the sign-in raised as hers, by name.
        fn sign_in(
            &self,
            connection: &FederatedIdpConnection<ResolvedTenant>,
            groups: &[&str],
        ) -> Vec<String> {
            names(&self.settled(connection, groups).raised)
        }

        /// What Ann's sign-in through `connection`, her provider naming
        /// `groups`, raised.
        fn settled(
            &self,
            connection: &FederatedIdpConnection<ResolvedTenant>,
            groups: &[&str],
        ) -> Settled {
            let tenant = test_ctx().tenant();
            let groups: Vec<ProviderGroupName> =
                groups.iter().map(|name| provider_group(name)).collect();
            let access = MappedAccess {
                records: &self.records,
                rules: &self.rules,
                assignments: self.sources.assignments.as_ref(),
                memberships: self.sources.memberships.as_ref(),
                holdings: &self.holdings,
            };
            let arrival = GroupedArrival {
                tenant: &tenant,
                connection,
                user: self.ann,
                label: EventLabel::of("ann@acme.test"),
                groups: &groups,
            };
            block_on(access.settle(&arrival)).unwrap()
        }

        fn holds(&self, role: &Role<ResolvedTenant>) -> bool {
            let ann = PrincipalRef::User(self.ann);
            let tenant = test_ctx().tenant();
            let held = self.sources.assignments.exists(&tenant, &ann, role.id());
            block_on(held).unwrap()
        }

        fn sits_in(&self, group: &GroupId) -> bool {
            let ann = PrincipalRef::User(self.ann);
            let tenant = test_ctx().tenant();
            let sits = self.sources.memberships.exists(&tenant, &ann, group);
            block_on(sits).unwrap()
        }
    }

    /// Okta says Ann is in `engineering`. She gets the Engineer role at
    /// sign-in, and not the role `ops` maps to.
    #[test]
    fn a_mapped_group_gives_its_role() {
        let (engineer, ops) = (role("Engineer", Vec::new()), role("Ops", Vec::new()));
        let connection = okta(vec![
            ("engineering", MappedGrant::Role(*engineer.id())),
            ("ops", MappedGrant::Role(*ops.id())),
        ]);
        let acme = Acme::holding(vec![engineer.clone(), ops.clone()], Vec::new());

        let raised = acme.sign_in(&connection, &["engineering"]);

        assert_eq!(raised, ["authorization.role_assigned"]);
        assert!(acme.holds(&engineer));
        assert!(!acme.holds(&ops));
    }

    /// Renewing Ann's expired Engineer assignment through a mapping returns
    /// separate expiry and grant events and leaves one active assignment.
    #[test]
    fn a_mapped_role_records_the_end_of_a_hold_that_ran_out() {
        let engineer = role("Engineer", Vec::new());
        let connection = okta(vec![("engineering", MappedGrant::Role(*engineer.id()))]);
        let acme = Acme::holding(vec![engineer.clone()], Vec::new());
        let ran_out = stored_assignment_until(
            PrincipalRef::User(acme.ann),
            *engineer.id(),
            Expiry::At(clock::now() - Duration::days(1)),
        );
        block_on(
            acme.sources
                .assignments
                .save(&test_ctx().tenant(), &ran_out),
        )
        .unwrap();

        let settled = acme.settled(&connection, &["engineering"]);

        assert_eq!(
            names(&settled.ended),
            ["authorization.role_assignment_expired"]
        );
        assert_eq!(names(&settled.raised), ["authorization.role_assigned"]);
        assert!(acme.holds(&engineer));
        assert_eq!(acme.sources.assignments.count(), 1);
    }

    /// Okta's `engineering` maps to the Backend group. Ann is put in it at
    /// sign-in.
    #[test]
    fn a_mapped_group_gives_its_membership() {
        let backend = team("Backend");
        let backend_id = *backend.id();
        let connection = okta(vec![("engineering", MappedGrant::Group(backend_id))]);
        let acme = Acme::holding(Vec::new(), vec![backend]);

        let raised = acme.sign_in(&connection, &["engineering"]);

        assert_eq!(raised, ["authorization.group_member_added"]);
        assert!(acme.sits_in(&backend_id));
    }

    /// When Okta stops naming `ops`, Ann's next sign-in removes the mapped
    /// role and group membership and raises both withdrawal events.
    #[test]
    fn what_the_provider_no_longer_brings_is_taken_back() {
        let ops = role("Ops", Vec::new());
        let oncall = team("On-call");
        let oncall_id = *oncall.id();
        let connection = okta(vec![
            ("ops", MappedGrant::Role(*ops.id())),
            ("ops", MappedGrant::Group(oncall_id)),
        ]);
        let acme = Acme::holding(vec![ops.clone()], vec![oncall]);
        acme.sign_in(&connection, &["ops"]);

        let raised = acme.sign_in(&connection, &["sales"]);

        assert_eq!(
            raised,
            [
                "authorization.role_revoked",
                "authorization.group_member_removed"
            ]
        );
        assert!(!acme.holds(&ops));
        assert!(!acme.sits_in(&oncall_id));
    }

    /// Okta says Ann is in `engineering`, which maps to the Engineer role
    /// and the Backend group. She gets both, and only her own share of
    /// Acme's records, with what the mapping names, is read for it.
    #[test]
    fn a_sign_in_reads_only_the_persons_records() {
        let engineer = role("Engineer", Vec::new());
        let backend = team("Backend");
        let backend_id = *backend.id();
        let connection = okta(vec![
            ("engineering", MappedGrant::Role(*engineer.id())),
            ("engineering", MappedGrant::Group(backend_id)),
        ]);
        let acme = Acme::holding(vec![engineer.clone()], vec![backend]);

        acme.sign_in(&connection, &["engineering"]);

        assert!(acme.holds(&engineer));
        assert!(acme.sits_in(&backend_id));
        assert_eq!(acme.records.whole_reads(), 0);
    }

    /// Ann still is in `ops`. Signing in again takes nothing back and gives
    /// nothing twice.
    #[test]
    fn a_grant_still_mapped_is_kept_as_it_is() {
        let ops = role("Ops", Vec::new());
        let connection = okta(vec![("ops", MappedGrant::Role(*ops.id()))]);
        let acme = Acme::holding(vec![ops.clone()], Vec::new());
        acme.sign_in(&connection, &["ops"]);

        let raised = acme.sign_in(&connection, &["ops"]);

        assert!(raised.is_empty());
        assert!(acme.holds(&ops));
    }

    /// An admin gave Ann the Ops role before Okta mapped `ops` to it. Okta
    /// drops her from `ops`; she keeps the role the mapping never gave.
    #[test]
    fn a_role_an_admin_gave_is_never_taken_back() {
        let ops = role("Ops", Vec::new());
        let connection = okta(vec![("ops", MappedGrant::Role(*ops.id()))]);
        let acme = Acme::holding(vec![ops.clone()], Vec::new()).given_by_admin(&ops);
        acme.sign_in(&connection, &["ops"]);

        let raised = acme.sign_in(&connection, &["sales"]);

        assert!(raised.is_empty());
        assert!(acme.holds(&ops));
    }

    /// A mapped role holding ManageUsers is omitted at sign-in without
    /// raising a grant event.
    #[test]
    fn a_role_widened_after_mapping_is_not_given() {
        let ops = role("Ops", vec![SystemPermission::ManageUsers]);
        let connection = okta(vec![("ops", MappedGrant::Role(*ops.id()))]);
        let acme = Acme::holding(vec![ops.clone()], Vec::new());

        let raised = acme.sign_in(&connection, &["ops"]);

        assert!(raised.is_empty());
        assert!(!acme.holds(&ops));
    }

    /// Ann's Requester role conflicts with the mapped Approver role, so
    /// sign-in omits the grant and raises no event.
    #[test]
    fn a_mapped_role_that_breaks_a_separation_is_left_out() {
        let (requester, approver) = (role("Requester", Vec::new()), role("Approver", Vec::new()));
        let connection = okta(vec![("finance", MappedGrant::Role(*approver.id()))]);
        let mut acme = Acme::holding(vec![requester.clone(), approver.clone()], Vec::new())
            .given_by_admin(&requester);
        let rule = separation_between("payments", &requester, &approver);
        acme.rules = FakeSeparationRuleStore::holding(test_ctx().tenant_id(), [rule]);

        let raised = acme.sign_in(&connection, &["finance"]);

        assert!(raised.is_empty());
        assert!(!acme.holds(&approver));
    }
}
