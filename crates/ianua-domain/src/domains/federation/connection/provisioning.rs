//! What the people a connection signs in are given: an account on their
//! first sign-in with its default role, and the roles and groups their
//! provider groups are mapped to.

use crate::domains::authorization::group::{Group, GroupMembership};
use crate::domains::authorization::group_tree::Conferred;
use crate::domains::authorization::role::Role;
use crate::domains::authorization::role_assignment::{RoleAssignment, ensure_given_automatically};
use crate::domains::federation::connection::FederatedIdpConnection;
use crate::domains::federation::connection::group_mapping::{
    GroupMapping, GroupRules, MappedGrant, MappedGrants, MappingRule, ProviderGroupName,
};
use crate::domains::federation::connection::mapped_holdings::{
    MappedHoldings, MappedPerson, MappedWithdrawal,
};
use crate::domains::federation::connection::settings::JitProvisioning;
use crate::domains::federation::control::{FederationControl, FederationRight};
use crate::domains::federation::provider_values::ProviderValues;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{GroupId, Label, RoleId, Setting, UserId};

impl<T: TenantScope> FederatedIdpConnection<T> {
    /// Creates an account on the first sign-in of someone the provider
    /// vouches for, giving it `default_role` when one is named.
    ///
    /// Every account made this way gets the role, so naming it is a grant
    /// to each of them: the person must be able to hand out what it carries.
    ///
    /// Raises `federation.connection_updated`, once per save however many
    /// settings change.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage
    ///   federation.
    /// - [`DomainError::Forbidden`] when the role carries a permission the
    ///   person may not hand out.
    /// - [`DomainError::Forbidden`] when the role carries a built-in
    ///   permission. Nobody chooses each person a provider or directory
    ///   creates, so admin rights are always given by a person.
    pub fn provision_new_accounts(
        &mut self,
        default_role: Setting<&Role<T>>,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::TrustConnection)?;
        self.jit_default_role_id = match default_role {
            Setting::Set(role) => {
                ensure_given_automatically(role)?;
                control
                    .holds()
                    .ensure_may_hand_out(role.system_permissions(), role.custom_permissions())?;
                Setting::Set(*role.id())
            }
            Setting::Unset => Setting::Unset,
        };
        self.jit_provisioning = JitProvisioning::Enabled;
        self.settings_changed();
        Ok(())
    }

    /// Refuses a sign-in that matches no account, and forgets the role new
    /// accounts were given. Raises `federation.connection_updated`, once per
    /// save however many settings change.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   connections.
    pub fn stop_provisioning(
        &mut self,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::EditConnection)?;
        self.jit_provisioning = JitProvisioning::Disabled;
        self.jit_default_role_id = Setting::Unset;
        self.settings_changed();
        Ok(())
    }

    /// Gives `user`, an account this connection just made, the role it
    /// gives new accounts.
    ///
    /// Only the role named as the default goes out this way. Without this
    /// check, any role could be recorded as given by the system, with no
    /// person checked for the right to hand it out.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `role` is not this connection's
    ///   role for new accounts.
    /// - [`DomainError::Forbidden`] when `role` carries a built-in
    ///   permission. A role given without a person choosing it holds
    ///   app permissions only.
    pub fn default_assignment(
        &self,
        user: UserId,
        role: &Role<T>,
    ) -> Result<RoleAssignment<T>, DomainError> {
        if self.jit_default_role_id.value() != Some(role.id()) {
            return Err(DomainError::forbidden(message!(
                "federation-this-role-is-not-the-one-2",
                "this role is not the one the connection gives new accounts"
            )));
        }
        RoleAssignment::by_provider(user, role)
    }

    /// Maps the provider's groups, sent in `claim`, to roles and groups
    /// here by `rules`, replacing any mapping before.
    ///
    /// Everyone the provider puts in a mapped group gets what it maps to,
    /// so each rule is a grant: nothing with a built-in permission, and
    /// nothing the person could not hand out themselves. It needs the full
    /// federation right. Raises `federation.connection_updated`, once per
    /// save however many settings change.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage
    ///   federation.
    /// - [`DomainError::Forbidden`] when a role or group carries a built-in
    ///   permission, or one the person may not hand out.
    /// - [`DomainError::Validation`] when a group is the top of the tree,
    ///   when no rule is given or more than 200, or a rule is given twice.
    pub fn map_provider_groups(
        &mut self,
        claim: Label,
        rules: Vec<MappingRule<'_, T>>,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::TrustConnection)?;
        let checked = rules
            .into_iter()
            .map(|rule| rule.checked(control))
            .collect::<Result<Vec<_>, _>>()?;
        self.group_mapping = GroupMapping::On(GroupRules::new(claim, checked)?);
        self.settings_changed();
        Ok(())
    }

    /// Stops mapping the provider's groups. What people were given through
    /// it is theirs until their next sign-in or sync takes it back. Raises
    /// `federation.connection_updated`, once per save however many settings
    /// change.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   connections.
    pub fn stop_mapping_groups(
        &mut self,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::EditConnection)?;
        self.group_mapping = GroupMapping::Off;
        self.settings_changed();
        Ok(())
    }

    /// Whether, and how, the provider's groups are mapped.
    #[must_use]
    pub fn group_mapping(&self) -> &GroupMapping {
        &self.group_mapping
    }

    /// Whether the connection hands out `role`: as the role new accounts
    /// are given, or through a group-mapping rule. A role it names must not
    /// be deleted, or the connection goes on handing out a role that is
    /// gone.
    #[must_use]
    pub fn names_role(&self, role: &RoleId) -> bool {
        self.jit_default_role_id() == Some(role)
            || self
                .mapped_targets()
                .any(|grant| grant == &MappedGrant::Role(*role))
    }

    /// Whether a group-mapping rule of the connection puts people in
    /// `group`, which must therefore not be deleted.
    #[must_use]
    pub fn names_group(&self, group: &GroupId) -> bool {
        self.mapped_targets()
            .any(|grant| grant == &MappedGrant::Group(*group))
    }

    /// What each group-mapping rule gives: nothing while mapping is off.
    fn mapped_targets(&self) -> impl Iterator<Item = &MappedGrant> {
        let rules = match &self.group_mapping {
            GroupMapping::Off => [].as_slice(),
            GroupMapping::On(rules) => rules.rules(),
        };
        rules.iter().map(|rule| &rule.grant)
    }

    /// The roles and groups a person in the provider's `groups` is given
    /// here, at sign-in or provisioning. Nothing while mapping is off.
    #[must_use]
    pub fn mapped_grants(&self, groups: &[ProviderGroupName]) -> MappedGrants {
        self.group_mapping.grants_for(groups)
    }

    /// The groups the provider names in `sent`, under the claim or
    /// attribute the mapping reads. Nothing while mapping is off.
    #[must_use]
    pub fn provider_groups(&self, sent: &ProviderValues) -> Vec<ProviderGroupName> {
        self.group_mapping.groups_sent(sent)
    }

    /// Gives `person` `role`, because the provider puts them in a group
    /// mapped to it, and notes on their holdings that the mapping gave it.
    /// Raises `authorization.role_assigned`, naming them by their label.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the holdings are another
    ///   connection's.
    /// - [`DomainError::Forbidden`] when none of the person's groups is
    ///   mapped to `role`.
    /// - [`DomainError::Forbidden`] when `role` has since been given a
    ///   built-in permission.
    pub fn mapped_assignment(
        &self,
        role: &Role<T>,
        person: &mut MappedPerson<'_, T>,
    ) -> Result<RoleAssignment<T>, DomainError> {
        self.ensure_holdings_of(person.holdings)?;
        if !self
            .mapped_grants(person.groups)
            .roles()
            .contains(role.id())
        {
            return Err(DomainError::forbidden(message!(
                "federation-none-of-the-provider-s-groups",
                "none of the provider's groups for this person is mapped to this role"
            )));
        }
        let user = *person.holdings.user_id();
        let assignment = RoleAssignment::by_group_mapping(user, role, person.label.clone())?;
        person.holdings.gave_role(*role.id());
        Ok(assignment)
    }

    /// Puts `person` in `group`, because the provider puts them in a group
    /// mapped to it, and notes on their holdings that the mapping did.
    /// Raises `authorization.group_member_added`, naming them by their
    /// label. `conferred` is what sitting in `group` brings now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the holdings are another
    ///   connection's.
    /// - [`DomainError::Forbidden`] when none of the person's groups is
    ///   mapped to `group`.
    /// - [`DomainError::Forbidden`] when `conferred` was worked out for
    ///   another group, or the group has since come to bring a built-in
    ///   permission.
    pub fn mapped_membership(
        &self,
        group: &Group<T>,
        conferred: &Conferred,
        person: &mut MappedPerson<'_, T>,
    ) -> Result<GroupMembership<T>, DomainError> {
        self.ensure_holdings_of(person.holdings)?;
        if !self
            .mapped_grants(person.groups)
            .groups()
            .contains(group.id())
        {
            return Err(DomainError::forbidden(message!(
                "federation-none-of-the-provider-s-groups-2",
                "none of the provider's groups for this person is mapped to this group"
            )));
        }
        let user = *person.holdings.user_id();
        let membership =
            GroupMembership::by_group_mapping(user, group, conferred, person.label.clone())?;
        person.holdings.gave_group(*group.id());
        Ok(membership)
    }

    /// What the mapping takes back from `person` at this sign-in: every
    /// role and group it gave them that none of the groups the provider
    /// puts them in now brings, taken off their holdings.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the holdings are another
    ///   connection's.
    pub fn mapped_withdrawal(
        &self,
        person: &mut MappedPerson<'_, T>,
    ) -> Result<MappedWithdrawal<T>, DomainError> {
        self.ensure_holdings_of(person.holdings)?;
        let now = self.mapped_grants(person.groups);
        Ok(person.holdings.withdraw(&now, person.label.clone()))
    }

    /// Refuses holdings another connection's mapping gave.
    fn ensure_holdings_of(&self, holdings: &MappedHoldings<T>) -> Result<(), DomainError> {
        if holdings.connection_id() != self.id() {
            return Err(DomainError::forbidden(message!(
                "federation-these-holdings-were-given-through-another",
                "these holdings were given through another connection"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::{GroupOrigin, GroupPlace, GroupRow};
    use crate::domains::authorization::group_tree::{Conferred, GroupTree};
    use crate::domains::authorization::permission::{
        FederationAction, SystemPermission, UserAction,
    };
    use crate::domains::authorization::role::{DefaultAssignment, NewRole};
    use crate::domains::federation::connection::group_mapping::GrantedThrough;
    use crate::domains::federation::connection::{EmailTrust, JitProvisioning};
    use crate::domains::federation::fixtures::{connection_for, federation_admin, holding};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{ConnectionId, EventLabel, GroupId, PrincipalRef, RoleId};

    fn role_granting(system: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("deployer"),
            system_permissions: system,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn okta() -> FederatedIdpConnection<ResolvedTenant> {
        connection_for("acme.com", EmailTrust::Unverified, JitProvisioning::Enabled)
    }

    fn group(name: &str) -> ProviderGroupName {
        ProviderGroupName::new(name).unwrap()
    }

    fn rule<'a>(
        provider_group: &str,
        grant: GrantedThrough<'a, ResolvedTenant>,
    ) -> MappingRule<'a, ResolvedTenant> {
        MappingRule {
            provider_group: group(provider_group),
            grant,
        }
    }

    /// Okta's connection, mapping `engineering` to `deployer`.
    fn mapping_engineering_to(
        deployer: &Role<ResolvedTenant>,
    ) -> FederatedIdpConnection<ResolvedTenant> {
        let mut conn = okta();
        conn.map_provider_groups(
            label("groups"),
            vec![rule("engineering", GrantedThrough::Role(deployer))],
            &federation_admin(),
        )
        .unwrap();
        conn
    }

    /// The Backend group, with id `id`, at the top of the tree, holding
    /// `roles`, and what sitting in it brings.
    fn backend(id: GroupId, roles: &[Role<ResolvedTenant>]) -> (Group<ResolvedTenant>, Conferred) {
        let now = crate::shared::clock::now();
        let group = Group::reconstitute(GroupRow {
            id,
            name: label("backend"),
            origin: GroupOrigin::Dashboard,
            place: GroupPlace::TopLevel,
            role_ids: roles.iter().map(|role| *role.id()).collect(),
            created_at: now,
            updated_at: now,
        })
        .unwrap();
        let groups = [group];
        let conferred = GroupTree::new(&groups)
            .conferred(GroupPlace::Under(*groups[0].id()), roles)
            .unwrap();
        let [group] = groups;
        (group, conferred)
    }

    /// Ann is in Okta's `engineering`, mapped to "deployer". She is given
    /// "deployer" by the provider, named by her address in the record, and
    /// her holdings note the mapping gave it.
    #[test]
    fn a_mapped_provider_group_brings_its_role_on_the_record() {
        let deployer = role_granting(Vec::new());
        let conn = mapping_engineering_to(&deployer);
        let ann = UserId::new();
        let mut holdings = MappedHoldings::none(*conn.id(), ann);
        let mut person = MappedPerson {
            holdings: &mut holdings,
            groups: &[group("engineering")],
            label: EventLabel::of("ann@acme.test"),
        };

        let mut given = conn.mapped_assignment(&deployer, &mut person).unwrap();
        let events = raised(&mut given);
        assert_eq!(given.principal(), &PrincipalRef::User(ann));
        assert_eq!(
            events[0].event_type().as_str(),
            "authorization.role_assigned"
        );
        assert!(matches!(
            events[0].payload().value("holder"),
            Some(FieldValue::Reference(holder)) if holder.label() == "ann@acme.test"
        ));
        assert_eq!(holdings.roles(), [*deployer.id()]);
    }

    /// Bob belongs to sales, so the engineering mapping cannot grant him the deployer role.
    #[test]
    fn an_unmapped_provider_group_cannot_grant_the_role() {
        let deployer = role_granting(Vec::new());
        let conn = mapping_engineering_to(&deployer);
        let mut bob_holdings = MappedHoldings::none(*conn.id(), UserId::new());
        let bob = conn.mapped_assignment(
            &deployer,
            &mut MappedPerson {
                holdings: &mut bob_holdings,
                groups: &[group("sales")],
                label: EventLabel::of("bob@acme.test"),
            },
        );
        assert!(matches!(bob, Err(DomainError::Forbidden(_))));
    }

    /// Okta drops Ann from `engineering`. At her next sign-in the deployer
    /// role the mapping gave her is taken back, and the record says so.
    #[test]
    fn a_role_the_provider_no_longer_brings_is_taken_back() {
        let deployer = role_granting(Vec::new());
        let conn = mapping_engineering_to(&deployer);
        let mut holdings = MappedHoldings::none(*conn.id(), UserId::new());
        let mut assignment = conn
            .mapped_assignment(
                &deployer,
                &mut MappedPerson {
                    holdings: &mut holdings,
                    groups: &[group("engineering")],
                    label: EventLabel::of("ann@acme.test"),
                },
            )
            .unwrap();

        let withdrawal = conn
            .mapped_withdrawal(&mut MappedPerson {
                holdings: &mut holdings,
                groups: &[],
                label: EventLabel::of("ann@acme.test"),
            })
            .unwrap();
        withdrawal.take_role(&mut assignment, &deployer).unwrap();

        assert_eq!(
            raised_names(&mut assignment),
            ["authorization.role_assigned", "authorization.role_revoked"]
        );
        assert!(holdings.roles().is_empty());
    }

    /// While Ann remains in engineering, her mapped deployer role is
    /// absent from the withdrawal and revoking it through that withdrawal
    /// is forbidden.
    #[test]
    fn a_role_still_mapped_is_never_taken_back() {
        let deployer = role_granting(Vec::new());
        let conn = mapping_engineering_to(&deployer);
        let mut holdings = MappedHoldings::none(*conn.id(), UserId::new());
        let mut person = MappedPerson {
            holdings: &mut holdings,
            groups: &[group("engineering")],
            label: EventLabel::of("ann@acme.test"),
        };
        let mut assignment = conn.mapped_assignment(&deployer, &mut person).unwrap();

        let withdrawal = conn.mapped_withdrawal(&mut person).unwrap();

        assert!(withdrawal.roles().is_empty());
        assert!(matches!(
            withdrawal.take_role(&mut assignment, &deployer),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Holdings associated with another connection cannot be used to
    /// assign a mapped role or obtain a withdrawal from Okta's connection.
    #[test]
    fn holdings_of_another_connection_are_refused() {
        let deployer = role_granting(Vec::new());
        let conn = mapping_engineering_to(&deployer);
        let mut elsewhere = MappedHoldings::none(ConnectionId::new(), UserId::new());
        let mut person = MappedPerson {
            holdings: &mut elsewhere,
            groups: &[group("engineering")],
            label: EventLabel::of("mallory@acme.test"),
        };

        assert!(conn.mapped_assignment(&deployer, &mut person).is_err());
        assert!(conn.mapped_withdrawal(&mut person).is_err());
    }

    /// Okta maps `engineering` to `deployer`: the connection names that
    /// role, so it may not be deleted, and names no other role or any
    /// group.
    #[test]
    fn a_connection_names_the_role_its_rules_hand_out() {
        let deployer = role_granting(Vec::new());

        let conn = mapping_engineering_to(&deployer);

        assert!(conn.names_role(deployer.id()));
        assert!(!conn.names_role(&RoleId::new()));
        assert!(!conn.names_group(&GroupId::new()));
        assert!(!okta().names_role(deployer.id()));
    }

    /// Okta maps `engineering` to the Backend group: the connection names
    /// that group, and no role.
    #[test]
    fn a_connection_names_the_group_its_rules_put_people_in() {
        let id = GroupId::new();
        let (_, conferred) = backend(id, &[]);
        let mut conn = okta();
        conn.map_provider_groups(
            label("groups"),
            vec![rule("engineering", GrantedThrough::Group(&conferred))],
            &federation_admin(),
        )
        .unwrap();

        assert!(conn.names_group(&id));
        assert!(!conn.names_group(&GroupId::new()));
        assert!(!conn.names_role(&RoleId::new()));
    }

    /// Okta's `engineering` maps to the Backend group. Ann is put in it,
    /// and the record says so.
    #[test]
    fn a_mapped_provider_group_brings_its_group() {
        let (team, conferred) = backend(GroupId::new(), &[role_granting(Vec::new())]);
        let mut conn = okta();
        conn.map_provider_groups(
            label("groups"),
            vec![rule("engineering", GrantedThrough::Group(&conferred))],
            &federation_admin(),
        )
        .unwrap();
        let mut holdings = MappedHoldings::none(*conn.id(), UserId::new());
        let mut person = MappedPerson {
            holdings: &mut holdings,
            groups: &[group("engineering")],
            label: EventLabel::of("ann@acme.test"),
        };

        let mut membership = conn
            .mapped_membership(&team, &conferred, &mut person)
            .unwrap();

        assert_eq!(
            raised_names(&mut membership),
            ["authorization.group_member_added"]
        );
        assert_eq!(holdings.groups(), [*team.id()]);
    }

    /// Giving the mapped Backend group a built-in permission forbids
    /// automatic membership and leaves the person's mapped groups empty.
    #[test]
    fn a_group_widened_after_mapping_is_not_joined() {
        let id = GroupId::new();
        let (_, as_mapped) = backend(id, &[]);
        let mut conn = okta();
        conn.map_provider_groups(
            label("groups"),
            vec![rule("engineering", GrantedThrough::Group(&as_mapped))],
            &federation_admin(),
        )
        .unwrap();
        let viewer = role_granting(vec![SystemPermission::Users(UserAction::View)]);
        let (team, widened) = backend(id, &[viewer]);
        let mut holdings = MappedHoldings::none(*conn.id(), UserId::new());

        let joined = conn.mapped_membership(
            &team,
            &widened,
            &mut MappedPerson {
                holdings: &mut holdings,
                groups: &[group("engineering")],
                label: EventLabel::of("ann@acme.test"),
            },
        );

        assert!(matches!(joined, Err(DomainError::Forbidden(_))));
        assert!(holdings.groups().is_empty());
    }

    /// Okta sends `groups` as two values. Both are read as groups, each
    /// whole.
    #[test]
    fn the_groups_are_read_from_the_mapped_claim() {
        let conn = mapping_engineering_to(&role_granting(Vec::new()));
        let sent = ProviderValues::new(std::collections::HashMap::from([(
            "groups".to_owned(),
            vec!["engineering".to_owned(), "cn=ops,dc=acme".to_owned()],
        )]));

        let groups = conn.provider_groups(&sent);

        assert_eq!(groups, [group("engineering"), group("cn=ops,dc=acme")]);
    }

    /// Even a federation administrator cannot map a provider group to a
    /// role with a built-in permission; group mapping remains disabled.
    #[test]
    fn a_role_with_a_built_in_permission_is_never_mapped() {
        let mut conn = okta();
        let viewer = role_granting(vec![SystemPermission::Users(UserAction::View)]);

        let result = conn.map_provider_groups(
            label("groups"),
            vec![rule("everyone", GrantedThrough::Role(&viewer))],
            &federation_admin(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(conn.group_mapping(), &GroupMapping::Off);
    }

    /// A connection editor is forbidden from mapping provider groups to
    /// local roles.
    #[test]
    fn mapping_groups_needs_the_full_right() {
        let mut conn = okta();
        let deployer = role_granting(Vec::new());
        let editor = [SystemPermission::Federation(FederationAction::Update)];

        let result = conn.map_provider_groups(
            label("groups"),
            vec![rule("engineering", GrantedThrough::Role(&deployer))],
            &holding(&editor),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// The top of the group tree is no group, so it cannot be mapped to.
    #[test]
    fn the_top_of_the_tree_is_not_a_group_to_map_to() {
        let mut conn = okta();
        let top = Conferred::at_top();

        let result = conn.map_provider_groups(
            label("groups"),
            vec![rule("engineering", GrantedThrough::Group(&top))],
            &federation_admin(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An editor stops mapping Okta's groups in an incident. Nobody is
    /// given anything through it from then on.
    #[test]
    fn stopping_the_mapping_brings_nothing() {
        let mut conn = okta();
        let deployer = role_granting(Vec::new());
        conn.map_provider_groups(
            label("groups"),
            vec![rule("engineering", GrantedThrough::Role(&deployer))],
            &federation_admin(),
        )
        .unwrap();
        let editor = [SystemPermission::Federation(FederationAction::Update)];

        conn.stop_mapping_groups(&holding(&editor)).unwrap();

        assert!(
            conn.mapped_grants(&[group("engineering")])
                .roles()
                .is_empty()
        );
    }
}
