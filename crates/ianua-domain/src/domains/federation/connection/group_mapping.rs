//! Which of the tenant's roles and groups a provider's groups bring.
//!
//! Okta, Entra and Keycloak send the groups a person belongs to there. A
//! connection may map such a group to a role or a group here, so people
//! get it at sign-in and keep it in step with the provider. It is off until
//! an admin turns it on, and every role or group mapped is checked like a
//! grant: nothing with a built-in permission, and nothing the admin could
//! not hand out themselves.

use crate::domains::authorization::group::{GroupPlace, ensure_joined_automatically};
use crate::domains::authorization::group_tree::Conferred;
use crate::domains::authorization::role::Role;
use crate::domains::authorization::role_assignment::ensure_given_automatically;
use crate::domains::federation::control::FederationControl;
use crate::domains::federation::provider_values::ProviderValues;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::{first_repeat, without_repeats};
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{GroupId, Label, RoleId};

/// The most mapping rules one connection may hold.
const MAX_RULES: usize = 200;

/// The longest group name a provider may send.
const MAX_GROUP_NAME_BYTES: usize = 512;

text_value! {
    /// The name or id of a group at a provider, as its `groups` claim or
    /// attribute sends it, such as `engineering` or an Entra object id.
    pub struct ProviderGroupName;
}

impl TextValue for ProviderGroupName {
    const FIELD: &'static str = "provider_group";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_blank()
            .max_bytes(MAX_GROUP_NAME_BYTES)
            .no_control_chars()
            .no_invisible_chars()
    }
}

/// What a provider's group brings here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MappedGrant {
    /// Grants the named permission bundle directly to the signing-in account.
    Role(RoleId),
    /// Membership of this group, with the roles it and the groups above it
    /// hold.
    Group(GroupId),
}

/// One rule: members of a provider's group get this.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupRule {
    /// The provider's group.
    pub provider_group: ProviderGroupName,
    /// What its members get here.
    pub grant: MappedGrant,
}

/// The rules of a mapping, and the claim the provider sends groups in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRules {
    claim: Label,
    rules: Vec<GroupRule>,
}

impl GroupRules {
    /// The rules `rules`, read from the claim or attribute `claim`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when there is no rule, more than 200,
    ///   or one rule twice.
    pub fn new(claim: Label, rules: Vec<GroupRule>) -> Result<Self, DomainError> {
        validate_count("group_rules", rules.len(), 1..=MAX_RULES)?;
        if let Some(twice) = first_repeat(&rules) {
            return Err(DomainError::invalid(message!(
                "federation-the-rule-for-the-provider-group",
                format!(
                    "the rule for the provider group {} is listed twice",
                    twice.provider_group.as_str()
                )
            )));
        }
        Ok(Self { claim, rules })
    }

    /// The claim or attribute the provider sends groups in, such as
    /// `groups` or `memberOf`.
    #[must_use]
    pub fn claim(&self) -> &Label {
        &self.claim
    }

    /// The provider group values and local grants applied at sign-in.
    #[must_use]
    pub fn rules(&self) -> &[GroupRule] {
        &self.rules
    }
}

/// Whether a connection maps its provider's groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupMapping {
    /// The provider's groups bring nothing. The default: a provider that
    /// names groups hands out rights here only once an admin says so.
    Off,
    /// The provider's groups bring what these rules say.
    On(GroupRules),
}

impl GroupMapping {
    /// The groups the provider names in `sent`, under the mapping's claim:
    /// each value one group, as it was sent. A value that is no group name
    /// is dropped. Nothing while mapping is off.
    #[must_use]
    pub fn groups_sent(&self, sent: &ProviderValues) -> Vec<ProviderGroupName> {
        let Self::On(mapping) = self else {
            return Vec::new();
        };
        sent.values(mapping.claim.as_str())
            .iter()
            .filter_map(|name| ProviderGroupName::new(name.as_str()).ok())
            .collect()
    }

    /// What a person in the provider's `groups` gets here, each role and
    /// group once. Nothing while mapping is off.
    #[must_use]
    pub fn grants_for(&self, groups: &[ProviderGroupName]) -> MappedGrants {
        let Self::On(mapping) = self else {
            return MappedGrants::default();
        };
        let matched: Vec<MappedGrant> = mapping
            .rules
            .iter()
            .filter(|rule| groups.contains(&rule.provider_group))
            .map(|rule| rule.grant)
            .collect();
        MappedGrants {
            roles: without_repeats(
                matched
                    .iter()
                    .filter_map(|grant| match grant {
                        MappedGrant::Role(role) => Some(*role),
                        MappedGrant::Group(_) => None,
                    })
                    .collect(),
            ),
            groups: without_repeats(
                matched
                    .iter()
                    .filter_map(|grant| match grant {
                        MappedGrant::Group(group) => Some(*group),
                        MappedGrant::Role(_) => None,
                    })
                    .collect(),
            ),
        }
    }
}

/// The roles and groups a person's provider groups bring, each once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MappedGrants {
    roles: Vec<RoleId>,
    groups: Vec<GroupId>,
}

impl MappedGrants {
    /// The roles to give.
    #[must_use]
    pub fn roles(&self) -> &[RoleId] {
        &self.roles
    }

    /// The groups to put the person in.
    #[must_use]
    pub fn groups(&self) -> &[GroupId] {
        &self.groups
    }
}

/// What a provider group is mapped to, with what it carries, so it can be
/// checked against the person mapping it.
#[derive(Debug)]
pub enum GrantedThrough<'a, T: TenantScope> {
    /// A role, as it is now.
    Role(&'a Role<T>),
    /// A group, with what sitting in it brings across the tree.
    Group(&'a Conferred),
}

/// One rule an admin asks for: members of `provider_group` get `grant`.
#[derive(Debug)]
pub struct MappingRule<'a, T: TenantScope> {
    /// The provider's group.
    pub provider_group: ProviderGroupName,
    /// What its members get here.
    pub grant: GrantedThrough<'a, T>,
}

impl<T: TenantScope> MappingRule<'_, T> {
    /// The rule to keep, once `control` may have it given to everyone the
    /// provider puts in the group.
    pub(crate) fn checked(self, control: &FederationControl<'_>) -> Result<GroupRule, DomainError> {
        let grant = match self.grant {
            GrantedThrough::Role(role) => {
                ensure_given_automatically(role)?;
                control
                    .holds()
                    .ensure_may_hand_out(role.system_permissions(), role.custom_permissions())?;
                MappedGrant::Role(*role.id())
            }
            GrantedThrough::Group(conferred) => {
                MappedGrant::Group(group_given(conferred, control)?)
            }
        };
        Ok(GroupRule {
            provider_group: self.provider_group,
            grant,
        })
    }
}

/// The group `conferred` was worked out for, once `control` may put anyone
/// in it.
fn group_given(
    conferred: &Conferred,
    control: &FederationControl<'_>,
) -> Result<GroupId, DomainError> {
    let GroupPlace::Under(group) = conferred.place() else {
        return Err(DomainError::invalid(message!(
            "federation-the-top-of-the-group-tree",
            "the top of the group tree is no group"
        )));
    };
    ensure_joined_automatically(conferred)?;
    control.holds().ensure_may_give(&conferred.handout())?;
    Ok(group)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(name: &str) -> ProviderGroupName {
        ProviderGroupName::new(name).unwrap()
    }

    fn mapping(rules: Vec<GroupRule>) -> GroupMapping {
        GroupMapping::On(GroupRules::new(Label::new("claim", "groups").unwrap(), rules).unwrap())
    }

    /// Ann is in `engineering` and `oncall` at Okta. Both map to the
    /// "deployer" role and `engineering` to the Backend group too. She gets
    /// "deployer" once and Backend once.
    #[test]
    fn a_persons_provider_groups_bring_each_mapped_grant_once() {
        let (deployer, backend) = (RoleId::new(), GroupId::new());
        let mapping = mapping(vec![
            GroupRule {
                provider_group: group("engineering"),
                grant: MappedGrant::Role(deployer),
            },
            GroupRule {
                provider_group: group("oncall"),
                grant: MappedGrant::Role(deployer),
            },
            GroupRule {
                provider_group: group("engineering"),
                grant: MappedGrant::Group(backend),
            },
        ]);

        let grants = mapping.grants_for(&[group("engineering"), group("oncall")]);

        assert_eq!(grants.roles(), [deployer]);
        assert_eq!(grants.groups(), [backend]);
    }

    /// Bob is in `sales` only, which no rule names. He gets nothing.
    #[test]
    fn an_unmapped_provider_group_brings_nothing() {
        let mapping = mapping(vec![GroupRule {
            provider_group: group("engineering"),
            grant: MappedGrant::Role(RoleId::new()),
        }]);

        let grants = mapping.grants_for(&[group("sales")]);

        assert!(grants.roles().is_empty());
        assert!(grants.groups().is_empty());
    }

    /// A provider's admins group produces no local grants while group
    /// mapping is disabled.
    #[test]
    fn nothing_is_mapped_while_mapping_is_off() {
        let grants = GroupMapping::Off.grants_for(&[group("admins")]);

        assert_eq!(grants, MappedGrants::default());
    }

    /// The same rule twice, or no rule at all, is refused.
    #[test]
    fn a_rule_listed_twice_or_none_is_refused() {
        let rule = GroupRule {
            provider_group: group("engineering"),
            grant: MappedGrant::Role(RoleId::new()),
        };
        let claim = Label::new("claim", "groups").unwrap();

        let twice = GroupRules::new(claim.clone(), vec![rule.clone(), rule]);
        let none = GroupRules::new(claim, Vec::new());

        assert!(matches!(twice, Err(DomainError::Validation(_))));
        assert!(matches!(none, Err(DomainError::Validation(_))));
    }
}
