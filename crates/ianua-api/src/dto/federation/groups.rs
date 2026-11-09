//! Group mapping bodies: which of a provider's groups give which roles and
//! groups here.

use ianua_app::use_cases::federation::connections::{GroupRuleRequest, MapProviderGroupsRequest};
use ianua_domain::domains::federation::connection::{
    GroupMapping, GroupRule, MappedGrant, ProviderGroupName,
};
use ianua_domain::types::{ConnectionId, GroupId, Label, RoleId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// What a provider group gives: `{"role": "<id>"}` or `{"group": "<id>"}`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MappedGrantBody {
    /// The role with this id.
    Role(Uuid),
    /// The group with this id.
    Group(Uuid),
}

impl From<MappedGrantBody> for MappedGrant {
    fn from(body: MappedGrantBody) -> Self {
        match body {
            MappedGrantBody::Role(id) => Self::Role(RoleId::from_uuid(id)),
            MappedGrantBody::Group(id) => Self::Group(GroupId::from_uuid(id)),
        }
    }
}

impl From<MappedGrant> for MappedGrantBody {
    fn from(grant: MappedGrant) -> Self {
        match grant {
            MappedGrant::Role(id) => Self::Role(*id.as_uuid()),
            MappedGrant::Group(id) => Self::Group(*id.as_uuid()),
        }
    }
}

/// One provider group and what it gives.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct GroupRuleBody {
    /// The group's name as the provider sends it.
    pub provider_group: String,
    /// What membership of it gives here.
    pub grant: MappedGrantBody,
}

impl TryFrom<GroupRuleBody> for GroupRuleRequest {
    type Error = ApiError;

    fn try_from(body: GroupRuleBody) -> Result<Self, ApiError> {
        Ok(Self {
            provider_group: ProviderGroupName::new(body.provider_group)
                .map_err(ApiError::validation)?,
            grant: body.grant.into(),
        })
    }
}

impl From<&GroupRule> for GroupRuleBody {
    fn from(rule: &GroupRule) -> Self {
        Self {
            provider_group: rule.provider_group.as_str().to_owned(),
            grant: rule.grant.into(),
        }
    }
}

/// A connection's group mapping: the claim the provider sends its groups
/// in, and what each group gives.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct GroupMappingBody {
    /// The claim or attribute that carries the provider's groups, such as
    /// `groups`.
    pub claim: String,
    /// One rule per provider group, one to two hundred.
    pub rules: Vec<GroupRuleBody>,
}

impl GroupMappingBody {
    /// The mapping as the dashboard shows it, or none while mapping is off.
    #[must_use]
    pub(crate) fn of(mapping: &GroupMapping) -> Option<Self> {
        let GroupMapping::On(rules) = mapping else {
            return None;
        };
        Some(Self {
            claim: rules.claim().as_str().to_owned(),
            rules: rules.rules().iter().map(GroupRuleBody::from).collect(),
        })
    }

    /// The mapping of `connection_id`'s provider groups this body asks for.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when the claim or a group name is not a
    ///   valid one.
    pub(crate) fn for_connection(
        self,
        connection_id: ConnectionId,
    ) -> Result<MapProviderGroupsRequest, ApiError> {
        Ok(MapProviderGroupsRequest {
            connection_id,
            claim: Label::new("claim", self.claim).map_err(ApiError::validation)?,
            rules: self
                .rules
                .into_iter()
                .map(GroupRuleRequest::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}
