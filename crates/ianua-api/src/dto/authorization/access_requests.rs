//! Access request bodies: asking for a role or a place in a group for a
//! while, the request as it is read back with its answer, and the tenant's
//! limit on how long one may ask for.

use ianua_app::use_cases::authorization::access_requests::RequestAccessRequest;
use ianua_domain::domains::authorization::access_request::{
    AccessRequest, AskedAccess, RequestAnswer,
};
use ianua_domain::domains::authorization::request_policy::AccessRequestPolicy;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{AccessRequestId, GroupId, Lifetime, RoleId, Text};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::principal::OwnerDto;
use crate::error::ApiError;

/// What is asked for: a role, or a place in a group.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum AskedAccessBody {
    /// A role, given straight.
    Role {
        /// The role's id.
        id: Uuid,
    },
    /// A place in a group, with the roles it carries.
    Group {
        /// The group's id.
        id: Uuid,
    },
}

impl From<AskedAccessBody> for AskedAccess {
    fn from(body: AskedAccessBody) -> Self {
        match body {
            AskedAccessBody::Role { id } => Self::Role(RoleId::from_uuid(id)),
            AskedAccessBody::Group { id } => Self::Group(GroupId::from_uuid(id)),
        }
    }
}

impl From<AskedAccess> for AskedAccessBody {
    fn from(asked: AskedAccess) -> Self {
        match asked {
            AskedAccess::Role(role) => Self::Role {
                id: *role.as_uuid(),
            },
            AskedAccess::Group(group) => Self::Group {
                id: *group.as_uuid(),
            },
        }
    }
}

/// A request for access, made for the caller.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RequestAccessBody {
    /// The role or group asked for.
    pub asked: AskedAccessBody,
    /// Why it is needed, shown to whoever answers.
    pub reason: String,
    /// How long it is needed, in seconds from the approval. At most the
    /// tenant's limit, and never more than 30 days.
    pub length_seconds: i64,
}

impl TryFrom<RequestAccessBody> for RequestAccessRequest {
    type Error = ApiError;

    fn try_from(body: RequestAccessBody) -> Result<Self, Self::Error> {
        Ok(Self {
            asked: body.asked.into(),
            reason: Text::new("reason", body.reason).map_err(ApiError::validation)?,
            length: Lifetime::seconds(body.length_seconds).map_err(ApiError::validation)?,
        })
    }
}

/// An access request and where it stands.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AccessRequestResponse {
    /// The request's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: AccessRequestId,
    /// The account that asked.
    pub requester: OwnerDto,
    /// The role or group asked for.
    pub asked: AskedAccessBody,
    /// Why it is needed.
    pub reason: String,
    /// How long it is needed, in seconds from the approval.
    pub length_seconds: i64,
    /// `pending`, `approved`, `denied`, `cancelled` or `expired`.
    pub status: &'static str,
    /// The account that approved or denied it, absent until answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answered_by: Option<OwnerDto>,
    /// When it was answered, absent until then.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub answered_at: Option<OffsetDateTime>,
    /// When it was asked.
    #[serde(with = "time::serde::rfc3339")]
    pub requested_at: OffsetDateTime,
    /// When it runs out if nobody answers.
    #[serde(with = "time::serde::rfc3339")]
    pub answer_by: OffsetDateTime,
}

impl From<&AccessRequest<ResolvedTenant>> for AccessRequestResponse {
    fn from(request: &AccessRequest<ResolvedTenant>) -> Self {
        let (answered_by, answered_at) = match request.answer() {
            RequestAnswer::Unanswered => (None, None),
            RequestAnswer::By { approver, at } => (Some(OwnerDto::from_human(approver)), Some(*at)),
        };
        Self {
            id: *request.id(),
            requester: OwnerDto::from_human(request.requester()),
            asked: request.asked().into(),
            reason: request.reason().as_str().to_owned(),
            length_seconds: request.length().whole_seconds(),
            status: request.status().as_str(),
            answered_by,
            answered_at,
            requested_at: request.requested_at(),
            answer_by: request.answer_by(),
        }
    }
}

/// The tenant's limit on how long one may ask for access.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AccessRequestPolicyResponse {
    /// The longest a request may ask for, in seconds.
    pub longest_seconds: i64,
    /// When the limit last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<&AccessRequestPolicy<ResolvedTenant>> for AccessRequestPolicyResponse {
    fn from(policy: &AccessRequestPolicy<ResolvedTenant>) -> Self {
        Self {
            longest_seconds: policy.limits().longest().whole_seconds(),
            updated_at: policy.updated_at(),
        }
    }
}

/// A new limit on how long one may ask for access.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeAccessRequestPolicyBody {
    /// The longest a request may ask for, in seconds; at most 30 days.
    pub longest_seconds: i64,
}

impl TryFrom<ChangeAccessRequestPolicyBody> for Lifetime {
    type Error = ApiError;

    fn try_from(body: ChangeAccessRequestPolicyBody) -> Result<Self, Self::Error> {
        Self::seconds(body.longest_seconds).map_err(ApiError::validation)
    }
}
