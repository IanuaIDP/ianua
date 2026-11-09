//! Relationship bodies: a fact about one object of the tenant's app,
//! either that someone holds a relation on it or that it sits under
//! another object.

use ianua_domain::domains::authorization::permission::PermissionSegment;
use ianua_domain::domains::authorization::relationship::{
    NewRelationship, ObjectKey, ObjectRef, RelationLink, RelationSubject, Relationship,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{GroupId, PrincipalRef, RelationshipId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::principal::PrincipalKind;
use crate::error::ApiError;

/// One object of the tenant's app: its resource type and its key there.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ObjectBody {
    /// The declared resource type, such as `document`.
    pub resource_type: String,
    /// The object's key in the app, such as `42`.
    pub key: String,
}

impl ObjectBody {
    /// The object this body names.
    ///
    /// # Errors
    ///
    /// A validation error when the type or the key is not valid.
    pub(crate) fn object(&self) -> Result<ObjectRef, ApiError> {
        object_ref(&self.resource_type, &self.key)
    }
}

/// The object of type `resource_type` keyed `key` in the tenant's app.
///
/// # Errors
///
/// A validation error when the type or the key is not valid.
pub fn object_ref(resource_type: &str, key: &str) -> Result<ObjectRef, ApiError> {
    Ok(ObjectRef::new(
        PermissionSegment::new("resource_type", resource_type).map_err(ApiError::validation)?,
        ObjectKey::new(key).map_err(ApiError::validation)?,
    ))
}

impl From<&ObjectRef> for ObjectBody {
    fn from(object: &ObjectRef) -> Self {
        Self {
            resource_type: object.resource_type().as_str().to_owned(),
            key: object.key().as_str().to_owned(),
        }
    }
}

/// The kind of subject that holds a relation: a principal, or a group,
/// whose members all hold it.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SubjectKind {
    /// A tenant user.
    User,
    /// A member acting from the organization's management plane.
    OrgUser,
    /// An automated actor registered in the tenant.
    Agent,
    /// An external app or service acting with its own credential.
    Consumer,
    /// A membership set whose members share the relation.
    Group,
}

impl SubjectKind {
    /// The subject of this kind with `id`.
    #[must_use]
    pub(crate) fn with_id(self, id: Uuid) -> RelationSubject {
        let principal = match self {
            Self::Group => return RelationSubject::Group(GroupId::from_uuid(id)),
            Self::User => PrincipalKind::User,
            Self::OrgUser => PrincipalKind::OrgUser,
            Self::Agent => PrincipalKind::Agent,
            Self::Consumer => PrincipalKind::Consumer,
        };
        RelationSubject::Principal(principal.with_id(id))
    }
}

/// Who holds a relation: a principal or a group.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct SubjectBody {
    /// The kind of subject.
    pub kind: SubjectKind,
    /// The UUID of the account or group identified by `kind`.
    pub id: Uuid,
}

impl From<&SubjectBody> for RelationSubject {
    fn from(body: &SubjectBody) -> Self {
        body.kind.with_id(body.id)
    }
}

impl From<RelationSubject> for SubjectBody {
    fn from(subject: RelationSubject) -> Self {
        match subject {
            RelationSubject::Group(group) => Self {
                kind: SubjectKind::Group,
                id: *group.as_uuid(),
            },
            RelationSubject::Principal(principal) => Self {
                kind: principal_kind(principal),
                id: principal.id(),
            },
        }
    }
}

/// The subject kind of `principal`.
fn principal_kind(principal: PrincipalRef) -> SubjectKind {
    match PrincipalKind::of(&principal) {
        PrincipalKind::User => SubjectKind::User,
        PrincipalKind::OrgUser => SubjectKind::OrgUser,
        PrincipalKind::Agent => SubjectKind::Agent,
        PrincipalKind::Consumer => SubjectKind::Consumer,
    }
}

/// How the object is related: someone holds a relation on it, or it sits
/// under a parent object whose relations reach it.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinkBody {
    /// `subject` holds `relation` on the object.
    Holds {
        /// One of the actions the object's resource type declares, such as
        /// `viewer`.
        relation: String,
        /// Who holds it.
        subject: SubjectBody,
    },
    /// The object sits under this parent.
    Under(ObjectBody),
}

impl TryFrom<&LinkBody> for RelationLink {
    type Error = ApiError;

    fn try_from(body: &LinkBody) -> Result<Self, Self::Error> {
        match body {
            LinkBody::Holds { relation, subject } => Ok(Self::Holds {
                relation: PermissionSegment::new("relation", relation.as_str())
                    .map_err(ApiError::validation)?,
                subject: subject.into(),
            }),
            LinkBody::Under(parent) => Ok(Self::Under(parent.object()?)),
        }
    }
}

impl From<&RelationLink> for LinkBody {
    fn from(link: &RelationLink) -> Self {
        match link {
            RelationLink::Holds { relation, subject } => Self::Holds {
                relation: relation.as_str().to_owned(),
                subject: (*subject).into(),
            },
            RelationLink::Under(parent) => Self::Under(parent.into()),
        }
    }
}

/// Adds a subject's relation to an app object or links it to a parent object.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct WriteRelationshipBody {
    /// The object the fact is about.
    pub object: ObjectBody,
    /// How it is related.
    pub link: LinkBody,
}

impl TryFrom<WriteRelationshipBody> for NewRelationship {
    type Error = ApiError;

    fn try_from(body: WriteRelationshipBody) -> Result<Self, Self::Error> {
        Ok(Self {
            object: body.object.object()?,
            link: (&body.link).try_into()?,
        })
    }
}

/// A stored authorization fact connecting an app object to a subject or parent.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RelationshipResponse {
    /// The relationship's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: RelationshipId,
    /// The object the fact is about.
    pub object: ObjectBody,
    /// How it is related.
    pub link: LinkBody,
    /// When it was written.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<&Relationship<ResolvedTenant>> for RelationshipResponse {
    fn from(relationship: &Relationship<ResolvedTenant>) -> Self {
        Self {
            id: *relationship.id(),
            object: relationship.object().into(),
            link: relationship.link().into(),
            created_at: relationship.created_at(),
        }
    }
}
