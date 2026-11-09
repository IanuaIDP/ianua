//! A relationship as its row holds it: read back into the aggregate, and
//! written out from it.
//!
//! What a relationship says is one of two things, kept in columns of their
//! own: who holds a relation on the object, or which object it sits under.

use ianua_domain::domains::authorization::permission::PermissionSegment;
use ianua_domain::domains::authorization::relationship::{
    ObjectKey, ObjectRef, RelationLink, RelationSubject, Relationship, RelationshipRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{GroupId, RelationshipId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::authorization::principals::{kind_word, principal_from};
use crate::postgres::foundation::stored::Stored;

const RELATIONSHIP: Stored = Stored("relationship");

/// The link word of a relation held on the object.
const HOLDS: &str = "holds";

/// The link word of the object sitting under another.
const UNDER: &str = "under";

/// The subject kind word of a group.
const GROUP: &str = "group";

/// A relationship as it is read. The store's checked queries fill it.
pub(super) struct RelationshipRecord {
    pub(super) id: Uuid,
    pub(super) object_type: String,
    pub(super) object_key: String,
    pub(super) link: String,
    pub(super) relation: Option<String>,
    pub(super) subject_kind: Option<String>,
    pub(super) subject_id: Option<Uuid>,
    pub(super) parent_type: Option<String>,
    pub(super) parent_key: Option<String>,
    pub(super) created_at: OffsetDateTime,
}

impl RelationshipRecord {
    /// The relationship the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, the link's columns do not fit it, or the object sits
    /// under itself.
    pub(super) fn into_relationship(self) -> Result<Relationship<ResolvedTenant>, DomainError> {
        let object = object_from(self.object_type, self.object_key)?;
        let link = link_from(
            &self.link,
            Holder {
                relation: self.relation,
                kind: self.subject_kind,
                id: self.subject_id,
            },
            self.parent_type.zip(self.parent_key),
        )?;
        Relationship::reconstitute(RelationshipRow {
            id: RelationshipId::from_uuid(self.id),
            object,
            link,
            created_at: self.created_at,
        })
    }
}

/// The holder columns of a row, all filled for a relation held.
struct Holder {
    relation: Option<String>,
    kind: Option<String>,
    id: Option<Uuid>,
}

/// The object a type and a key column hold.
fn object_from(resource_type: String, key: String) -> Result<ObjectRef, DomainError> {
    Ok(ObjectRef::new(
        RELATIONSHIP.value(
            "object type",
            PermissionSegment::new("object_type", resource_type),
        )?,
        RELATIONSHIP.value("object key", ObjectKey::new(key))?,
    ))
}

/// What the link word and its columns say.
fn link_from(
    link: &str,
    holder: Holder,
    parent: Option<(String, String)>,
) -> Result<RelationLink, DomainError> {
    match (link, holder, parent) {
        (
            HOLDS,
            Holder {
                relation: Some(relation),
                kind: Some(kind),
                id: Some(id),
            },
            None,
        ) => Ok(RelationLink::Holds {
            relation: RELATIONSHIP
                .value("relation", PermissionSegment::new("relation", relation))?,
            subject: subject_from(&kind, id)?,
        }),
        (
            UNDER,
            Holder {
                relation: None,
                kind: None,
                id: None,
            },
            Some((resource_type, key)),
        ) => Ok(RelationLink::Under(object_from(resource_type, key)?)),
        (_, _, _) => Err(DomainError::corrupt_row(
            RELATIONSHIP.0,
            "a link whose columns do not fit it",
        )),
    }
}

/// The subject a kind and an id column hold: a group, or a principal.
fn subject_from(kind: &str, id: Uuid) -> Result<RelationSubject, DomainError> {
    if kind == GROUP {
        return Ok(RelationSubject::Group(GroupId::from_uuid(id)));
    }
    principal_from(RELATIONSHIP, kind, id).map(RelationSubject::Principal)
}

/// The kind word and id `subject` is stored as.
pub(super) fn subject_columns(subject: &RelationSubject) -> (&'static str, Uuid) {
    match subject {
        RelationSubject::Principal(principal) => (kind_word(principal), principal.id()),
        RelationSubject::Group(group) => (GROUP, *group.as_uuid()),
    }
}

/// A relationship's columns, as they are written, and as a search for the
/// same fact names them.
pub(super) struct RelationshipColumns<'a> {
    pub(super) object_type: &'a str,
    pub(super) object_key: &'a str,
    pub(super) link: &'static str,
    pub(super) relation: Option<&'a str>,
    pub(super) subject_kind: Option<&'static str>,
    pub(super) subject_id: Option<Uuid>,
    pub(super) parent_type: Option<&'a str>,
    pub(super) parent_key: Option<&'a str>,
}

impl<'a> RelationshipColumns<'a> {
    /// The columns saying `link` about `object`.
    pub(super) fn of(object: &'a ObjectRef, link: &'a RelationLink) -> Self {
        let on_object = Self {
            object_type: object.resource_type().as_str(),
            object_key: object.key().as_str(),
            link: HOLDS,
            relation: None,
            subject_kind: None,
            subject_id: None,
            parent_type: None,
            parent_key: None,
        };
        match link {
            RelationLink::Holds { relation, subject } => {
                let (kind, id) = subject_columns(subject);
                Self {
                    relation: Some(relation.as_str()),
                    subject_kind: Some(kind),
                    subject_id: Some(id),
                    ..on_object
                }
            }
            RelationLink::Under(parent) => Self {
                link: UNDER,
                parent_type: Some(parent.resource_type().as_str()),
                parent_key: Some(parent.key().as_str()),
                ..on_object
            },
        }
    }
}
