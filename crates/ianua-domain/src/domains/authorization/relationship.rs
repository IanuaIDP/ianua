//! Who holds what on single objects of a tenant's app, and which object
//! sits under which.
//!
//! A resource type says what can be done to projects in general. A
//! relationship says what Ann may do to project 42: she is its `editor`.
//! The relation is one of the type's own actions, so its ladder applies:
//! an `editor` of project 42 may `read` it when the ladder says editing
//! brings reading. An object may sit under another, such as a document in
//! a folder, and a relation held on the folder counts on the document.
//!
//! The tenant's app writes relationships as its people share and move
//! things; [`access_check`](crate::domains::authorization::access_check)
//! reads them.

use std::fmt;
use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::events::relationships::{
    RelationshipAdded, RelationshipRemoved,
};
use crate::domains::authorization::permission::{
    CustomPermission, PermissionSegment, RoleAction, SystemPermission,
};
use crate::domains::authorization::resource_type::ResourceType;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{GroupId, PrincipalRef, RelationshipId};

/// The longest object key, in characters.
const MAX_KEY: usize = 128;

text_value! {
    /// The id the tenant's app gives one of its objects, such as `42`,
    /// `inv-2026-0031` or `acme.test/reports/q3`.
    pub struct ObjectKey;
}

impl TextValue for ObjectKey {
    const FIELD: &'static str = "object_key";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=MAX_KEY,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::UNDERSCORE
                | Charset::HYPHEN
                | Charset::DOT
                | Charset::COLON
                | Charset::SLASH
                | Charset::AT,
        )
    }
}

/// One object of the tenant's app: its resource type and its key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ObjectRef {
    resource_type: PermissionSegment,
    key: ObjectKey,
}

impl ObjectRef {
    /// The object of type `resource_type` keyed `key`.
    #[must_use]
    pub fn new(resource_type: PermissionSegment, key: ObjectKey) -> Self {
        Self { resource_type, key }
    }

    /// Its resource type's key, such as `project`.
    #[must_use]
    pub fn resource_type(&self) -> &PermissionSegment {
        &self.resource_type
    }

    /// The app's id for it.
    #[must_use]
    pub fn key(&self) -> &ObjectKey {
        &self.key
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.resource_type, self.key)
    }
}

/// Who holds a relation: one person, agent or app, or everyone in a group
/// and the groups under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationSubject {
    /// One directly named user, organization member, agent or application.
    Principal(PrincipalRef),
    /// Everyone in this group, or in a group under it.
    Group(GroupId),
}

impl fmt::Display for RelationSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Principal(principal) => {
                write!(f, "{}:{}", principal.ref_kind().as_str(), principal.id())
            }
            Self::Group(group) => write!(f, "group:{group}"),
        }
    }
}

/// What one relationship says about its object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationLink {
    /// `subject` holds `relation` on the object: one of its type's actions,
    /// with everything the ladder brings.
    Holds {
        /// The action held, such as `owner`, `editor` or `viewer`.
        relation: PermissionSegment,
        /// Who holds it.
        subject: RelationSubject,
    },
    /// The object sits under `parent`, and what is held on the parent
    /// counts on it.
    Under(ObjectRef),
}

/// What the tenant's app writes about one of its objects.
#[derive(Debug, Clone)]
pub struct NewRelationship {
    /// The app resource on which the relation or parent link is established.
    pub object: ObjectRef,
    /// What it says about it.
    pub link: RelationLink,
}

/// One fact about an object of the tenant's app: who holds a relation on
/// it, or which object it sits under.
///
/// A relationship keeps these rules:
/// - Its object's type is one the tenant declared, and a relation is one of
///   that type's actions, never `*`.
/// - An object never sits under itself.
/// - Writing or removing one needs the right to assign roles, and someone
///   writing a relation must be able to hand out everything it brings. Sam
///   may assign roles but does not hold `project:admin`; he cannot make
///   himself `admin` of project 42.
#[derive(Debug)]
pub struct Relationship<T: TenantScope> {
    id: RelationshipId,
    object: ObjectRef,
    link: RelationLink,
    created_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// A [`Relationship`] as storage holds it, read back through
/// [`Relationship::reconstitute`].
pub struct RelationshipRow {
    /// The relationship.
    pub id: RelationshipId,
    /// The object it is about.
    pub object: ObjectRef,
    /// What it says.
    pub link: RelationLink,
    /// When it was written.
    pub created_at: OffsetDateTime,
}

impl<T: TenantScope> Relationship<T> {
    /// Writes `new`, checked against the tenant's `catalogue`, for `by`.
    /// Raises `authorization.relationship_added`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not assign roles.
    /// - [`DomainError::Validation`] when the object's type is not declared,
    ///   or a relation is not one of its actions, or the object is put
    ///   under itself or under an undeclared type.
    /// - [`DomainError::Forbidden`] when `by` may not hand out what the
    ///   relation brings.
    pub fn write(
        new: NewRelationship,
        catalogue: &[ResourceType<T>],
        by: &TenantAuthority,
    ) -> Result<Self, DomainError> {
        ensure_written_by(&new.object, &new.link, catalogue, by)?;
        let mut relationship = Self {
            id: RelationshipId::new(),
            object: new.object,
            link: new.link,
            created_at: crate::shared::clock::now(),
            raised: Raised::default(),
            _scope: PhantomData,
        };
        relationship.raised.raise(RelationshipAdded {
            relationship_id: relationship.id,
            object: relationship.object.clone(),
            link: relationship.link.clone(),
            occurred_at: relationship.created_at,
        });
        Ok(relationship)
    }

    /// Removes this relationship, for `by`. Raises
    /// `authorization.relationship_removed`, taken once it is removed from
    /// storage.
    ///
    /// Taking a relation away is held to the same rules as giving it: Sam
    /// cannot strip Ann of `admin` on project 42 if he could not have given
    /// it.
    ///
    /// # Errors
    ///
    /// - The cases [`write`](Self::write) lists.
    pub fn remove(
        &mut self,
        catalogue: &[ResourceType<T>],
        by: &TenantAuthority,
    ) -> Result<(), DomainError> {
        ensure_written_by(&self.object, &self.link, catalogue, by)?;
        self.raised.raise(RelationshipRemoved {
            relationship_id: self.id,
            object: self.object.clone(),
            link: self.link.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Rebuilds a relationship from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the object sits under itself.
    pub fn reconstitute(row: RelationshipRow) -> Result<Self, DomainError> {
        RowCheck::of("relationship")
            .holds(
                row.link != RelationLink::Under(row.object.clone()),
                "an object under itself",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            object: row.object,
            link: row.link,
            created_at: row.created_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The relationship.
    #[must_use]
    pub fn id(&self) -> &RelationshipId {
        &self.id
    }

    /// The object it is about.
    #[must_use]
    pub fn object(&self) -> &ObjectRef {
        &self.object
    }

    /// What it says about the object.
    #[must_use]
    pub fn link(&self) -> &RelationLink {
        &self.link
    }

    /// When it was written.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

impl<T: TenantScope> Raises for Relationship<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// The declared type of `object` in `catalogue`.
///
/// # Errors
///
/// - [`DomainError::Validation`] when the catalogue does not declare it.
pub(crate) fn type_of<'c, T: TenantScope>(
    catalogue: &'c [ResourceType<T>],
    object: &ObjectRef,
) -> Result<&'c ResourceType<T>, DomainError> {
    catalogue
        .iter()
        .find(|declared| declared.key() == object.resource_type())
        .ok_or_else(|| {
            DomainError::invalid(message!(
                "authorization-the-tenant-declares-no-resource-type",
                format!(
                    "the tenant declares no resource type '{}'",
                    object.resource_type()
                )
            ))
        })
}

/// Refuses `link` on `object` unless the catalogue allows it and `by` may
/// give or take it.
fn ensure_written_by<T: TenantScope>(
    object: &ObjectRef,
    link: &RelationLink,
    catalogue: &[ResourceType<T>],
    by: &TenantAuthority,
) -> Result<(), DomainError> {
    let held = by.standing();
    held.ensure_holds(SystemPermission::Roles(RoleAction::Assign))?;
    let declared = type_of(catalogue, object)?;
    match link {
        RelationLink::Holds { relation, .. } => {
            let brings = brought_by(declared, relation)?;
            held.ensure_may_hand_out(&[], &brings)
        }
        RelationLink::Under(parent) => {
            if parent == object {
                return Err(DomainError::invalid(message!(
                    "authorization-an-object-cannot-sit-under-itself",
                    "an object cannot sit under itself"
                )));
            }
            type_of(catalogue, parent).map(|_| ())
        }
    }
}

/// Everything holding `relation` on an object of `declared` brings.
///
/// # Errors
///
/// - [`DomainError::Validation`] when `relation` is `*` or not one of the
///   type's actions.
fn brought_by<T: TenantScope>(
    declared: &ResourceType<T>,
    relation: &PermissionSegment,
) -> Result<Vec<CustomPermission>, DomainError> {
    if relation.is_wildcard() || !declared.declares(relation.as_str()) {
        return Err(DomainError::invalid(message!(
            "authorization-is-not-an-action-of",
            format!("'{relation}' is not an action of '{}'", declared.key())
        )));
    }
    declared.expand(relation.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::fixtures::{projects, segment};
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::{anyone_holding, assumed_authority};
    use crate::test_support::events::raised_names;
    use crate::types::{Human, HumanAccount, PersonKey, TenantId, UserId};

    fn project(key: &str) -> ObjectRef {
        ObjectRef::new(segment("project"), ObjectKey::new(key).unwrap())
    }

    fn holds(relation: &str) -> RelationLink {
        RelationLink::Holds {
            relation: segment(relation),
            subject: RelationSubject::Principal(PrincipalRef::User(UserId::new())),
        }
    }

    fn writing(link: RelationLink) -> NewRelationship {
        NewRelationship {
            object: project("42"),
            link,
        }
    }

    /// Someone who may assign roles and holds every app permission.
    fn owner() -> &'static TenantAuthority {
        assumed_authority(
            &Human::new(
                HumanAccount::User(UserId::new()),
                PersonKey::new("owner@acme.test").unwrap(),
            ),
            TenantId::new(),
            &[SystemPermission::Roles(RoleAction::Assign)],
            &[CustomPermission::parse("project:*").unwrap()],
        )
    }

    /// Ann's app gives Bob `write` on project 42. It is written and
    /// recorded.
    #[test]
    fn a_relation_on_a_declared_action_is_written() {
        let catalogue = [projects()];

        let mut written =
            Relationship::<ResolvedTenant>::write(writing(holds("write")), &catalogue, owner())
                .unwrap();

        assert_eq!(written.object(), &project("42"));
        assert_eq!(
            raised_names(&mut written),
            ["authorization.relationship_added"]
        );
    }

    /// Role-assignment rights alone cannot grant project administration, and a
    /// caller with no rights cannot grant even project reading.
    #[test]
    fn a_relation_is_written_only_by_someone_who_could_give_it() {
        let catalogue = [projects()];
        let sam = anyone_holding(&[SystemPermission::Roles(RoleAction::Assign)]);
        let nobody = anyone_holding(&[]);

        let admin = Relationship::<ResolvedTenant>::write(writing(holds("admin")), &catalogue, sam);
        let read =
            Relationship::<ResolvedTenant>::write(writing(holds("read")), &catalogue, nobody);

        assert!(matches!(admin, Err(DomainError::Forbidden(_))));
        assert!(matches!(read, Err(DomainError::Forbidden(_))));
    }

    /// A relation the type does not declare, a `*` relation, an object of
    /// an undeclared type, and a project put under itself are each refused.
    #[test]
    fn a_relation_means_what_the_catalogue_declares() {
        let catalogue = [projects()];
        let undeclared_type = NewRelationship {
            object: ObjectRef::new(segment("invoice"), ObjectKey::new("7").unwrap()),
            link: holds("read"),
        };
        let itself = writing(RelationLink::Under(project("42")));

        for refused in [
            writing(holds("delete")),
            writing(holds("*")),
            undeclared_type,
            itself,
        ] {
            let written = Relationship::<ResolvedTenant>::write(refused, &catalogue, owner());

            assert!(matches!(written, Err(DomainError::Validation(_))));
        }
    }

    /// Sam cannot remove project administration he could not grant. An authorized
    /// owner can remove it afterward, raising exactly one removal event.
    #[test]
    fn a_relation_is_removed_only_by_someone_who_could_give_it() {
        let catalogue = [projects()];
        let mut anns =
            Relationship::<ResolvedTenant>::write(writing(holds("admin")), &catalogue, owner())
                .unwrap();
        raised_names(&mut anns);
        let sam = anyone_holding(&[SystemPermission::Roles(RoleAction::Assign)]);

        let by_sam = anns.remove(&catalogue, sam);
        anns.remove(&catalogue, owner()).unwrap();

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert_eq!(
            raised_names(&mut anns),
            ["authorization.relationship_removed"]
        );
    }

    /// A stored relationship placing project 42 under itself is rejected as corrupt.
    #[test]
    fn a_stored_object_under_itself_is_refused() {
        let stored = Relationship::<ResolvedTenant>::reconstitute(RelationshipRow {
            id: RelationshipId::new(),
            object: project("42"),
            link: RelationLink::Under(project("42")),
            created_at: crate::shared::clock::now(),
        });

        assert!(matches!(stored, Err(DomainError::Infrastructure(_))));
    }

    /// An object key takes the shapes apps use, and refuses a space.
    #[test]
    fn object_keys_take_the_shapes_apps_use() {
        for key in ["42", "inv-2026-0031", "acme.test/reports/q3", "user@acme"] {
            assert!(ObjectKey::new(key).is_ok(), "{key}");
        }
        assert!(ObjectKey::new("two words").is_err());
    }
}
