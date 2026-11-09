//! Events about relationships on the objects of a tenant's app.

use time::OffsetDateTime;

use crate::domains::authorization::relationship::{ObjectRef, RelationLink};
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::RelationshipId;

/// A relationship was written: someone holds a relation on an object, or
/// an object was put under another.
#[derive(Debug)]
pub struct RelationshipAdded {
    /// The stored edge establishing this access or parent relationship.
    pub(crate) relationship_id: RelationshipId,
    /// The object it is about.
    pub(crate) object: ObjectRef,
    /// What it says.
    pub(crate) link: RelationLink,
    /// When it was written.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RelationshipAdded => crate::types::event_type::AuthorizationEvent::RelationshipAdded,
    fn payload(&self) -> EventData {
        link_payload(self.relationship_id, &self.object, &self.link)
    }
}

/// A relationship was removed.
#[derive(Debug)]
pub struct RelationshipRemoved {
    /// The stored edge whose access or inheritance was withdrawn.
    pub(crate) relationship_id: RelationshipId,
    /// The object it was about.
    pub(crate) object: ObjectRef,
    /// What it said.
    pub(crate) link: RelationLink,
    /// When it was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    RelationshipRemoved => crate::types::event_type::AuthorizationEvent::RelationshipRemoved,
    fn payload(&self) -> EventData {
        link_payload(self.relationship_id, &self.object, &self.link)
    }
}

/// The relationship, its object, and either the relation and its holder or
/// the parent.
fn link_payload(id: RelationshipId, object: &ObjectRef, link: &RelationLink) -> EventData {
    let payload = EventData::new()
        .field("relationship", id.to_string())
        .field("object", object.to_string());
    match link {
        RelationLink::Holds { relation, subject } => payload
            .field("relation", relation.to_string())
            .field("subject", subject.to_string()),
        RelationLink::Under(parent) => payload.field("parent", parent.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::fixtures::segment;
    use crate::domains::authorization::relationship::{ObjectKey, RelationSubject};
    use crate::shared::events::event::DomainEventCore;
    use crate::types::GroupId;

    fn object(kind: &str, key: &str) -> ObjectRef {
        ObjectRef::new(segment(kind), ObjectKey::new(key).unwrap())
    }

    /// Engineering is made `editor` of project 42, and document 7 is put
    /// under the project. Each record names the object and what was said.
    #[test]
    fn a_relationship_records_its_object_and_what_it_says() {
        let group = GroupId::new();
        let shared = RelationshipAdded {
            relationship_id: RelationshipId::new(),
            object: object("project", "42"),
            link: RelationLink::Holds {
                relation: segment("editor"),
                subject: RelationSubject::Group(group),
            },
            occurred_at: crate::shared::clock::now(),
        };
        let filed = RelationshipAdded {
            relationship_id: RelationshipId::new(),
            object: object("document", "7"),
            link: RelationLink::Under(object("project", "42")),
            occurred_at: crate::shared::clock::now(),
        };

        let shared = shared.payload();
        let filed = filed.payload();

        assert_eq!(shared.get("object"), Some("project:42"));
        assert_eq!(shared.get("relation"), Some("editor"));
        assert_eq!(
            shared.get("subject"),
            Some(format!("group:{group}").as_str())
        );
        assert_eq!(filed.get("parent"), Some("project:42"));
    }
}
