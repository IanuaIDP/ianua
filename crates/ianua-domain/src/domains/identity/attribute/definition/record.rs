//! What a declared attribute raises for the audit trail as it changes.

use crate::domains::identity::attribute::definition::{AttributeDefinition, AttributeUse};
use crate::domains::identity::events::attributes::{
    AttributeSubject, UserAttributeArchived, UserAttributeDeclared, UserAttributeDeleted,
    UserAttributeRestored, UserAttributeUpdated,
};
use crate::isolation::scope::TenantScope;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raises, SavedFor};
use crate::types::EventLabel;

impl<T: TenantScope> AttributeDefinition<T> {
    /// How every attribute event names this attribute: its namespace, its
    /// key and what an administrator calls it now.
    fn subject(&self) -> AttributeSubject {
        AttributeSubject {
            namespace: self.namespace,
            key: self.key.clone(),
            display_name: EventLabel::of(self.display_name.as_str()),
        }
    }

    /// Raises the declaration of this attribute as it is now.
    pub(super) fn raise_declared(&mut self) {
        self.raised.raise(UserAttributeDeclared {
            subject: self.subject(),
            kind: self.kind,
            sensitive: self.visibility.sensitive,
            occurred_at: self.updated_at,
        });
    }

    /// Raises one update of this attribute, as it is after it.
    pub(super) fn raise_updated(&mut self) {
        self.raised.raise(UserAttributeUpdated {
            subject: self.subject(),
            sensitive: self.visibility.sensitive,
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Raises that this attribute was withdrawn or brought back, as its use
    /// says now.
    pub(super) fn raise_use(&mut self) {
        let subject = self.subject();
        let occurred_at = self.updated_at;
        match self.archived {
            AttributeUse::Archived => self.raised.raise(UserAttributeArchived {
                subject,
                occurred_at,
            }),
            AttributeUse::InUse => self.raised.raise(UserAttributeRestored {
                subject,
                occurred_at,
            }),
        }
    }

    /// Raises that this attribute was deleted with `values_discarded` values.
    pub(super) fn raise_deleted(&mut self, values_discarded: u64) {
        self.raised.raise(UserAttributeDeleted {
            subject: self.subject(),
            values_discarded,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for AttributeDefinition<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::domains::identity::attribute::definition::{
        AttributeDefinitionRow, AttributeVisibility, DeclareAttribute,
    };
    use crate::domains::identity::attribute::key::AttributeKey;
    use crate::domains::identity::attribute::kind::AttributeKind;
    use crate::domains::identity::attribute::namespace::AttributeNamespace;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::restriction::Restriction;
    use crate::test_support::authority::{anyone_holding, user_editor};
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{Label, Preference};

    type Attribute = AttributeDefinition<ResolvedTenant>;

    fn cost_centre() -> Attribute {
        Attribute::declare(
            DeclareAttribute {
                key: AttributeKey::new("cost_centre").unwrap(),
                namespace: AttributeNamespace::App,
                kind: AttributeKind::Text,
                control: Preference::Inherited,
                display_name: Label::new("display_name", "Cost centre").unwrap(),
                description: None,
                options: Vec::new(),
                max_length: Restriction::Unrestricted,
                minimum: Restriction::Unrestricted,
                maximum: Restriction::Unrestricted,
                visibility: AttributeVisibility::default(),
            },
            user_editor(),
        )
        .unwrap()
    }

    fn label_of(event: &DomainEvent) -> String {
        match event.payload().value("attribute") {
            Some(FieldValue::Reference(reference)) => reference.label().to_owned(),
            other => panic!("attribute is not a reference: {other:?}"),
        }
    }

    /// Ann declares `cost_centre`. The declaration is raised, naming the
    /// attribute by what she called it.
    #[test]
    fn declaring_raises_identity_attribute_declared() {
        let mut attribute = cost_centre();

        let events = raised(&mut attribute);

        assert_eq!(
            events[0].event_type().to_string(),
            "identity.attribute_declared"
        );
        assert_eq!(label_of(&events[0]), "Cost centre");
    }

    /// Ann renames `cost_centre` and describes it in one update. One update
    /// is raised, naming it by its new name.
    #[test]
    fn an_update_raises_identity_attribute_updated_once() {
        let mut attribute = cost_centre();
        raised_names(&mut attribute);
        let editor = user_editor();

        attribute
            .update(editor, |attribute| {
                attribute.rename(Label::new("display_name", "Budget").unwrap(), editor)?;
                attribute.describe(None, editor)
            })
            .unwrap();

        let events = raised(&mut attribute);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "identity.attribute_updated"
        );
        assert_eq!(label_of(&events[0]), "Budget");
    }

    /// Ann withdraws `cost_centre`, brings it back, withdraws it again and
    /// deletes it with 3 stored values. Each step is raised, in order.
    #[test]
    fn archiving_restoring_and_deleting_are_raised_in_order() {
        let mut attribute = cost_centre();
        raised_names(&mut attribute);
        let editor = user_editor();

        attribute.archive(editor).unwrap();
        attribute.restore(editor).unwrap();
        attribute.archive(editor).unwrap();
        attribute.delete(3, editor).unwrap();

        let events = raised(&mut attribute);
        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "identity.attribute_archived",
                "identity.attribute_restored",
                "identity.attribute_archived",
                "identity.attribute_deleted",
            ]
        );
        assert_eq!(events[3].payload().get("values_discarded"), Some("3"));
    }

    /// User-view permission cannot update, archive or delete an attribute;
    /// all three refusals leave the event queue empty.
    #[test]
    fn a_refused_attribute_change_raises_nothing() {
        let mut attribute = cost_centre();
        raised_names(&mut attribute);
        let sam = anyone_holding(&[SystemPermission::Users(UserAction::View)]);

        let updated = attribute.update(sam, |_| Ok(()));
        let archived = attribute.archive(sam);
        let deleted = attribute.delete(0, sam);

        assert!(updated.is_err());
        assert!(archived.is_err());
        assert!(deleted.is_err());
        assert!(raised_names(&mut attribute).is_empty());
    }

    /// `cost_centre` is read back from storage. It has raised nothing.
    #[test]
    fn an_attribute_read_back_from_storage_has_raised_nothing() {
        let declared = cost_centre();
        let mut attribute = Attribute::reconstitute(AttributeDefinitionRow {
            id: declared.id,
            key: declared.key.clone(),
            namespace: declared.namespace,
            kind: declared.kind,
            control: declared.control,
            display_name: declared.display_name.clone(),
            description: None,
            options: Vec::new(),
            max_length: declared.max_length,
            minimum: declared.minimum,
            maximum: declared.maximum,
            visibility: declared.visibility,
            archived: declared.archived,
            created_at: declared.created_at,
            updated_at: declared.updated_at,
        })
        .unwrap();

        assert!(raised_names(&mut attribute).is_empty());
    }
}
