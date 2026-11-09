//! Events about the attributes a tenant declares and stores on its users.

use time::OffsetDateTime;

use crate::domains::identity::attribute::definition::AttributeSensitivity;
use crate::domains::identity::attribute::key::AttributeKey;
use crate::domains::identity::attribute::kind::AttributeKind;
use crate::domains::identity::attribute::namespace::AttributeNamespace;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::EventLabel;

/// What every attribute event records about the attribute it concerns.
///
/// The five events differ in what happened, not in what they name. So the
/// naming lives here and the shared payload is built once.
#[derive(Debug, Clone)]
pub(crate) struct AttributeSubject {
    /// Which namespace the attribute is in.
    pub(crate) namespace: AttributeNamespace,
    /// The attribute's internal name.
    pub(crate) key: AttributeKey,
    /// What an administrator called it.
    pub(crate) display_name: EventLabel,
}

impl AttributeSubject {
    /// The payload every attribute event shares: a reference to the
    /// attribute, its namespace and its key.
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "attribute",
                Reference::new(
                    RefKind::USER_ATTRIBUTE,
                    format!("{}:{}", self.namespace.as_str(), self.key),
                    self.display_name.as_str(),
                ),
            )
            .field("namespace", self.namespace.as_str())
            .field("key", self.key.as_str())
    }
}

/// A tenant declared a custom user attribute.
#[derive(Debug)]
pub(crate) struct UserAttributeDeclared {
    /// The attribute concerned.
    pub(crate) subject: AttributeSubject,
    /// What kind of thing it holds.
    pub(crate) kind: AttributeKind,
    /// Whether reading it needs more than the right to view users.
    pub(crate) sensitive: AttributeSensitivity,
    /// When it was declared.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserAttributeDeclared => crate::types::event_type::IdentityEvent::AttributeDeclared,
    fn payload(&self) -> EventData {
        self.subject
            .payload()
            .field("kind", self.kind.as_str())
            .field("sensitive", bool::from(self.sensitive).to_string())
    }
}

/// A tenant changed a custom user attribute's declaration.
#[derive(Debug)]
pub(crate) struct UserAttributeUpdated {
    /// The attribute concerned.
    pub(crate) subject: AttributeSubject,
    /// Whether reading it now needs more than the right to view users.
    ///
    /// It is recorded on every change. Who may read an attribute is the part
    /// of a change a reviewer cares about most.
    pub(crate) sensitive: AttributeSensitivity,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserAttributeUpdated => crate::types::event_type::IdentityEvent::AttributeUpdated,
    fn payload(&self) -> EventData {
        self.subject
            .payload()
            .field("sensitive", bool::from(self.sensitive).to_string())
    }
}

/// A tenant archived a custom user attribute.
///
/// Values stored under it are kept. Only the attribute is hidden.
#[derive(Debug)]
pub(crate) struct UserAttributeArchived {
    /// The attribute concerned.
    pub(crate) subject: AttributeSubject,
    /// When it was archived.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserAttributeArchived => crate::types::event_type::IdentityEvent::AttributeArchived,
    fn payload(&self) -> EventData {
        self.subject.payload()
    }
}

/// A tenant brought an archived attribute back into use.
#[derive(Debug)]
pub(crate) struct UserAttributeRestored {
    /// The attribute concerned.
    pub(crate) subject: AttributeSubject,
    /// When it was restored.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserAttributeRestored => crate::types::event_type::IdentityEvent::AttributeRestored,
    fn payload(&self) -> EventData {
        self.subject.payload()
    }
}

/// A tenant deleted a custom user attribute and every value stored under it.
#[derive(Debug)]
pub(crate) struct UserAttributeDeleted {
    /// The attribute concerned.
    pub(crate) subject: AttributeSubject,
    /// How many stored values were deleted with it.
    ///
    /// It records how much was lost, because this is the one attribute change
    /// that cannot be undone.
    pub(crate) values_discarded: u64,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    UserAttributeDeleted => crate::types::event_type::IdentityEvent::AttributeDeleted,
    fn payload(&self) -> EventData {
        self.subject
            .payload()
            .field("values_discarded", self.values_discarded.to_string())
    }
}
