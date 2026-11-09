//! Events about the resource types a tenant declares.

use time::OffsetDateTime;

use crate::domains::authorization::permission::PermissionSegment;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::{Label, ResourceTypeId};

/// A resource type was declared in a tenant's permission catalogue.
///
/// The tenant's application now has a named thing it protects, and the verbs
/// it accepts. Roles and routes can refer to it from here on.
#[derive(Debug)]
pub struct ResourceTypeDeclared {
    /// The newly declared resource type.
    pub(crate) resource_type_id: ResourceTypeId,
    /// The key used in `resource:action`.
    pub(crate) key: PermissionSegment,
    /// The resource type's display name.
    pub(crate) display_name: Label,
    /// How many actions it declares.
    pub(crate) action_count: usize,
    /// When it was declared.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ResourceTypeDeclared => crate::types::event_type::AuthorizationEvent::ResourceTypeDeclared,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "resource_type",
                Reference::new(
                    RefKind::RESOURCE_TYPE,
                    self.resource_type_id.to_string(),
                    self.display_name.as_str(),
                ),
            )
            .field("key", self.key.as_str())
            .field("action_count", self.action_count.to_string())
    }
}

/// A resource type's name, description or action ladder changed.
///
/// A ladder change matters most. When `admin` starts to confer `refund`,
/// every holder of `admin` gains `refund`. When `admin` stops conferring
/// `write`, every role that relied on it loses `write`.
#[derive(Debug)]
pub struct ResourceTypeUpdated {
    /// The resource type that changed.
    pub(crate) resource_type_id: ResourceTypeId,
    /// The key used in `resource:action`.
    pub(crate) key: PermissionSegment,
    /// The resource type's display name after the change.
    pub(crate) display_name: Label,
    /// How many actions it declares after the change.
    pub(crate) action_count: usize,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ResourceTypeUpdated => crate::types::event_type::AuthorizationEvent::ResourceTypeUpdated,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "resource_type",
                Reference::new(
                    RefKind::RESOURCE_TYPE,
                    self.resource_type_id.to_string(),
                    self.display_name.as_str(),
                ),
            )
            .field("key", self.key.as_str())
            .field("action_count", self.action_count.to_string())
    }
}

/// A resource type was removed from a tenant's catalogue.
#[derive(Debug)]
pub struct ResourceTypeDeleted {
    /// The resource type that was removed.
    pub(crate) resource_type_id: ResourceTypeId,
    /// The key it used in `resource:action`.
    pub(crate) key: PermissionSegment,
    /// When it was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    ResourceTypeDeleted => crate::types::event_type::AuthorizationEvent::ResourceTypeDeleted,
    fn payload(&self) -> EventData {
        EventData::new()
            .reference(
                "resource_type",
                Reference::new(
                    RefKind::RESOURCE_TYPE,
                    self.resource_type_id.to_string(),
                    self.key.as_str(),
                ),
            )
            .field("key", self.key.as_str())
    }
}
