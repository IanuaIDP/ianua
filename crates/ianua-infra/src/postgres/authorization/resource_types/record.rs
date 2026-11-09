//! A resource type as its row holds it: read back into the aggregate, and
//! written out from it.

use ianua_domain::domains::authorization::permission::PermissionSegment;
use ianua_domain::domains::authorization::resource_type::{
    ActionDefinition, ResourceType, ResourceTypeRow,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, ResourceTypeId, Text};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;

const RESOURCE_TYPE: Stored = Stored("resource type");

const ACTIONS: Kept = Kept {
    entity: RESOURCE_TYPE.0,
    column: "actions",
    shape: 1,
};

/// Every level, in rank order, to read a stored name back.
const LEVELS: [DataClassLevel; 4] = [
    DataClassLevel::Public,
    DataClassLevel::Internal,
    DataClassLevel::Confidential,
    DataClassLevel::Restricted,
];

/// A resource type as it is read. The store's checked queries fill it.
pub(crate) struct ResourceTypeRecord {
    pub(crate) id: Uuid,
    pub(crate) key: String,
    pub(crate) display_name: String,
    pub(crate) description: Option<String>,
    pub(crate) actions: Value,
    pub(crate) data_class: String,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

impl ResourceTypeRecord {
    /// The resource type the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, the level is unknown, or the row breaks a rule the
    /// resource type keeps.
    pub(crate) fn into_resource_type(self) -> Result<ResourceType<ResolvedTenant>, DomainError> {
        let description = self
            .description
            .map(|text| RESOURCE_TYPE.value("description", Text::new("description", text)))
            .transpose()?;
        let actions: Vec<ActionDefinition> = ACTIONS.open(self.actions)?;
        ResourceType::reconstitute(ResourceTypeRow {
            id: ResourceTypeId::from_uuid(self.id),
            key: RESOURCE_TYPE.value("key", PermissionSegment::new("key", self.key))?,
            display_name: RESOURCE_TYPE.value(
                "display name",
                Label::new("display_name", self.display_name),
            )?,
            description,
            actions,
            created_at: self.created_at,
            updated_at: self.updated_at,
            data_class: data_class_from(&self.data_class)?,
        })
    }
}

/// The level a stored name stands for.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the name is no level's.
fn data_class_from(stored: &str) -> Result<DataClassLevel, DomainError> {
    LEVELS
        .into_iter()
        .find(|level| level.as_str() == stored)
        .ok_or_else(|| DomainError::corrupt_row(RESOURCE_TYPE.0, "an unknown data class"))
}

/// The resource types `records` hold.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` for the first record that does
/// not read back.
pub(crate) fn resource_types_from(
    records: Vec<ResourceTypeRecord>,
) -> Result<Vec<ResourceType<ResolvedTenant>>, DomainError> {
    records
        .into_iter()
        .map(ResourceTypeRecord::into_resource_type)
        .collect()
}

/// A resource type's columns, as they are written.
pub(crate) struct ResourceTypeColumns<'a> {
    pub(crate) id: &'a Uuid,
    pub(crate) key: &'a str,
    pub(crate) display_name: &'a str,
    pub(crate) description: Option<&'a str>,
    pub(crate) actions: Value,
    pub(crate) data_class: &'static str,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

impl<'a> ResourceTypeColumns<'a> {
    /// The columns `resource_type` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its actions cannot be
    /// written out as JSON.
    pub(crate) fn of(resource_type: &'a ResourceType<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: resource_type.id().as_uuid(),
            key: resource_type.key().as_str(),
            display_name: resource_type.display_name().as_str(),
            description: resource_type.description().map(Text::as_str),
            actions: ACTIONS.seal(&resource_type.actions())?,
            data_class: resource_type.data_class().as_str(),
            created_at: resource_type.created_at(),
            updated_at: resource_type.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use serde_json::json;

    use super::*;

    fn segment(value: &str) -> PermissionSegment {
        PermissionSegment::new("test", value).unwrap()
    }

    /// The actions are written in the shape pinned here, each with its key,
    /// its name and what it brings, and read back the same.
    #[test]
    fn the_actions_are_stored_in_their_pinned_shape() {
        let actions = vec![
            ActionDefinition::new(
                segment("read"),
                Label::new("test", "Read").unwrap(),
                Vec::new(),
            ),
            ActionDefinition::new(
                segment("write"),
                Label::new("test", "Write").unwrap(),
                vec![segment("read")],
            ),
        ];
        let stored = json!({"v": 1, "value": [
            {"key": "read", "display_name": "Read", "implies": []},
            {"key": "write", "display_name": "Write", "implies": ["read"]}
        ]});

        assert_eq!(ACTIONS.seal(&actions).unwrap(), stored);
        assert_eq!(
            ACTIONS.open::<Vec<ActionDefinition>>(stored).unwrap(),
            actions
        );
    }

    /// Every level reads back from the name it is stored under.
    #[test]
    fn every_level_reads_back_from_its_name() {
        for level in LEVELS {
            assert_eq!(data_class_from(level.as_str()).unwrap(), level);
        }
    }
}
