//! A declared attribute and a stored value as their rows hold them: read
//! back into the domain, and written out from it.

use std::collections::HashMap;

use ianua_app::ports::identity::StoredAttribute;
use ianua_domain::domains::identity::attribute::definition::{
    AttributeSensitivity, AttributeUse, Filtering, Listing, Requirement, Sorting,
};
use ianua_domain::domains::identity::attribute::{
    AttributeControl, AttributeDefinition, AttributeDefinitionRow, AttributeKey, AttributeKind,
    AttributeNamespace, AttributeVisibility,
};
use ianua_domain::domains::identity::metadata_value::MetadataValue;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{AttributeDefinitionId, Label, Text, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const ATTRIBUTE: Stored = Stored("attribute definition");

const METADATA: Stored = Stored("user metadata");

/// A declared attribute as it is read. The store's checked queries fill it.
pub(super) struct AttributeRecord {
    pub(super) id: Uuid,
    pub(super) namespace: String,
    pub(super) key: String,
    pub(super) kind: String,
    pub(super) control: String,
    pub(super) display_name: String,
    pub(super) description: Option<String>,
    pub(super) options: Vec<String>,
    pub(super) max_length: Option<i32>,
    pub(super) minimum: Option<f64>,
    pub(super) maximum: Option<f64>,
    pub(super) required: bool,
    pub(super) sensitive: bool,
    pub(super) filterable: bool,
    pub(super) sortable: bool,
    pub(super) listed: bool,
    pub(super) archived: bool,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl AttributeRecord {
    /// The declaration the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the
    /// declaration keeps.
    pub(super) fn into_definition(
        self,
    ) -> Result<AttributeDefinition<ResolvedTenant>, DomainError> {
        let visibility = self.visibility();
        let max_length = self
            .max_length
            .map(|length| u32::try_from(length).map_err(DomainError::infra))
            .transpose()?;
        AttributeDefinition::reconstitute(AttributeDefinitionRow {
            id: AttributeDefinitionId::from_uuid(self.id),
            key: ATTRIBUTE.value("key", AttributeKey::new(self.key))?,
            namespace: namespace_of(ATTRIBUTE, &self.namespace)?,
            kind: AttributeKind::parse(&self.kind)
                .ok_or_else(|| DomainError::corrupt_row(ATTRIBUTE.0, "an unknown kind"))?,
            control: AttributeControl::parse(&self.control)
                .ok_or_else(|| DomainError::corrupt_row(ATTRIBUTE.0, "an unknown control"))?,
            display_name: ATTRIBUTE.value(
                "display name",
                Label::new("display_name", self.display_name),
            )?,
            description: description_from(self.description)?,
            options: options_from(self.options)?,
            max_length: restriction(max_length),
            minimum: restriction(self.minimum),
            maximum: restriction(self.maximum),
            visibility,
            archived: AttributeUse::from(self.archived),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// The named visibility choices represented by the stored flags.
    fn visibility(&self) -> AttributeVisibility {
        AttributeVisibility {
            required: Requirement::from(self.required),
            sensitive: AttributeSensitivity::from(self.sensitive),
            filterable: Filtering::from(self.filterable),
            sortable: Sorting::from(self.sortable),
            listed: Listing::from(self.listed),
        }
    }
}

/// Validates an optional stored description without inventing one for an empty column.
fn description_from(description: Option<String>) -> Result<Option<Text>, DomainError> {
    description
        .map(|text| ATTRIBUTE.value("description", Text::new("description", text)))
        .transpose()
}

/// Validates every declared option in its stored order.
fn options_from(options: Vec<String>) -> Result<Vec<Label>, DomainError> {
    options
        .into_iter()
        .map(|option| ATTRIBUTE.value("option", Label::new("option", option)))
        .collect()
}

/// Converts a domain length limit to the bounded storage column.
fn length_column(length: Option<&u32>) -> Result<Option<i32>, DomainError> {
    length
        .map(|length| i32::try_from(*length).map_err(DomainError::infra))
        .transpose()
}

/// A declared attribute's columns, as they are written.
pub(super) struct AttributeColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) namespace: &'static str,
    pub(super) key: &'a str,
    pub(super) kind: &'static str,
    pub(super) control: &'static str,
    pub(super) display_name: &'a str,
    pub(super) description: Option<&'a str>,
    pub(super) options: Vec<String>,
    pub(super) max_length: Option<i32>,
    pub(super) minimum: Option<f64>,
    pub(super) maximum: Option<f64>,
    pub(super) required: bool,
    pub(super) sensitive: bool,
    pub(super) filterable: bool,
    pub(super) sortable: bool,
    pub(super) listed: bool,
    pub(super) archived: bool,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> AttributeColumns<'a> {
    /// The columns `definition` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its length limit does not
    /// fit the column, which no limit the domain allows does.
    pub(super) fn of(
        definition: &'a AttributeDefinition<ResolvedTenant>,
    ) -> Result<Self, DomainError> {
        let visibility = definition.visibility();
        let max_length = length_column(definition.max_length().limit())?;
        Ok(Self {
            id: definition.id().as_uuid(),
            namespace: definition.namespace().as_str(),
            key: definition.key().as_str(),
            kind: definition.kind().as_str(),
            control: definition.control().as_str(),
            display_name: definition.display_name().as_str(),
            description: definition.description().map(Text::as_str),
            options: definition
                .options()
                .iter()
                .map(|option| option.as_str().to_owned())
                .collect(),
            max_length,
            minimum: definition.minimum().limit().copied(),
            maximum: definition.maximum().limit().copied(),
            required: visibility.required.into(),
            sensitive: visibility.sensitive.into(),
            filterable: visibility.filterable.into(),
            sortable: visibility.sortable.into(),
            listed: visibility.listed.into(),
            archived: definition.archived(),
            created_at: definition.created_at(),
            updated_at: definition.updated_at(),
        })
    }
}

/// A stored value as it is read, with the attribute it belongs to.
pub(super) struct MetadataRecord {
    pub(super) user_id: Uuid,
    pub(super) namespace: String,
    pub(super) key: String,
    pub(super) value_type: String,
    pub(super) value_text: Option<String>,
    pub(super) value_int: Option<i64>,
    pub(super) value_float: Option<f64>,
    pub(super) value_bool: Option<bool>,
    pub(super) value_array: Option<Vec<String>>,
}

impl MetadataRecord {
    /// The namespace, the key as a label, and the value the record holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the namespace or the type
    /// is unknown, the key is no label, or the value is not in the column
    /// its type names.
    pub(super) fn into_labelled(
        self,
    ) -> Result<(AttributeNamespace, Label, MetadataValue), DomainError> {
        let namespace = namespace_of(METADATA, &self.namespace)?;
        let key = METADATA.value("key", Label::new("metadata_key", self.key.as_str()))?;
        Ok((namespace, key, self.into_value()?))
    }

    /// The user, and the value as the attribute it belongs to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the namespace or the type
    /// is unknown, the key is no attribute key, or the value is not in the
    /// column its type names.
    pub(super) fn into_attribute(self) -> Result<(UserId, StoredAttribute), DomainError> {
        let user_id = UserId::from_uuid(self.user_id);
        let namespace = namespace_of(METADATA, &self.namespace)?;
        let key = METADATA.value("key", AttributeKey::new(self.key.as_str()))?;
        let value = self.into_value()?;
        Ok((
            user_id,
            StoredAttribute {
                namespace,
                key,
                value,
            },
        ))
    }

    /// The value, from the column its type names.
    fn into_value(self) -> Result<MetadataValue, DomainError> {
        let value = match self.value_type.as_str() {
            "string" => self.value_text.map(MetadataValue::String),
            "integer" => self.value_int.map(MetadataValue::Integer),
            "number" => self.value_float.map(MetadataValue::Number),
            "boolean" => self.value_bool.map(MetadataValue::Bool),
            "string_array" => self.value_array.map(MetadataValue::StringArray),
            "null" => Some(MetadataValue::Null),
            _ => None,
        };
        value.ok_or_else(|| {
            DomainError::corrupt_row(METADATA.0, "a value missing from the column its type names")
        })
    }
}

/// A value's columns, as they are written: its type, and the one column
/// that type keeps it in.
#[derive(Default)]
pub(super) struct ValueColumns<'a> {
    pub(super) value_type: &'static str,
    pub(super) value_text: Option<&'a str>,
    pub(super) value_int: Option<i64>,
    pub(super) value_float: Option<f64>,
    pub(super) value_bool: Option<bool>,
    pub(super) value_array: Option<&'a [String]>,
}

impl<'a> ValueColumns<'a> {
    /// The columns `value` is written to.
    pub(super) fn of(value: &'a MetadataValue) -> Self {
        match value {
            MetadataValue::String(text) => Self {
                value_text: Some(text.as_str()),
                ..Self::empty("string")
            },
            MetadataValue::Integer(number) => Self {
                value_int: Some(*number),
                ..Self::empty("integer")
            },
            MetadataValue::Number(number) => Self {
                value_float: Some(*number),
                ..Self::empty("number")
            },
            MetadataValue::Bool(flag) => Self {
                value_bool: Some(*flag),
                ..Self::empty("boolean")
            },
            MetadataValue::StringArray(items) => Self {
                value_array: Some(items.as_slice()),
                ..Self::empty("string_array")
            },
            MetadataValue::Null => Self::empty("null"),
        }
    }

    /// Starts a typed row with every payload column absent until its type fills one.
    fn empty(value_type: &'static str) -> Self {
        Self {
            value_type,
            ..Self::default()
        }
    }
}

/// The namespace a stored word names, in a row of `stored`.
fn namespace_of(stored: Stored, word: &str) -> Result<AttributeNamespace, DomainError> {
    AttributeNamespace::parse(word)
        .ok_or_else(|| DomainError::corrupt_row(stored.0, "an unknown namespace"))
}

/// The restriction a stored limit records. No limit means unrestricted.
fn restriction<T>(limit: Option<T>) -> Restriction<T> {
    limit.map_or(Restriction::Unrestricted, Restriction::To)
}

/// One user's metadata: the user namespace, then the app namespace.
pub(super) type Metadata = (HashMap<Label, MetadataValue>, HashMap<Label, MetadataValue>);

/// `records` split into the user namespace and the app namespace.
pub(super) fn by_namespace(records: Vec<MetadataRecord>) -> Result<Metadata, DomainError> {
    records
        .into_iter()
        .map(MetadataRecord::into_labelled)
        .try_fold(Metadata::default(), |(mut user, mut app), labelled| {
            let (namespace, key, value) = labelled?;
            match namespace {
                AttributeNamespace::User => user.insert(key, value),
                AttributeNamespace::App => app.insert(key, value),
            };
            Ok((user, app))
        })
}

/// `records` gathered by the user they belong to.
pub(super) fn by_user(
    records: Vec<MetadataRecord>,
) -> Result<HashMap<UserId, Vec<StoredAttribute>>, DomainError> {
    records
        .into_iter()
        .map(MetadataRecord::into_attribute)
        .try_fold(
            HashMap::<UserId, Vec<StoredAttribute>>::new(),
            |mut found, attribute| {
                let (user_id, attribute) = attribute?;
                found.entry(user_id).or_default().push(attribute);
                Ok(found)
            },
        )
}
