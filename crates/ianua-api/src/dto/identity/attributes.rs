//! Custom user attribute bodies: declarations, the catalogue of kinds, and
//! the values people hold.

use std::collections::BTreeMap;

use ianua_app::ports::identity::StoredAttribute;
use ianua_app::use_cases::identity::attributes::{
    AttributeListing, Changes, ReadableValue, Status,
};
use ianua_domain::domains::identity::attribute::{
    AttributeControl, AttributeDefinition, AttributeKey, AttributeKind, AttributeNamespace,
    AttributeOperator, AttributeVisibility, DeclareAttribute,
};
use ianua_domain::domains::identity::metadata_value::MetadataValue;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{Label, Preference, Text};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::error::ApiError;

/// Declares a custom field on the tenant's users.
///
/// `kind` is the only choice that has to be made. Everything else follows
/// from it and may be left out: the control, the comparisons a filter may
/// use, and what counts as a valid value.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DeclareAttributeBody {
    /// Which namespace the field belongs to. `user` is kept by the person it
    /// describes, `app` only by administrators and the application.
    #[schema(schema_with = crate::dto::schemas::attribute_namespace)]
    pub namespace: AttributeNamespace,
    /// What kind of thing the field holds.
    #[schema(schema_with = crate::dto::schemas::attribute_kind)]
    pub kind: AttributeKind,
    /// What to call the field.
    pub display_name: String,
    /// The internal name. Derived from `display_name` when omitted, and
    /// fixed once declared: every stored value is filed under it.
    #[serde(default)]
    pub key: Option<String>,
    /// Help text shown beside the control.
    #[serde(default)]
    pub description: Option<String>,
    /// The control to render. Defaults to the kind's own, and must be one
    /// the kind permits.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::attribute_control)]
    pub control: Option<AttributeControl>,
    /// The options to choose from, for the kinds that draw from a list.
    #[serde(default)]
    pub options: Vec<String>,
    /// Longest permitted text, for the free-form text kinds.
    #[serde(default)]
    pub max_length: Option<u32>,
    /// Lowest permitted value, for the number kinds.
    #[serde(default)]
    pub minimum: Option<f64>,
    /// Highest permitted value, for the number kinds.
    #[serde(default)]
    pub maximum: Option<f64>,
    /// Whether every user must hold a value.
    #[serde(default)]
    pub required: bool,
    /// Whether the field holds information needing more than the right to
    /// view the directory, such as a salary or a health note. Filtering and
    /// sorting are held back the same way as reading, because narrowing a
    /// list and reading off the count discloses the value.
    #[serde(default)]
    pub sensitive: bool,
    /// Whether a directory may be narrowed by this field.
    #[serde(default)]
    pub filterable: bool,
    /// Whether a directory may be ordered by this field.
    #[serde(default)]
    pub sortable: bool,
    /// Whether the field is returned with each user in a listing.
    #[serde(default)]
    pub listed: bool,
}

impl TryFrom<DeclareAttributeBody> for DeclareAttribute {
    type Error = ApiError;

    /// The declaration the body asks for.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] when the name, key, description or an
    /// option is not a valid one.
    fn try_from(body: DeclareAttributeBody) -> Result<Self, ApiError> {
        let key = match &body.key {
            Some(key) => AttributeKey::new(key.as_str()),
            None => AttributeKey::derive_from(&body.display_name),
        }
        .map_err(ApiError::validation)?;
        Ok(Self {
            key,
            namespace: body.namespace,
            kind: body.kind,
            control: Preference::from_stored(body.control),
            display_name: Label::new("display_name", body.display_name)
                .map_err(ApiError::validation)?,
            description: description_of(body.description)?,
            options: options_of(body.options)?,
            max_length: restriction(body.max_length),
            minimum: restriction(body.minimum),
            maximum: restriction(body.maximum),
            visibility: AttributeVisibility {
                required: body.required.into(),
                sensitive: body.sensitive.into(),
                filterable: body.filterable.into(),
                sortable: body.sortable.into(),
                listed: body.listed.into(),
            },
        })
    }
}

/// Changes to a declared field. Every field left out stays as it is.
///
/// The internal name and the kind are absent on purpose. The name is
/// written beside every stored value, so changing it would orphan them; the
/// kind decides which column those values live in, so changing it would
/// misread them.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateAttributeBody {
    /// A new display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// New help text. Send `null` to clear it.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub description: Option<Option<String>>,
    /// A different control, within the ones the kind renders.
    #[serde(default)]
    #[schema(schema_with = crate::dto::schemas::attribute_control)]
    pub control: Option<AttributeControl>,
    /// A replacement set of options.
    #[serde(default)]
    pub options: Option<Vec<String>>,
    /// A new longest length. Send `null` to remove the limit.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub max_length: Option<Option<u32>>,
    /// A new lowest permitted value. Send `null` to remove it.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub minimum: Option<Option<f64>>,
    /// A new highest permitted value. Send `null` to remove it.
    #[serde(default, deserialize_with = "crate::patch::nullable::deserialize")]
    pub maximum: Option<Option<f64>>,
    /// Whether every user must hold a value.
    #[serde(default)]
    pub required: Option<bool>,
    /// Whether the field needs more than the right to view the directory.
    #[serde(default)]
    pub sensitive: Option<bool>,
    /// Whether a directory may be narrowed by this field.
    #[serde(default)]
    pub filterable: Option<bool>,
    /// Whether a directory may be ordered by this field.
    #[serde(default)]
    pub sortable: Option<bool>,
    /// Whether the field is returned with each user in a listing.
    #[serde(default)]
    pub listed: Option<bool>,
}

impl UpdateAttributeBody {
    /// The changes the body asks for, read against `current`: the
    /// visibility is changed whole, so the flags not named keep the values
    /// `current` has.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] when a name, description or option is not a
    /// valid one.
    pub(crate) fn changes(
        self,
        current: Option<&AttributeDefinition<ResolvedTenant>>,
    ) -> Result<Changes, ApiError> {
        let visibility = current.and_then(|current| self.visibility(current.visibility()));
        Ok(Changes {
            display_name: self
                .display_name
                .map(|name| Label::new("display_name", name))
                .transpose()
                .map_err(ApiError::validation)?,
            description: self.description.map(description_of).transpose()?,
            control: self.control,
            options: self.options.map(options_of).transpose()?,
            max_length: self.max_length.map(restriction),
            minimum: self.minimum.map(restriction),
            maximum: self.maximum.map(restriction),
            visibility,
        })
    }

    /// The visibility to apply, or `None` when no flag was named.
    fn visibility(&self, now: AttributeVisibility) -> Option<AttributeVisibility> {
        let named = [
            self.required,
            self.sensitive,
            self.filterable,
            self.sortable,
            self.listed,
        ]
        .iter()
        .any(Option::is_some);
        if !named {
            return None;
        }
        Some(AttributeVisibility {
            required: self.required.map_or(now.required, Into::into),
            sensitive: self.sensitive.map_or(now.sensitive, Into::into),
            filterable: self.filterable.map_or(now.filterable, Into::into),
            sortable: self.sortable.map_or(now.sortable, Into::into),
            listed: self.listed.map_or(now.listed, Into::into),
        })
    }
}

/// Whether a field should be in use.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AttributeStatusBody {
    /// `true` withdraws the field from use, keeping every value stored under
    /// it. `false` brings it back.
    pub archived: bool,
}

impl AttributeStatusBody {
    /// The state the field is asked to be in.
    #[must_use]
    pub(crate) fn status(&self) -> Status {
        if self.archived {
            return Status::Withdrawn;
        }
        Status::InUse
    }
}

/// Sets one user's value for a custom field.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct SetAttributeValueBody {
    /// The value. `null` clears it, which a required field refuses.
    #[schema(value_type = Option<Object>)]
    pub value: Option<Value>,
}

impl SetAttributeValueBody {
    /// The value to store, or `None` to clear it.
    ///
    /// # Errors
    ///
    /// [`ApiError::validation`] for a JSON shape no attribute can hold: an
    /// object, a list holding anything but text, or a number too large to
    /// store. Whether the value suits this attribute is the schema's
    /// question, answered next.
    pub(crate) fn value(self) -> Result<Option<MetadataValue>, ApiError> {
        self.value.map(metadata_value).transpose()
    }
}

/// Whether withdrawn attributes are listed.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AttributeListingParams {
    /// Include the attributes withdrawn from use. Off by default: a form has
    /// no use for them.
    #[serde(default)]
    pub include_archived: bool,
}

impl From<AttributeListingParams> for AttributeListing {
    fn from(params: AttributeListingParams) -> Self {
        if params.include_archived {
            return Self::WithArchived;
        }
        Self::InUse
    }
}

/// One declared custom field, with everything a client needs to render it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AttributeResponse {
    /// Which namespace the field belongs to.
    #[schema(schema_with = crate::dto::schemas::attribute_namespace)]
    pub namespace: AttributeNamespace,
    /// The internal name, which filters and sorts use.
    pub key: String,
    /// What kind of thing it holds.
    #[schema(schema_with = crate::dto::schemas::attribute_kind)]
    pub kind: AttributeKind,
    /// The control to render.
    #[schema(schema_with = crate::dto::schemas::attribute_control)]
    pub control: AttributeControl,
    /// What to call it.
    pub display_name: String,
    /// Help text shown beside the control.
    pub description: Option<String>,
    /// The options to choose from, empty when values are typed.
    pub options: Vec<String>,
    /// Longest permitted text.
    pub max_length: Option<u32>,
    /// Lowest permitted value.
    pub minimum: Option<f64>,
    /// Highest permitted value.
    pub maximum: Option<f64>,
    /// Whether every user must hold a value.
    pub required: bool,
    /// Whether it needs more than the right to view the directory.
    pub sensitive: bool,
    /// Whether a directory may be narrowed by it.
    pub filterable: bool,
    /// Whether a directory may be ordered by it.
    pub sortable: bool,
    /// Whether it is returned with each user in a listing.
    pub listed: bool,
    /// Whether it has been withdrawn from use, keeping its stored values.
    pub archived: bool,
    /// The comparisons a filter on it may use, so a client can build a
    /// filter bar without knowing which apply to which kind.
    #[schema(schema_with = crate::dto::schemas::attribute_operator_list)]
    pub operators: Vec<AttributeOperator>,
    /// The controls it may be rendered with, for the editor's own control
    /// picker.
    #[schema(schema_with = crate::dto::schemas::attribute_control_list)]
    pub available_controls: Vec<AttributeControl>,
    /// When it was declared.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it was last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<AttributeDefinition<ResolvedTenant>> for AttributeResponse {
    fn from(definition: AttributeDefinition<ResolvedTenant>) -> Self {
        let visibility = definition.visibility();
        Self {
            namespace: definition.namespace(),
            key: definition.key().as_str().to_owned(),
            kind: definition.kind(),
            control: definition.control(),
            display_name: definition.display_name().as_str().to_owned(),
            description: definition.description().map(|d| d.as_str().to_owned()),
            options: definition
                .options()
                .iter()
                .map(|option| option.as_str().to_owned())
                .collect(),
            max_length: definition.max_length().limit().copied(),
            minimum: definition.minimum().limit().copied(),
            maximum: definition.maximum().limit().copied(),
            required: visibility.required.into(),
            sensitive: visibility.sensitive.into(),
            filterable: visibility.filterable.into(),
            sortable: visibility.sortable.into(),
            listed: visibility.listed.into(),
            archived: definition.archived(),
            operators: AttributeOperator::applicable_to(definition.value_type()),
            available_controls: definition.kind().spec().controls.to_vec(),
            created_at: definition.created_at(),
            updated_at: definition.updated_at(),
        }
    }
}

/// One kind a tenant may declare a field as: the catalogue a client
/// renders the "what kind of thing is this?" step from.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AttributeKindResponse {
    /// The kind itself.
    #[schema(schema_with = crate::dto::schemas::attribute_kind)]
    pub kind: AttributeKind,
    /// The control rendered unless another is chosen.
    #[schema(schema_with = crate::dto::schemas::attribute_control)]
    pub default_control: AttributeControl,
    /// Every control this kind may be rendered with.
    #[schema(schema_with = crate::dto::schemas::attribute_control_list)]
    pub available_controls: Vec<AttributeControl>,
    /// The comparisons a filter on it may use.
    #[schema(schema_with = crate::dto::schemas::attribute_operator_list)]
    pub operators: Vec<AttributeOperator>,
    /// Whether it draws its values from a declared list, which the editor
    /// must then ask for.
    pub requires_options: bool,
    /// Whether a longest length may be set.
    pub supports_max_length: bool,
    /// Whether a lowest and highest value may be set.
    pub supports_range: bool,
    /// Whether a directory may be ordered by it.
    pub sortable: bool,
}

impl AttributeKindResponse {
    /// Every kind, as the catalogue.
    #[must_use]
    pub(crate) fn catalogue() -> Vec<Self> {
        AttributeKind::all()
            .iter()
            .copied()
            .map(Self::from)
            .collect()
    }
}

impl From<AttributeKind> for AttributeKindResponse {
    fn from(kind: AttributeKind) -> Self {
        let spec = kind.spec();
        Self {
            kind,
            default_control: spec.default_control(),
            available_controls: spec.controls.to_vec(),
            operators: AttributeOperator::applicable_to(spec.value_type),
            requires_options: kind.requires_options(),
            supports_max_length: kind.permits_length_limit(),
            supports_range: kind.permits_bounds(),
            sortable: kind.is_orderable(),
        }
    }
}

/// What deleting a field discarded.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct AttributeDeletedResponse {
    /// How many stored values went with the field.
    pub values_discarded: u64,
}

/// One user's custom field values.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UserAttributeValuesResponse {
    /// The values, keyed by `<namespace>.<key>`.
    #[schema(value_type = Object)]
    pub values: BTreeMap<String, Value>,
}

impl From<Vec<ReadableValue>> for UserAttributeValuesResponse {
    fn from(values: Vec<ReadableValue>) -> Self {
        Self {
            values: values
                .into_iter()
                .map(|(namespace, key, value)| (keyed(namespace, &key), rendered(&value)))
                .collect(),
        }
    }
}

/// Stored values as a listing row carries them: the same `<namespace>.<key>`
/// shape as one user's values, so a client reads a value out of a listing
/// exactly as out of a profile.
#[must_use]
pub(crate) fn listed_values(stored: Vec<StoredAttribute>) -> BTreeMap<String, Value> {
    stored
        .into_iter()
        .map(|attribute| {
            (
                keyed(attribute.namespace, attribute.key.as_str()),
                rendered(&attribute.value),
            )
        })
        .collect()
}

/// The `<namespace>.<key>` a value is keyed by.
fn keyed(namespace: AttributeNamespace, key: &str) -> String {
    format!("{}.{key}", namespace.as_str())
}

/// A stored value as JSON.
fn rendered(value: &MetadataValue) -> Value {
    match value {
        MetadataValue::String(text) => Value::String(text.clone()),
        MetadataValue::Integer(number) => Value::from(*number),
        MetadataValue::Number(number) => {
            serde_json::Number::from_f64(*number).map_or(Value::Null, Value::Number)
        }
        MetadataValue::Bool(flag) => Value::Bool(*flag),
        MetadataValue::StringArray(items) => {
            Value::Array(items.iter().cloned().map(Value::String).collect())
        }
        MetadataValue::Null => Value::Null,
    }
}

/// A JSON value as one an attribute could hold.
fn metadata_value(value: Value) -> Result<MetadataValue, ApiError> {
    match value {
        Value::String(text) => Ok(MetadataValue::String(text)),
        Value::Bool(flag) => Ok(MetadataValue::Bool(flag)),
        Value::Number(number) => number
            .as_i64()
            .map(MetadataValue::Integer)
            .or_else(|| number.as_f64().map(MetadataValue::Number))
            .ok_or_else(|| {
                ApiError::validation(message!(
                    "api-a-number-that-large-cannot-be",
                    "a number that large cannot be stored"
                ))
            }),
        Value::Array(items) => items
            .into_iter()
            .map(text_item)
            .collect::<Result<Vec<_>, _>>()
            .map(MetadataValue::StringArray),
        Value::Null => Ok(MetadataValue::Null),
        Value::Object(_) => Err(ApiError::validation(message!(
            "api-an-attribute-does-not-hold-an",
            "an attribute does not hold an object"
        ))),
    }
}

/// One item of a list value, which holds text and nothing else.
fn text_item(item: Value) -> Result<String, ApiError> {
    let Value::String(text) = item else {
        return Err(ApiError::validation(message!(
            "api-a-list-holds-text-and-nothing",
            "a list holds text and nothing else"
        )));
    };
    Ok(text)
}

/// The help text, once it is a valid one.
fn description_of(description: Option<String>) -> Result<Option<Text>, ApiError> {
    description
        .map(|text| Text::new("description", text))
        .transpose()
        .map_err(ApiError::validation)
}

/// Each option, once it is a valid one.
fn options_of(options: Vec<String>) -> Result<Vec<Label>, ApiError> {
    options
        .into_iter()
        .map(|option| Label::new("option", option))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::validation)
}

/// A limit as sent: a value holds the attribute to it, none lifts it.
fn restriction<T>(limit: Option<T>) -> Restriction<T> {
    limit.map_or(Restriction::Unrestricted, Restriction::To)
}
