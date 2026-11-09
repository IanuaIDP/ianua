//! A tenant's custom user fields: the fields it declares and the values
//! its people hold under them.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// `POST …/user-attributes`: a field declared on the tenant's users.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DeclareAttribute {
    /// `user` when the person keeps it, `app` when only staff do.
    pub namespace: String,
    /// What the field holds, such as `text`, `whole_number` or
    /// `single_choice`.
    pub kind: String,
    /// The label shown beside it.
    pub display_name: String,
    /// The fixed internal name, such as `shirt_size`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The options of a kind that draws from a list.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    /// Largest number allowed, for the number kinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
    /// Whether every user must hold a value.
    pub required: bool,
    /// Whether reading it asks for more than the right to view users.
    pub sensitive: bool,
    /// Whether it is returned with each user in a listing.
    pub listed: bool,
}

/// `PATCH …/user-attributes/{namespace}/{key}`: a change to a declared
/// field, naming only what changes.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChangeAttribute {
    /// A new label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// A replacement list of options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    /// Whether every user must hold a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// One declared field, as `GET …/user-attributes` and the changes answer.
#[derive(Debug, Clone, Deserialize)]
pub struct DeclaredAttribute {
    /// `user` or `app`.
    pub namespace: String,
    /// The fixed internal name.
    pub key: String,
    /// What the field holds.
    pub kind: String,
    /// The label shown beside it.
    pub display_name: String,
    /// The options to choose from, empty when values are typed.
    pub options: Vec<String>,
    /// Whether every user must hold a value.
    pub required: bool,
    /// Whether reading it asks for more than the right to view users.
    pub sensitive: bool,
    /// Whether it was withdrawn from use, its values kept.
    pub archived: bool,
}

/// One kind a field may be declared as, from `GET …/user-attributes/kinds`.
#[derive(Debug, Clone, Deserialize)]
pub struct AttributeKindEntry {
    /// The kind, such as `single_choice`.
    pub kind: String,
    /// Whether it needs a list of options.
    pub requires_options: bool,
    /// Whether a lowest and highest value may be set.
    pub supports_range: bool,
}

/// `PUT …/user-attributes/{namespace}/{key}/status`.
#[derive(Debug, Clone, Serialize)]
pub struct AttributeStatus {
    /// `true` withdraws the field, keeping its values; `false` brings it
    /// back.
    pub archived: bool,
}

/// What `DELETE …/user-attributes/{namespace}/{key}` discarded.
#[derive(Debug, Clone, Deserialize)]
pub struct AttributeDeleted {
    /// How many stored values went with the field.
    pub values_discarded: u64,
}

/// `PUT …/users/{id}/attributes/{namespace}/{key}`: the value to keep;
/// `null` clears it.
#[derive(Debug, Clone, Serialize)]
pub struct AttributeValue {
    /// The value, or null to clear it.
    pub value: Value,
}

/// `GET …/users/{id}/attributes`: a person's values the caller may read.
#[derive(Debug, Clone, Deserialize)]
pub struct AttributeValues {
    /// The values, by `<namespace>.<key>`.
    pub values: Map<String, Value>,
}
