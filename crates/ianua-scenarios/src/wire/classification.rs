//! A tenant's data classification: which fields of an app's answers are
//! sensitive, how sensitive, and what the gateway does to each.

use serde::{Deserialize, Serialize};

/// How sensitive a field is, lowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DataClass {
    /// Anyone may see it.
    Public,
    /// For people inside the tenant.
    Internal,
    /// Personal or financial data.
    Confidential,
    /// Secrets and health records.
    Restricted,
}

/// What the gateway does to a classified field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Redaction {
    /// Takes the field out.
    Remove,
    /// Replaces its value with a mask.
    Mask,
    /// Replaces its value with a keyed digest.
    Hash,
    /// Asks for encryption, which the platform refuses.
    Encrypt,
}

/// `GET …/classification`: the tenant's rule set.
#[derive(Debug, Clone, Deserialize)]
pub struct Classification {
    /// The rule set's id, absent until the first rule.
    pub id: Option<String>,
    /// Every rule.
    pub rules: Vec<ClassificationRule>,
}

/// One rule of the set.
#[derive(Debug, Clone, Deserialize)]
pub struct ClassificationRule {
    /// Handle used to change or remove this field's classification.
    pub id: String,
    /// The dotted path of the field, such as `patient.ssn`.
    pub field_path: String,
    /// How sensitive the field is.
    pub level: DataClass,
    /// What the gateway does to it.
    pub redaction: Redaction,
}

/// `POST …/classification/rules`.
#[derive(Debug, Clone, Serialize)]
pub struct NewClassificationRule {
    /// The dotted path of the field.
    pub field_path: String,
    /// How sensitive it is.
    pub level: DataClass,
    /// What the gateway does to it.
    pub redaction: Redaction,
}

/// `PUT …/classification/rules/{id}`: the rule's level and redaction from
/// now on.
#[derive(Debug, Clone, Serialize)]
pub struct ClassificationChange {
    /// How sensitive the field is.
    pub level: DataClass,
    /// What the gateway does to it.
    pub redaction: Redaction,
}
