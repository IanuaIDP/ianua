//! The name a step goes by inside its workflow.

use crate::domains::workflows::data::FieldName;
use crate::domains::workflows::design::node::TRIGGER_FIELD;
use crate::message;
use crate::shared::validation::{Charset, Rule, ValidationError, Validator};

/// The name a step goes by inside its workflow.
///
/// Edges name the step by it. Later steps find its output under it. It uses
/// lowercase letters, digits, `-` and `_`. It is never `trigger`, which
/// names the trigger's own data. It holds the [`FieldName`] its output is
/// found under, so it is always a valid field name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeKey(FieldName);

impl NodeKey {
    /// Checks `value` against a node key's rules.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] for the first rule the value breaks.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        Validator::new("node_key", &value)
            .length(1..=64)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN | Charset::UNDERSCORE)
            .rule(&NotTheTriggerField)
            .validate_first()?;
        Ok(Self(FieldName::new(value)?))
    }

    /// The key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The field this step's output is found under.
    #[must_use]
    pub fn as_field(&self) -> &FieldName {
        &self.0
    }
}

impl std::fmt::Display for NodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

struct NotTheTriggerField;

impl Rule for NotTheTriggerField {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        (value == TRIGGER_FIELD).then(|| ValidationError::Custom {
            field,
            code: "reserved".to_owned(),
            message: message!(
                "workflows-names-the-trigger-s-data-not",
                format!("`{TRIGGER_FIELD}` names the trigger's data, not a step")
            ),
        })
    }
}
