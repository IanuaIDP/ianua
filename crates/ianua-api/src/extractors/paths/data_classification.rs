//! The classification rule a tenant request names.

use ianua_domain::types::ClassificationRuleId;
use serde::Deserialize;
use uuid::Uuid;

/// `.../classification/rules/{id}`.
#[derive(Deserialize)]
pub(crate) struct ClassificationRulePath {
    id: Uuid,
}

impl ClassificationRulePath {
    /// The rule named.
    #[must_use]
    pub(crate) fn rule(&self) -> ClassificationRuleId {
        ClassificationRuleId::from_uuid(self.id)
    }
}
