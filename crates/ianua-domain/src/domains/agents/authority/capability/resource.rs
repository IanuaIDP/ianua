//! Relations on named resources that a delegation may hold, such as the use
//! of a model provider or a tool.

use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{AgentToolId, ModelProviderId};

text_value! {
    /// A relation one holds on a resource, such as `reader` or `owner`.
    pub struct Relation;
}

impl TextValue for Relation {
    const FIELD: &'static str = "relation";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(128)
    }
}

impl Relation {
    /// Whether holding this relation may let an agent change the object.
    ///
    /// Each tenant picks its own relation names. Only `reader` and `viewer`
    /// are known to be read-only. Any other name counts as one that may
    /// write, to be safe.
    #[must_use]
    pub fn may_write(&self) -> bool {
        !matches!(self.0.as_str(), "reader" | "viewer")
    }
}

text_value! {
    /// The object a relation is held on, such as `calendar:abc123`.
    pub struct ResourceRef;
}

impl TextValue for ResourceRef {
    const FIELD: &'static str = "resource_ref";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.free_text(256)
    }
}

impl ResourceRef {
    /// The resource type the object is of: `calendar` for `calendar:abc123`.
    /// An object named without a type has none.
    #[must_use]
    pub fn type_key(&self) -> Option<&str> {
        self.as_str()
            .split_once(':')
            .map(|(kind, _)| kind)
            .filter(|kind| !kind.is_empty())
    }
}

/// A relation on one named object, such as `reader` on `calendar:abc123`.
///
/// It grants "read this calendar", not every calendar. A delegated one must
/// match one the delegator holds exactly. No relation implies another:
/// holding owner does not hold reader.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceCapability {
    relation: Relation,
    resource_ref: ResourceRef,
}

/// The relation that lets a person spend a tenant resource through an agent
/// run. That is a model provider's key and quota, or a tool's calls.
const USE: &str = "user";

impl ResourceCapability {
    /// The right to run an agent against a model provider, which spends its
    /// key and quota.
    #[must_use]
    pub fn use_of_provider(id: &ModelProviderId) -> Self {
        Self::use_of(format!("model_provider:{id}"))
    }

    /// The right to call a registered tool from an agent run.
    #[must_use]
    pub fn use_of_tool(id: &AgentToolId) -> Self {
        Self::use_of(format!("tool:{id}"))
    }

    fn use_of(object: String) -> Self {
        Self {
            relation: Relation(USE.to_owned()),
            resource_ref: ResourceRef(object),
        }
    }

    /// Creates a relation on one object.
    #[must_use]
    pub fn new(relation: Relation, resource_ref: ResourceRef) -> Self {
        Self {
            relation,
            resource_ref,
        }
    }

    /// The relation held.
    #[must_use]
    pub fn relation(&self) -> &Relation {
        &self.relation
    }

    /// The object the relation is held on.
    #[must_use]
    pub fn resource_ref(&self) -> &ResourceRef {
        &self.resource_ref
    }

    /// Whether this is the same relation on the same object as `other`.
    ///
    /// No relation implies another, so owner does not cover reader.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        self == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The right to use one model provider is the relation `user` on
    /// `model_provider:<id>`, with that provider's own id.
    #[test]
    fn use_of_a_provider_names_that_provider() {
        let id = ModelProviderId::new();

        let cap = ResourceCapability::use_of_provider(&id);

        assert_eq!(cap.relation().as_str(), "user");
        assert_eq!(cap.resource_ref().as_str(), format!("model_provider:{id}"));
    }

    /// Tool and model-provider capabilities remain distinct even when
    /// their resource identifiers contain the same UUID.
    #[test]
    fn use_of_a_tool_is_not_use_of_a_provider_with_the_same_id() {
        let id = uuid::Uuid::now_v7();

        let tool = ResourceCapability::use_of_tool(&AgentToolId::from_uuid(id));
        let provider = ResourceCapability::use_of_provider(&ModelProviderId::from_uuid(id));

        assert_ne!(tool, provider);
    }

    /// `reader` and `viewer` are read-only. `owner`, `editor`, `writer`,
    /// `member` and any name the tenant made up are taken to write.
    #[test]
    fn only_reading_relations_are_known_not_to_write() {
        for relation in ["reader", "viewer"] {
            assert!(!Relation::new(relation).unwrap().may_write(), "{relation}");
        }
        for relation in ["owner", "editor", "writer", "member", "custom-relation"] {
            assert!(Relation::new(relation).unwrap().may_write(), "{relation}");
        }
    }

    /// A stored relation or object reference that is an empty string fails
    /// to load.
    #[cfg(feature = "serde")]
    #[test]
    fn an_empty_relation_or_resource_ref_is_refused() {
        assert!(serde_json::from_str::<Relation>(r#""""#).is_err());
        assert!(serde_json::from_str::<ResourceRef>(r#""""#).is_err());
    }

    /// `calendar:abc123` is a calendar; a name with no type, or an empty
    /// one, has none.
    #[test]
    fn a_resource_names_its_type_before_the_colon() {
        let typed = ResourceRef::new("calendar:abc123").unwrap();
        let untyped = ResourceRef::new("abc123").unwrap();
        let empty = ResourceRef::new(":abc123").unwrap();

        assert_eq!(typed.type_key(), Some("calendar"));
        assert_eq!(untyped.type_key(), None);
        assert_eq!(empty.type_key(), None);
    }
}
