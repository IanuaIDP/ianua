//! Applying a configuration document to a tenant's gateway, as one change.
//!
//! A document creates, changes and removes services, pipelines and routes
//! in one go. Each is written through the same steps as changing it by
//! hand, but the person made one change, the document. So one record
//! covers the whole apply, and the records each resource would raise on
//! its own are not kept.

use std::marker::PhantomData;

use crate::domains::routing::events::GatewayConfigImported;
use crate::isolation::scope::TenantScope;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};

/// Whether an apply may remove what the document does not mention.
///
/// "Apply this file" and "make the gateway be exactly this file" differ by
/// whether traffic stops for a route nobody put in the document, so the two
/// are named rather than told apart by a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportMode {
    /// Create and update what the document names; leave everything else
    /// alone. The default, because a document that omits a route is far more
    /// often incomplete than a demand to take that route down.
    #[default]
    Merge,
    /// Make the gateway match the document exactly, deleting what it omits.
    Replace,
}

impl ImportMode {
    /// The mode as the audit record names it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Replace => "replace",
        }
    }
}

/// How far an applied document reached, counted over services, pipelines
/// and routes together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportedChanges {
    /// How many it created.
    pub created: usize,
    /// How many it changed.
    pub updated: usize,
    /// How many it removed.
    pub deleted: usize,
}

/// A document applied to a tenant's gateway, and the record it leaves.
#[derive(Debug)]
pub struct GatewayImport<T: TenantScope> {
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> GatewayImport<T> {
    /// A document applied in `mode` that reached as far as `changes`, once
    /// every write it made has succeeded. Raises
    /// `routing.gateway_config_imported` with the mode and the counts.
    #[must_use]
    pub fn applied(mode: ImportMode, changes: ImportedChanges) -> Self {
        let mut import = Self {
            raised: Raised::default(),
            _scope: PhantomData,
        };
        import.raised.raise(GatewayConfigImported {
            mode,
            created: changes.created,
            updated: changes.updated,
            deleted: changes.deleted,
            occurred_at: crate::shared::clock::now(),
        });
        import
    }
}

impl<T: TenantScope> Raises for GatewayImport<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::events::raised;

    fn text(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not a scalar: {other:?}"),
        }
    }

    /// Ann replaces the gateway with a document that adds two routes,
    /// changes a service and removes a pipeline. One record covers it, with
    /// the mode and the counts.
    #[test]
    fn an_applied_document_raises_one_record_with_its_mode_and_counts() {
        let mut import = GatewayImport::<ResolvedTenant>::applied(
            ImportMode::Replace,
            ImportedChanges {
                created: 2,
                updated: 1,
                deleted: 1,
            },
        );

        let events = raised(&mut import);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "routing.gateway_config_imported"
        );
        assert_eq!(text(&events[0], "mode"), "replace");
        assert_eq!(
            ["created", "updated", "deleted"].map(|key| text(&events[0], key)),
            ["2", "1", "1"]
        );
    }

    /// The modes are stored as `merge` and `replace`, the names the audit
    /// trail has always used.
    #[test]
    fn each_mode_keeps_the_name_it_is_recorded_under() {
        assert_eq!(ImportMode::Merge.as_str(), "merge");
        assert_eq!(ImportMode::Replace.as_str(), "replace");
    }
}
