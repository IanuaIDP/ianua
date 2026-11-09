//! The records of a memory: made, set to be deleted, brought back, and
//! deleted for good once its waiting period is over.

use time::OffsetDateTime;

use crate::domains::workflows::memory::source::EmbeddingSource;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::tenant_event;
use crate::types::event_type::WorkflowsEvent;
use crate::types::{EventLabel, MemoryId};

/// The reference kind for a memory.
const MEMORY: RefKind = RefKind::new("memory");

/// Which memory an event is about.
#[derive(Debug, Clone)]
pub(crate) struct MemoryRef {
    /// The collection whose lifecycle change is recorded.
    pub(crate) memory_id: MemoryId,
    /// Its name when the event fired.
    pub(crate) label: EventLabel,
}

impl MemoryRef {
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "memory",
            Reference::new(MEMORY, self.memory_id.to_string(), self.label.as_str()),
        )
    }
}

/// A memory was made.
#[derive(Debug)]
pub struct MemoryCreated {
    /// The newly created collection and its captured display label.
    pub(crate) memory: MemoryRef,
    /// Where its vectors come from.
    pub(crate) source: EmbeddingSource,
    /// When it was made.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MemoryCreated => WorkflowsEvent::MemoryCreated,
    fn payload(&self) -> EventData {
        self.memory
            .payload()
            .field("embedding_source", self.source.kind_str())
            .field("embedding_model", self.source.model().as_str().to_owned())
    }
}

/// A memory was set to be deleted once its waiting period is over.
#[derive(Debug)]
pub struct MemoryDeletionRequested {
    /// The collection scheduled for removal after its waiting period.
    pub(crate) memory: MemoryRef,
    /// When it is deleted for good, unless brought back first.
    pub(crate) deleted_after: OffsetDateTime,
    /// When it was set to be deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MemoryDeletionRequested => WorkflowsEvent::MemoryDeletionRequested,
    fn payload(&self) -> EventData {
        self.memory
            .payload()
            .field("deleted_after", self.deleted_after.to_string())
    }
}

/// A memory set to be deleted was brought back.
#[derive(Debug)]
pub struct MemoryRestored {
    /// The collection recovered before its pending deletion became permanent.
    pub(crate) memory: MemoryRef,
    /// When it was brought back.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MemoryRestored => WorkflowsEvent::MemoryRestored,
    fn payload(&self) -> EventData {
        self.memory.payload()
    }
}

/// A memory and every text it kept were deleted for good.
#[derive(Debug)]
pub struct MemoryPurged {
    /// The collection whose retained passages were permanently removed.
    pub(crate) memory: MemoryRef,
    /// When it was deleted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    MemoryPurged => WorkflowsEvent::MemoryPurged,
    fn payload(&self) -> EventData {
        self.memory.payload()
    }
}
