//! A tenant's memories as the API answers them, the bodies that make and
//! delete one, and a page of a memory's texts.

use serde::{Deserialize, Serialize};

/// `POST …/memories`: a memory filled by the platform's embedding server,
/// or by a provider's embedding model when `provider_id` is set.
#[derive(Debug, Clone, Serialize)]
pub struct NewMemory {
    /// Its name for people.
    pub name: String,
    /// The provider filling it, if not the platform's server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// The most sensitive data its texts may hold, such as `Internal`.
    pub clearance: String,
}

/// `POST …/memories/{id}/delete`: its name, typed to confirm.
#[derive(Debug, Clone, Serialize)]
pub struct DeleteMemory {
    /// The memory's name as typed.
    pub name: String,
}

/// One memory, never its texts.
#[derive(Debug, Clone, Deserialize)]
pub struct Memory {
    /// Handle used to list entries or request deletion of this collection.
    pub id: String,
    /// Label people select and type to confirm deletion.
    pub name: String,
    /// `platform` or `provider`.
    pub embedding_source: String,
    /// The embedding model that fills it.
    pub embedding_model: String,
    /// How many numbers each of its vectors holds.
    pub vector_size: u16,
    /// `active` or `deletion_requested`.
    pub status: String,
    /// When it is deleted for good, while it waits to be.
    pub deleted_after: Option<String>,
}

/// One text a memory keeps, without its vector.
#[derive(Debug, Clone, Deserialize)]
pub struct MemoryEntry {
    /// Handle identifying the stored entry within its collection.
    pub id: String,
    /// Original content retained alongside its search embedding.
    pub text: String,
    /// The most sensitive data it may hold, such as `Internal`.
    pub exposure: String,
    /// When it was kept.
    pub kept_at: String,
}

/// `GET …/memories/{id}/entries`: one page of texts, oldest first.
#[derive(Debug, Clone, Deserialize)]
pub struct MemoryEntryPage {
    /// The texts.
    pub entries: Vec<MemoryEntry>,
    /// Where the next page starts, if one follows.
    pub next: Option<String>,
}
