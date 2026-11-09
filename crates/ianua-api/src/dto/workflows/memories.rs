//! Memories on the wire: a memory, the body that makes one, the body
//! confirming its deletion with its name, and a page of its texts.

use ianua_app::use_cases::workflows::memories;
use ianua_app::use_cases::workflows::memories::MemorySourceChoice;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::memory::entry::{EntryPage, KeptEntry, NextPage};
use ianua_domain::domains::workflows::memory::source::EmbeddingSource;
use ianua_domain::domains::workflows::memory::{Memory, MemoryStatus};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{Label, MemoryId, ModelProviderId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::workflows::data::person_label;
use crate::error::ApiError;

/// Request body for making a memory.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateMemoryBody {
    /// Its name for people, such as `Support tickets`.
    pub name: String,
    /// The tenant's model provider whose embedding model fills it; left out
    /// for the platform's own embedding server.
    #[serde(default)]
    pub provider_id: Option<Uuid>,
    /// The most sensitive data its texts may hold: `Public`, `Internal`,
    /// `Confidential` or `Restricted`.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub clearance: DataClassLevel,
}

impl TryFrom<CreateMemoryBody> for memories::CreateRequest {
    type Error = ApiError;

    fn try_from(body: CreateMemoryBody) -> Result<Self, ApiError> {
        let source = body.provider_id.map_or(MemorySourceChoice::Platform, |id| {
            MemorySourceChoice::Provider(ModelProviderId::from_uuid(id))
        });
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            source,
            clearance: body.clearance,
        })
    }
}

/// Request body for deleting a memory: its name, typed to confirm.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DeleteMemoryBody {
    /// The memory's name, exactly.
    pub name: String,
}

impl DeleteMemoryBody {
    /// The deletion of `memory_id` this body confirms.
    #[must_use]
    pub(crate) fn into_request(self, memory_id: MemoryId) -> memories::DeleteRequest {
        memories::DeleteRequest {
            memory_id,
            typed_name: self.name,
        }
    }
}

/// One memory: never its texts.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MemoryResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// Its name for people.
    pub name: String,
    /// `platform` for the platform's embedding server, or `provider`.
    pub embedding_source: &'static str,
    /// The provider filling it, when `embedding_source` is `provider`.
    pub provider_id: Option<Uuid>,
    /// The embedding model that fills it.
    pub embedding_model: String,
    /// How many numbers each of its vectors holds.
    pub vector_size: u16,
    /// The most sensitive data its texts may hold.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub clearance: DataClassLevel,
    /// `active`, or `deletion_requested` while it waits to be deleted.
    pub status: &'static str,
    /// When it is deleted for good, while it waits to be.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub deleted_after: Option<OffsetDateTime>,
    /// The person who made it, as `<kind>:<uuid>`.
    pub created_by: String,
    /// When it was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Memory<ResolvedTenant>> for MemoryResponse {
    fn from(memory: Memory<ResolvedTenant>) -> Self {
        let provider_id = match memory.source() {
            EmbeddingSource::Provider { provider_id, .. } => Some(*provider_id.as_uuid()),
            EmbeddingSource::Platform(_) => None,
        };
        let deleted_after = match memory.status() {
            MemoryStatus::DeletionRequested { deleted_after } => Some(deleted_after),
            MemoryStatus::Active => None,
        };
        Self {
            id: *memory.id().as_uuid(),
            name: memory.name().as_str().to_owned(),
            embedding_source: memory.source().kind_str(),
            provider_id,
            embedding_model: memory.source().model().as_str().to_owned(),
            vector_size: memory.vector_size().get(),
            clearance: memory.clearance(),
            status: memory.status().as_str(),
            deleted_after,
            created_by: person_label(memory.created_by()),
            created_at: memory.created_at(),
            updated_at: memory.updated_at(),
        }
    }
}

/// One text a memory keeps, without its vector.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MemoryEntryResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The stored source content represented by the entry's embedding.
    pub text: String,
    /// The most sensitive data the text may hold.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub exposure: DataClassLevel,
    /// When it was kept.
    #[serde(with = "time::serde::rfc3339")]
    pub kept_at: OffsetDateTime,
}

impl From<KeptEntry> for MemoryEntryResponse {
    fn from(entry: KeptEntry) -> Self {
        Self {
            id: *entry.id.as_uuid(),
            text: entry.text.as_str().to_owned(),
            exposure: entry.exposure,
            kept_at: entry.kept_at,
        }
    }
}

/// One page of a memory's texts, oldest first.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MemoryEntryPageResponse {
    /// The texts.
    pub entries: Vec<MemoryEntryResponse>,
    /// Where the next page starts, passed back as `from`; absent on the
    /// last page.
    pub next: Option<Uuid>,
}

impl From<EntryPage> for MemoryEntryPageResponse {
    fn from(page: EntryPage) -> Self {
        let next = match page.next {
            NextPage::At(entry) => Some(*entry.as_uuid()),
            NextPage::Done => None,
        };
        Self {
            entries: page
                .entries
                .into_iter()
                .map(MemoryEntryResponse::from)
                .collect(),
            next,
        }
    }
}
