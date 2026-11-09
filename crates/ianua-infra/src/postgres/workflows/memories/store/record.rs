//! A memory as its row holds it: read back into the aggregate, and written
//! out from it.

use ianua_domain::domains::agents::execution::model_provider::ModelName;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::memory::source::{EmbeddingSource, VectorSize};
use ianua_domain::domains::workflows::memory::{Memory, MemoryRow, MemoryStatus};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{Label, MemoryId, ModelProviderId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;

const MEMORY: Stored = Stored("memory");

const CREATED_BY: Kept = Kept {
    entity: MEMORY.0,
    column: "created_by",
    shape: 1,
};

/// A memory as it is read. The store's checked queries fill it.
pub(super) struct MemoryRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) embedding_source: String,
    pub(super) provider_id: Option<Uuid>,
    pub(super) embedding_model: String,
    pub(super) vector_size: i32,
    pub(super) clearance: String,
    pub(super) status: String,
    pub(super) deleted_after: Option<OffsetDateTime>,
    pub(super) created_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl MemoryRecord {
    /// The memory the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the memory
    /// keeps.
    pub(super) fn into_memory(self) -> Result<Memory<ResolvedTenant>, DomainError> {
        let source = self.source()?;
        let status = self.status()?;
        let vector_size = u16::try_from(self.vector_size)
            .ok()
            .and_then(|size| VectorSize::new(size).ok())
            .ok_or_else(|| DomainError::corrupt_row(MEMORY.0, "a vector size no memory keeps"))?;
        Memory::reconstitute(MemoryRow {
            id: MemoryId::from_uuid(self.id),
            name: MEMORY.value("name", Label::new("name", self.name))?,
            source,
            vector_size,
            clearance: DataClassLevel::from_stored(&self.clearance)?,
            status,
            created_by: CREATED_BY.open(self.created_by)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    /// Where the record says the memory's vectors come from.
    fn source(&self) -> Result<EmbeddingSource, DomainError> {
        let model = MEMORY.value(
            "embedding model",
            ModelName::new(self.embedding_model.clone()),
        )?;
        match (self.embedding_source.as_str(), self.provider_id) {
            ("platform", None) => Ok(EmbeddingSource::Platform(model)),
            ("provider", Some(id)) => Ok(EmbeddingSource::Provider {
                provider_id: ModelProviderId::from_uuid(id),
                model,
            }),
            _ => Err(DomainError::corrupt_row(
                MEMORY.0,
                "an unknown embedding source",
            )),
        }
    }

    /// Whether the record says the memory is active or waits to be deleted.
    fn status(&self) -> Result<MemoryStatus, DomainError> {
        match (self.status.as_str(), self.deleted_after) {
            ("active", None) => Ok(MemoryStatus::Active),
            ("deletion_requested", Some(deleted_after)) => {
                Ok(MemoryStatus::DeletionRequested { deleted_after })
            }
            _ => Err(DomainError::corrupt_row(
                MEMORY.0,
                "an unknown or incomplete status",
            )),
        }
    }
}

/// A memory's columns, as they are written.
pub(super) struct MemoryColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) embedding_source: &'static str,
    pub(super) provider_id: Option<&'a Uuid>,
    pub(super) embedding_model: &'a str,
    pub(super) vector_size: i32,
    pub(super) clearance: &'static str,
    pub(super) status: &'static str,
    pub(super) deleted_after: Option<OffsetDateTime>,
    pub(super) created_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> MemoryColumns<'a> {
    /// The columns `memory` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its maker cannot be
    /// written out.
    pub(super) fn of(memory: &'a Memory<ResolvedTenant>) -> Result<Self, DomainError> {
        let provider_id = match memory.source() {
            EmbeddingSource::Provider { provider_id, .. } => Some(provider_id.as_uuid()),
            EmbeddingSource::Platform(_) => None,
        };
        let deleted_after = match memory.status() {
            MemoryStatus::DeletionRequested { deleted_after } => Some(deleted_after),
            MemoryStatus::Active => None,
        };
        Ok(Self {
            id: memory.id().as_uuid(),
            name: memory.name().as_str(),
            embedding_source: memory.source().kind_str(),
            provider_id,
            embedding_model: memory.source().model().as_str(),
            vector_size: i32::from(memory.vector_size().get()),
            clearance: memory.clearance().as_str(),
            status: memory.status().as_str(),
            deleted_after,
            created_by: CREATED_BY.seal(memory.created_by())?,
            created_at: memory.created_at(),
            updated_at: memory.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{Human, HumanAccount, PersonKey, UserId};

    use super::*;

    fn record(source: &str, provider_id: Option<Uuid>) -> MemoryRecord {
        MemoryRecord {
            id: Uuid::new_v4(),
            name: "Support tickets".to_owned(),
            embedding_source: source.to_owned(),
            provider_id,
            embedding_model: "bge-small-en-v1.5".to_owned(),
            vector_size: 384,
            clearance: "internal".to_owned(),
            status: "active".to_owned(),
            deleted_after: None,
            created_by: serde_json::json!({"v": 1, "value": {
                "account": {"User": "00000000-0000-0000-0000-000000000000"},
                "person": "ann@acme.example"
            }}),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// A memory on the platform's server reads back with its model.
    #[test]
    fn a_platform_memory_reads_back() {
        let memory = record("platform", None).into_memory().unwrap();

        assert_eq!(memory.source().model().as_str(), "bge-small-en-v1.5");
    }

    /// The person who made a memory is written as their account and
    /// address, and read back. A row written now is read for years, so a
    /// change here means raising the column's shape, not this pin.
    #[test]
    fn the_maker_is_stored_in_their_pinned_shape() {
        let ann = Human::new(
            HumanAccount::User(UserId::from_uuid(Uuid::nil())),
            PersonKey::new("ann@acme.example").unwrap(),
        );
        let stored = serde_json::json!({"v": 1, "value": {
            "account": {"User": "00000000-0000-0000-0000-000000000000"},
            "person": "ann@acme.example"
        }});

        assert_eq!(CREATED_BY.seal(&ann).unwrap(), stored);
        assert_eq!(CREATED_BY.open::<Human>(stored).unwrap(), ann);
    }

    /// Reading a provider-backed memory without its provider returns an
    /// infrastructure error.
    #[test]
    fn a_provider_memory_without_its_provider_is_corrupt() {
        let read = record("provider", None).into_memory();

        assert!(
            matches!(read, Err(DomainError::Infrastructure(_))),
            "{read:?}"
        );
    }
}
