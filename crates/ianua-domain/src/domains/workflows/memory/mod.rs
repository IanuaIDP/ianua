//! Memory: a tenant's named store of texts and their vectors, which a
//! workflow step adds to and a later one searches for the most similar.
//! Each support ticket is kept, and the next one finds the three most
//! alike for the agent answering it.
//!
//! A memory keeps the embedding model that fills it, since a vector means
//! something only beside vectors of the same model. A company's data never
//! goes away by itself: only someone who may delete workflows deletes a
//! memory, typing its name to confirm, and it is kept for
//! [`DELETION_WAITING_DAYS`] days in which it can be brought back before
//! it and every text it keeps are deleted for good.

pub mod entry;
pub mod events;
pub mod source;

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::memory::events::{
    MemoryCreated, MemoryDeletionRequested, MemoryPurged, MemoryRef, MemoryRestored,
};
use crate::domains::workflows::memory::source::{EmbeddingSource, VectorSize};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::types::{EventLabel, Human, Label, MemoryId};

/// How long a memory set to be deleted is kept, in which it can be brought
/// back.
pub const DELETION_WAITING_DAYS: i64 = 30;

/// The built-in integration whose operations keep texts in and search a
/// memory; the platform runs them itself.
pub const MEMORY_INTEGRATION: &str = "memory";

/// The operation keeping its `text` in the memory a step names.
pub const REMEMBER: &str = "remember";

/// The operation finding the texts of a memory most like its `text`.
pub const FIND_SIMILAR: &str = "find-similar";

/// The input naming the text a memory operation keeps or searches with.
pub const TEXT_INPUT: &str = "text";

/// The input naming how many texts a search finds.
pub const COUNT_INPUT: &str = "count";

/// Whether a memory is in use or waiting to be deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryStatus {
    /// Steps keep texts in it and search it.
    Active,
    /// Set to be deleted: nothing is kept in or found in it, and it is
    /// deleted for good after this moment unless brought back first.
    DeletionRequested {
        /// When it is deleted for good.
        deleted_after: OffsetDateTime,
    },
}

impl MemoryStatus {
    /// Moves to `to` if a memory in this status may: an active memory may be
    /// set to be deleted, and one set to be deleted may be brought back.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!(
                (from, to),
                (Self::Active, Self::DeletionRequested { .. })
                    | (Self::DeletionRequested { .. }, Self::Active)
            )
        })
    }

    /// The stored name, `active` or `deletion_requested`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::DeletionRequested { .. } => "deletion_requested",
        }
    }
}

/// The values a memory is made with.
pub struct CreateMemoryParams {
    /// Its name for people, such as "Support tickets".
    pub name: Label,
    /// Where its vectors come from.
    pub source: EmbeddingSource,
    /// How long its vectors are, as its embedding model makes them.
    pub vector_size: VectorSize,
    /// The most sensitive data its texts may hold.
    pub clearance: DataClassLevel,
}

/// A memory as stored.
pub struct MemoryRow {
    /// The persisted identity referenced by entries and workflow memory steps.
    pub id: MemoryId,
    /// The display label used when people choose a passage collection.
    pub name: Label,
    /// Where its vectors come from.
    pub source: EmbeddingSource,
    /// How long its vectors are.
    pub vector_size: VectorSize,
    /// The most sensitive data its texts may hold.
    pub clearance: DataClassLevel,
    /// Whether it is in use or waiting to be deleted.
    pub status: MemoryStatus,
    /// The person who made it.
    pub created_by: Human,
    /// When it was made.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// A tenant's named store of texts and their vectors.
#[derive(Debug, Clone)]
pub struct Memory<T: TenantScope> {
    id: MemoryId,
    name: Label,
    source: EmbeddingSource,
    vector_size: VectorSize,
    clearance: DataClassLevel,
    status: MemoryStatus,
    created_by: Human,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> Memory<T> {
    /// `by` makes a memory, empty. Raises `workflows.memory_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not create workflows.
    pub fn create(
        params: CreateMemoryParams,
        by: &WorkflowControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(WorkflowAction::Create)?;
        let now = crate::shared::clock::now();
        let mut memory = Self {
            id: MemoryId::new(),
            name: params.name,
            source: params.source,
            vector_size: params.vector_size,
            clearance: params.clearance,
            status: MemoryStatus::Active,
            created_by: by.by().clone(),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        memory.raised.raise(MemoryCreated {
            memory: memory.memory_ref(),
            source: memory.source.clone(),
            occurred_at: now,
        });
        Ok(memory)
    }

    /// Rebuilds a memory from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when it changed before it was
    ///   made, or is set to be deleted sooner than its waiting period after
    ///   it last changed.
    pub fn reconstitute(row: MemoryRow) -> Result<Self, DomainError> {
        let waited_long_enough = match row.status {
            MemoryStatus::Active => true,
            MemoryStatus::DeletionRequested { deleted_after } => {
                deleted_after
                    >= row
                        .updated_at
                        .saturating_add(Duration::days(DELETION_WAITING_DAYS))
            }
        };
        RowCheck::of("memory")
            .in_order(row.created_at, row.updated_at, "changed before it was made")
            .holds(
                waited_long_enough,
                "set to be deleted before its waiting period",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            name: row.name,
            source: row.source,
            vector_size: row.vector_size,
            clearance: row.clearance,
            status: row.status,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Sets the memory to be deleted after [`DELETION_WAITING_DAYS`] days,
    /// once `by` typed its name as `typed`. Nothing is kept in or found in
    /// it meanwhile. Raises `workflows.memory_deletion_requested`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete workflows.
    /// - [`DomainError::Validation`] when `typed` is not its name.
    /// - [`DomainError::InvalidTransition`] when it is set to be deleted
    ///   already.
    pub fn request_deletion(
        &mut self,
        typed: &str,
        by: &WorkflowControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Delete)?;
        if typed.trim() != self.name.as_str() {
            return Err(DomainError::invalid(message!(
                "workflows-type-the-memory-s-name-to-delete-it",
                "type the memory's name exactly to delete it"
            )));
        }
        let now = crate::shared::clock::now();
        let deleted_after = now.saturating_add(Duration::days(DELETION_WAITING_DAYS));
        self.status = self
            .status
            .try_transition(MemoryStatus::DeletionRequested { deleted_after })
            .map_err(|_| {
                DomainError::invalid_transition(message!(
                    "workflows-the-memory-is-set-to-be-deleted-already",
                    "the memory is set to be deleted already"
                ))
            })?;
        self.updated_at = now;
        self.raised.raise(MemoryDeletionRequested {
            memory: self.memory_ref(),
            deleted_after,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Brings back a memory set to be deleted, with every text it kept.
    /// Raises `workflows.memory_restored`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not delete workflows.
    /// - [`DomainError::InvalidTransition`] when it is not set to be
    ///   deleted.
    pub fn restore(&mut self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(WorkflowAction::Delete)?;
        self.status = self
            .status
            .try_transition(MemoryStatus::Active)
            .map_err(|_| {
                DomainError::invalid_transition(message!(
                    "workflows-the-memory-is-not-set-to-be-deleted",
                    "the memory is not set to be deleted"
                ))
            })?;
        self.updated_at = crate::shared::clock::now();
        self.raised.raise(MemoryRestored {
            memory: self.memory_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Marks the memory deleted for good, once its waiting period is over
    /// at `now`; the caller deletes it and every text it kept. Raises
    /// `workflows.memory_purged`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not set to be
    ///   deleted, or its waiting period is not over.
    pub fn purge(&mut self, now: OffsetDateTime) -> Result<(), DomainError> {
        let MemoryStatus::DeletionRequested { deleted_after } = self.status else {
            return Err(DomainError::invalid_transition(message!(
                "workflows-the-memory-is-not-set-to-be-deleted",
                "the memory is not set to be deleted"
            )));
        };
        if now < deleted_after {
            return Err(DomainError::invalid_transition(message!(
                "workflows-the-memory-s-waiting-period-is-not-over",
                "the memory's waiting period is not over"
            )));
        }
        self.raised.raise(MemoryPurged {
            memory: self.memory_ref(),
            occurred_at: now,
        });
        Ok(())
    }

    /// Refuses a memory set to be deleted, in which nothing is kept or
    /// found.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is set to be deleted.
    pub fn ensure_active(&self) -> Result<(), DomainError> {
        match self.status {
            MemoryStatus::Active => Ok(()),
            MemoryStatus::DeletionRequested { .. } => Err(DomainError::invalid(message!(
                "workflows-the-memory-is-set-to-be-deleted",
                "the memory is set to be deleted, so nothing is kept in or found in it"
            ))),
        }
    }

    /// Refuses a text exposed to data more sensitive than the memory may
    /// keep, so a memory cleared for internal data never takes HR records.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `exposure` is above its clearance.
    pub fn ensure_clears(&self, exposure: DataClassLevel) -> Result<(), DomainError> {
        if exposure <= self.clearance {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "workflows-the-memory-is-not-cleared-for-this-data",
            "the memory is not cleared for data this sensitive"
        )))
    }

    fn memory_ref(&self) -> MemoryRef {
        MemoryRef {
            memory_id: self.id,
            label: EventLabel::of(self.name.as_str()),
        }
    }

    /// The stable identity referenced by entries and workflow memory steps.
    #[must_use]
    pub fn id(&self) -> &MemoryId {
        &self.id
    }

    /// Its name for people.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Where its vectors come from.
    #[must_use]
    pub fn source(&self) -> &EmbeddingSource {
        &self.source
    }

    /// How long its vectors are.
    #[must_use]
    pub fn vector_size(&self) -> VectorSize {
        self.vector_size
    }

    /// The most sensitive data its texts may hold.
    #[must_use]
    pub fn clearance(&self) -> DataClassLevel {
        self.clearance
    }

    /// Whether it is in use or waiting to be deleted.
    #[must_use]
    pub fn status(&self) -> MemoryStatus {
        self.status
    }

    /// The person who made it.
    #[must_use]
    pub fn created_by(&self) -> &Human {
        &self.created_by
    }
}

impl<T: TenantScope> Raises for Memory<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for Memory<T> {
    type Id = MemoryId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::execution::model_provider::ModelName;
    use crate::domains::workflows::execution::tests::fixtures::{
        ann, bob, holding_only, managing, viewing,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};

    fn tickets_params() -> CreateMemoryParams {
        CreateMemoryParams {
            name: Label::new("name", "Support tickets").unwrap(),
            source: EmbeddingSource::Platform(ModelName::new("bge-small-en-v1.5").unwrap()),
            vector_size: VectorSize::new(384).unwrap(),
            clearance: DataClassLevel::Internal,
        }
    }

    /// Ann's support tickets memory, its making taken out.
    fn tickets() -> Memory<ResolvedTenant> {
        let ann = ann();
        let mut memory = Memory::create(tickets_params(), &managing(&ann)).unwrap();
        raised(&mut memory);
        memory
    }

    fn row_of(memory: &Memory<ResolvedTenant>) -> MemoryRow {
        MemoryRow {
            id: memory.id,
            name: memory.name.clone(),
            source: memory.source.clone(),
            vector_size: memory.vector_size,
            clearance: memory.clearance,
            status: memory.status,
            created_by: memory.created_by.clone(),
            created_at: memory.created_at,
            updated_at: memory.updated_at,
        }
    }

    /// Ann makes a memory for support tickets: it is active, keeps the
    /// embedding model that fills it, and its making is recorded.
    #[test]
    fn a_memory_is_made_active_with_its_embedding_model() {
        let ann = ann();

        let mut memory =
            Memory::<ResolvedTenant>::create(tickets_params(), &managing(&ann)).unwrap();

        assert_eq!(memory.status(), MemoryStatus::Active);
        assert_eq!(memory.source().model().as_str(), "bge-small-en-v1.5");
        assert_eq!(raised_names(&mut memory), ["workflows.memory_created"]);
    }

    /// Workflow viewing rights do not authorize memory creation.
    #[test]
    fn a_viewer_makes_no_memory() {
        let sam = bob();

        let made = Memory::<ResolvedTenant>::create(tickets_params(), &viewing(&sam));

        assert!(matches!(made, Err(DomainError::Forbidden(_))));
    }

    /// Ann deletes the memory, typing its name. It is set to be deleted after
    /// the waiting period, keeps nothing new meanwhile, and the request is
    /// recorded.
    #[test]
    fn deleting_waits_and_stops_new_texts() {
        let ann = ann();
        let mut memory = tickets();

        memory
            .request_deletion("Support tickets", &managing(&ann))
            .unwrap();

        let MemoryStatus::DeletionRequested { deleted_after } = memory.status() else {
            panic!("the memory waits to be deleted");
        };
        assert_eq!(
            deleted_after,
            memory.updated_at + Duration::days(DELETION_WAITING_DAYS)
        );
        assert!(memory.ensure_active().is_err());
        assert_eq!(
            raised_names(&mut memory),
            ["workflows.memory_deletion_requested"]
        );
    }

    /// A deletion request with a mistyped name is rejected, leaving the memory
    /// active.
    #[test]
    fn a_mistyped_name_deletes_nothing() {
        let ann = ann();
        let mut memory = tickets();

        let deleted = memory.request_deletion("Support", &managing(&ann));

        assert!(matches!(deleted, Err(DomainError::Validation(_))));
        assert_eq!(memory.status(), MemoryStatus::Active);
    }

    /// Workflow creation rights do not authorize requesting a memory's deletion.
    #[test]
    fn only_someone_who_may_delete_workflows_deletes_a_memory() {
        let bob = bob();
        let mut memory = tickets();

        let deleted = memory.request_deletion(
            "Support tickets",
            &holding_only(&bob, WorkflowAction::Create),
        );

        assert!(matches!(deleted, Err(DomainError::Forbidden(_))));
    }

    /// Ann changes her mind within the waiting period and brings the memory
    /// back: it is active again, and that is recorded.
    #[test]
    fn a_memory_is_brought_back_within_its_waiting_period() {
        let ann = ann();
        let mut memory = tickets();
        memory
            .request_deletion("Support tickets", &managing(&ann))
            .unwrap();
        raised(&mut memory);

        memory.restore(&managing(&ann)).unwrap();

        assert_eq!(memory.status(), MemoryStatus::Active);
        assert_eq!(raised_names(&mut memory), ["workflows.memory_restored"]);
    }

    /// Purging one day before the waiting period ends fails. At its exact end,
    /// the purge succeeds and raises one memory-purged event.
    #[test]
    fn a_memory_is_deleted_for_good_only_after_its_waiting_period() {
        let ann = ann();
        let mut memory = tickets();
        memory
            .request_deletion("Support tickets", &managing(&ann))
            .unwrap();
        raised(&mut memory);
        let MemoryStatus::DeletionRequested { deleted_after } = memory.status() else {
            panic!("the memory waits to be deleted");
        };

        let early = memory.purge(deleted_after - Duration::days(1));
        memory.purge(deleted_after).unwrap();

        assert!(matches!(early, Err(DomainError::InvalidTransition(_))));
        assert_eq!(raised_names(&mut memory), ["workflows.memory_purged"]);
    }

    /// Purging an active memory fails even a year after its creation.
    #[test]
    fn an_active_memory_is_never_purged() {
        let mut memory = tickets();

        let purged = memory.purge(memory.created_at + Duration::days(365));

        assert!(matches!(purged, Err(DomainError::InvalidTransition(_))));
    }

    /// An internally cleared memory accepts internal exposure and rejects
    /// confidential exposure.
    #[test]
    fn a_memory_keeps_no_data_above_its_clearance() {
        let memory = tickets();

        assert!(memory.ensure_clears(DataClassLevel::Internal).is_ok());
        assert!(matches!(
            memory.ensure_clears(DataClassLevel::Confidential),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A stored deletion deadline only one day after the last change is
    /// rejected as corrupt because it shortens the waiting period.
    #[test]
    fn a_stored_memory_deleted_early_is_corrupt() {
        let memory = tickets();
        let row = MemoryRow {
            status: MemoryStatus::DeletionRequested {
                deleted_after: memory.updated_at + Duration::days(1),
            },
            ..row_of(&memory)
        };

        assert!(refused_as_corrupt(&Memory::<ResolvedTenant>::reconstitute(
            row
        )));
    }
}
