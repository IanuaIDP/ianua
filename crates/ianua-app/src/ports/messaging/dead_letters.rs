//! Dead letters: messages a subscription's service never acknowledged,
//! set aside once their deliveries ran out.

use async_trait::async_trait;
use ianua_domain::domains::messaging::topic::RetentionPolicy;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{Page, PageRequest, SortKey, SortKeys};
use crate::ports::messaging::{ConsumerRead, ReceivedMessage};

/// Which dead letter of a consumer: its place in the consumer's dead
/// letters, as the bus numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeadLetterId(u64);

impl DeadLetterId {
    /// The dead letter numbered `sequence`.
    #[must_use]
    pub fn new(sequence: u64) -> Self {
        Self(sequence)
    }

    /// Its number.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// A message set aside.
#[derive(Debug, Clone)]
pub struct DeadLetter {
    /// Which dead letter it is.
    pub id: DeadLetterId,
    /// The message itself.
    pub message: ReceivedMessage,
    /// How many times it was delivered before it was set aside.
    pub delivered: u32,
    /// When it was set aside.
    pub set_aside_at: OffsetDateTime,
}

define_sort_field! {
    /// The one order a consumer's dead letters are listed in: by the bus's
    /// number, oldest first.
    pub enum DeadLetterSortField {
        /// Order by the number the bus gave the dead letter.
        Sequence => "sequence",
    }
    default = Sequence;
}

impl SortKeys<DeadLetterSortField> for DeadLetter {
    fn sort_key(&self, field: DeadLetterSortField) -> SortKey {
        match field {
            DeadLetterSortField::Sequence => self.id.get().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id.get().into()
    }
}

/// What came of putting a dead letter back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// It is delivered again, with its delivery count starting over.
    Requeued,
    /// The consumer holds no such dead letter.
    NotHeld,
}

/// Dyn-safe port for the dead letters the bus keeps for each subscription's
/// consumer, in the tenant's own space on the bus.
#[async_trait]
pub trait DeadLetters: Send + Sync {
    /// One page of `consumer_name`'s dead letters, oldest first, without
    /// those past `retention` counted from when the bus first took the
    /// message, which are removed as they are found.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the bus cannot be read, or a letter past
    /// its limit cannot be removed.
    async fn list(
        &self,
        tenant_id: &TenantId,
        consumer_name: &str,
        retention: RetentionPolicy,
        page: &PageRequest,
    ) -> Result<Page<DeadLetter>, DomainError>;

    /// Puts dead letter `id` back on the topic `read` names for that consumer
    /// alone, and removes it from the dead letters. A letter past the
    /// retention is removed and answered as not held.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` if the bus refuses.
    async fn replay(
        &self,
        tenant_id: &TenantId,
        read: ConsumerRead<'_>,
        id: DeadLetterId,
    ) -> Result<Replay, DomainError>;
}
