//! Fake for reading the tenant messaging bus: the consumers open on it, the
//! messages they hand out, how each delivery was settled, and the dead
//! letters set aside.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::messaging::topic::RetentionPolicy;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::listing::{Page, PageRequest, SortOrder};
use crate::ports::messaging::{
    Acknowledgement, ConsumerRead, ConsumerSpec, DeadLetter, DeadLetterId, DeadLetterSortField,
    DeadLetters, DeliveryReceipt, MessageConsumer, MessageKey, OpenDelivery, PendingMessage,
    ReceivedMessage, Replay,
};
use crate::test_support::Fake;
use crate::test_support::listing::page;

/// What became of one delivery a [`FakeMessageConsumer`] handed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    /// The service acknowledged it.
    Acknowledged,
    /// It was refused and is delivered again.
    Redelivered,
    /// It was set aside as a dead letter.
    DeadLettered,
}

/// `order 7`, handed out under `receipt` for its `delivered`th time.
#[must_use]
pub fn pending_message(receipt: &str, delivered: u32) -> PendingMessage {
    PendingMessage {
        message: ReceivedMessage {
            key: MessageKey::new(receipt),
            payload: b"order 7".to_vec(),
            headers: Vec::new(),
            message_type: None,
            published_at: clock::now(),
        },
        receipt: DeliveryReceipt::new(receipt),
        delivered,
    }
}

/// `order 7`, set aside as dead letter `sequence` after five deliveries.
#[must_use]
pub fn dead_letter(sequence: u64) -> DeadLetter {
    DeadLetter {
        id: DeadLetterId::new(sequence),
        message: pending_message("spent", 5).message,
        delivered: 5,
        set_aside_at: clock::now(),
    }
}

/// One consumer open on the bus.
struct OpenConsumer {
    tenant: TenantId,
    name: String,
    acknowledgement: Acknowledgement,
}

/// Message consumer that opens every consumer it is asked to, hands every
/// open one the same waiting messages, and remembers how each delivery was
/// settled and which were set aside.
#[derive(Default)]
pub struct FakeMessageConsumer {
    open: Mutex<Vec<OpenConsumer>>,
    pending: Mutex<Vec<PendingMessage>>,
    settled: Mutex<Vec<(DeliveryReceipt, Settlement)>>,
    dead: Mutex<Vec<(String, DeadLetter)>>,
    removed: Mutex<Vec<RetentionPolicy>>,
    retentions: Mutex<Vec<RetentionPolicy>>,
}

impl FakeMessageConsumer {
    /// A bus with no consumer open and no message waiting.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The limits dead letters were last read or replayed under, in order.
    #[must_use]
    pub fn dead_letter_limits(&self) -> Vec<RetentionPolicy> {
        self.retentions.lock().unwrap().clone()
    }

    /// A bus where every open consumer has `pending` waiting.
    #[must_use]
    pub fn holding(pending: Vec<PendingMessage>) -> Self {
        Self {
            pending: Mutex::new(pending),
            ..Self::default()
        }
    }

    /// Every retention rule a removal asked the bus to apply, oldest first.
    #[must_use]
    pub fn removals(&self) -> Vec<RetentionPolicy> {
        self.removed.lock().unwrap().clone()
    }

    /// Opens `name` in `tenant`, as a subscription made earlier did.
    pub fn open(&self, tenant: TenantId, name: &str) {
        self.open.lock().unwrap().push(OpenConsumer {
            tenant,
            name: name.to_owned(),
            acknowledgement: Acknowledgement::OnFetch,
        });
    }

    /// Sets `letter` aside for `consumer_name`, as an earlier delivery did.
    pub fn set_aside(&self, consumer_name: &str, letter: DeadLetter) {
        self.dead
            .lock()
            .unwrap()
            .push((consumer_name.to_owned(), letter));
    }

    /// The names of the consumers open in `tenant`.
    #[must_use]
    pub fn open_in(&self, tenant: TenantId) -> Vec<String> {
        self.open
            .lock()
            .unwrap()
            .iter()
            .filter(|open| open.tenant == tenant)
            .map(|open| open.name.clone())
            .collect()
    }

    /// When the consumer `name` counts a message as taken, if it is open.
    #[must_use]
    pub fn acknowledgement_of(&self, name: &str) -> Option<Acknowledgement> {
        self.open
            .lock()
            .unwrap()
            .iter()
            .find(|open| open.name == name)
            .map(|open| open.acknowledgement)
    }

    /// How every delivery settled so far was settled, in order.
    #[must_use]
    pub fn settled(&self) -> Vec<(DeliveryReceipt, Settlement)> {
        self.settled.lock().unwrap().clone()
    }

    /// The messages still waiting.
    #[must_use]
    pub fn pending(&self) -> Vec<PendingMessage> {
        self.pending.lock().unwrap().clone()
    }

    /// The dead letters `consumer_name` holds.
    #[must_use]
    pub fn dead_letters_of(&self, consumer_name: &str) -> Vec<DeadLetter> {
        self.dead
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name == consumer_name)
            .map(|(_, letter)| letter.clone())
            .collect()
    }

    fn ensure_open(&self, tenant: TenantId, name: &str) -> Result<(), DomainError> {
        if self.open_in(tenant).iter().any(|open| open == name) {
            return Ok(());
        }
        Err(DomainError::infra_msg("no such consumer on the bus"))
    }

    fn taken(&self, receipt: &DeliveryReceipt) -> Option<PendingMessage> {
        let mut pending = self.pending.lock().unwrap();
        let index = pending.iter().position(|held| &held.receipt == receipt)?;
        Some(pending.remove(index))
    }

    fn settle(
        &self,
        tenant: TenantId,
        name: &str,
        receipt: &DeliveryReceipt,
        how: Settlement,
    ) -> Result<Option<PendingMessage>, DomainError> {
        self.ensure_open(tenant, name)?;
        let taken = self.taken(receipt);
        self.settled.lock().unwrap().push((receipt.clone(), how));
        Ok(taken)
    }

    fn next_dead_letter(&self) -> DeadLetterId {
        let held = u64::try_from(self.dead.lock().unwrap().len()).unwrap();
        DeadLetterId::new(held + 1)
    }
}

#[async_trait]
impl MessageConsumer for FakeMessageConsumer {
    async fn ensure_consumer(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer: &ConsumerSpec<'_>,
    ) -> Result<(), DomainError> {
        let mut open = self.open.lock().unwrap();
        if open
            .iter()
            .any(|held| held.tenant == *tenant_id && held.name == consumer.name)
        {
            return Ok(());
        }
        open.push(OpenConsumer {
            tenant: *tenant_id,
            name: consumer.name.to_owned(),
            acknowledgement: consumer.acknowledgement,
        });
        Ok(())
    }

    async fn pull_messages(
        &self,
        tenant_id: &TenantId,
        read: ConsumerRead<'_>,
        max_messages: usize,
    ) -> Result<Vec<ReceivedMessage>, DomainError> {
        self.ensure_open(*tenant_id, read.consumer_name)?;
        let mut pending = self.pending.lock().unwrap();
        let count = max_messages.min(pending.len());
        Ok(pending.drain(..count).map(|held| held.message).collect())
    }

    async fn fetch_pending(
        &self,
        tenant_id: &TenantId,
        read: ConsumerRead<'_>,
        max_messages: usize,
    ) -> Result<Vec<PendingMessage>, DomainError> {
        self.ensure_open(*tenant_id, read.consumer_name)?;
        Ok(self
            .pending
            .lock()
            .unwrap()
            .iter()
            .take(max_messages)
            .cloned()
            .collect())
    }

    async fn remove_lapsed(
        &self,
        _tenant_id: &TenantId,
        _topic_name: &TopicName,
        retention: RetentionPolicy,
    ) -> Result<(), DomainError> {
        self.removed.lock().unwrap().push(retention);
        Ok(())
    }

    async fn open_delivery(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<Option<OpenDelivery>, DomainError> {
        self.ensure_open(*tenant_id, consumer_name)?;
        Ok(self
            .pending
            .lock()
            .unwrap()
            .iter()
            .find(|held| &held.receipt == receipt)
            .map(|held| OpenDelivery {
                delivered: held.delivered,
            }))
    }

    async fn acknowledge(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError> {
        self.settle(*tenant_id, consumer_name, receipt, Settlement::Acknowledged)?;
        Ok(())
    }

    async fn redeliver(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError> {
        self.settle(*tenant_id, consumer_name, receipt, Settlement::Redelivered)?;
        Ok(())
    }

    async fn dead_letter(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer_name: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<(), DomainError> {
        let id = self.next_dead_letter();
        let taken = self.settle(*tenant_id, consumer_name, receipt, Settlement::DeadLettered)?;
        let Some(taken) = taken else {
            return Ok(());
        };
        self.set_aside(
            consumer_name,
            DeadLetter {
                id,
                message: taken.message,
                delivered: taken.delivered,
                set_aside_at: clock::now(),
            },
        );
        Ok(())
    }

    async fn delete_consumer(
        &self,
        tenant_id: &TenantId,
        _topic_name: &TopicName,
        consumer_name: &str,
    ) -> Result<(), DomainError> {
        self.open
            .lock()
            .unwrap()
            .retain(|open| !(open.tenant == *tenant_id && open.name == consumer_name));
        Ok(())
    }
}

#[async_trait]
impl DeadLetters for FakeMessageConsumer {
    async fn list(
        &self,
        _tenant_id: &TenantId,
        consumer_name: &str,
        retention: RetentionPolicy,
        request: &PageRequest,
    ) -> Result<Page<DeadLetter>, DomainError> {
        self.retentions.lock().unwrap().push(retention);
        let letters = self.dead_letters_of(consumer_name);
        page(
            letters,
            &SortOrder::<DeadLetterSortField>::default(),
            request,
        )
    }

    async fn replay(
        &self,
        _tenant_id: &TenantId,
        read: ConsumerRead<'_>,
        id: DeadLetterId,
    ) -> Result<Replay, DomainError> {
        self.retentions.lock().unwrap().push(read.retention);
        let mut dead = self.dead.lock().unwrap();
        let Some(index) = dead
            .iter()
            .position(|(name, letter)| name == read.consumer_name && letter.id == id)
        else {
            return Ok(Replay::NotHeld);
        };
        let (_, letter) = dead.remove(index);
        self.pending.lock().unwrap().push(PendingMessage {
            message: letter.message,
            receipt: DeliveryReceipt::new(format!("replayed-{}", id.get())),
            delivered: 0,
        });
        Ok(Replay::Requeued)
    }
}

impl Fake for Arc<dyn MessageConsumer> {
    fn fake() -> Self {
        Arc::new(FakeMessageConsumer::empty())
    }
}

impl Fake for Arc<dyn DeadLetters> {
    fn fake() -> Self {
        Arc::new(FakeMessageConsumer::empty())
    }
}
