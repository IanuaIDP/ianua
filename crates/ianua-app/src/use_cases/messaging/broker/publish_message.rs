//! Publish message: send a message to a topic.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::messaging::message_type::MessageType;
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::messaging::{MessagePublisher, OutgoingMessage, TopicStore};
use crate::ports::realtime::{BrokerDelivery, NotificationPublisher, RealtimeMessage};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::messaging::bus::live_subject;
use crate::use_cases::messaging::caller::{MessagingActor, MessagingCaller};
use crate::use_cases::messaging::lookup::existing_named_topic;

/// Maximum message payload size (1 MiB). Matches NATS JetStream default.
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Headers starting with this belong to the platform, never to a publisher.
const RESERVED_HEADER_PREFIX: &str = "Ianua-";

/// The destination, payload and publisher-supplied metadata for a broker publication.
pub struct PublishMessageRequest {
    /// The topic to publish to.
    pub topic_name: TopicName,
    /// Message payload (opaque bytes).
    pub payload: Vec<u8>,
    /// Optional headers (key-value pairs).
    pub headers: Vec<(String, String)>,
    /// What kind of message it is, which subscriptions filter on.
    pub message_type: Option<MessageType>,
}

/// Ports needed by the publish message use case.
#[derive(ianua_macros::Fakes)]
pub struct PublishMessagePorts {
    /// Port for topic lookup (existence + active check).
    pub topic_store: Arc<dyn TopicStore>,
    /// Port for publishing to the bus.
    pub message_publisher: Arc<dyn MessagePublisher>,
    /// Port for broadcasting to connected WebSocket subscribers. They carry
    /// the payload, so only a stream the stream-topic use case admits may
    /// pass them on.
    pub broadcaster: Arc<dyn NotificationPublisher>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// What a consumer's roles give it, once it signed in.
    pub consumers: Arc<dyn ConsumerAuthorities>,
}

/// Sends a caller's payload through the tenant's admitted messaging topic.
pub struct PublishMessageUseCase {
    ports: PublishMessagePorts,
}

impl PublishMessageUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: PublishMessagePorts) -> Self {
        Self { ports }
    }

    /// The active topic `req` publishes to, once the caller may publish,
    /// holding the publish it took until the message is on the bus.
    async fn admitted_topic(
        &self,
        tenant: &ScopedTenant,
        actor: &MessagingActor,
        req: &PublishMessageRequest,
    ) -> Result<Topic<ResolvedTenant>, AppError> {
        actor.ensure_holds(SystemPermission::Messaging(MessagingAction::Publish))?;
        ensure_payload_fits(&req.payload)?;
        ensure_no_reserved_headers(&req.headers)?;
        let mut topic =
            existing_named_topic(self.ports.topic_store.as_ref(), tenant, &req.topic_name).await?;
        topic
            .accept_publish(req.payload.len())
            .map_err(AppError::from_domain)?;
        Ok(topic)
    }

    /// Shows the published message to the dashboards watching the topic.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the broadcast cannot be sent.
    async fn broadcast(
        &self,
        tenant: &ScopedTenant,
        req: &PublishMessageRequest,
    ) -> Result<(), AppError> {
        let subject = live_subject(tenant, &req.topic_name);
        let message = RealtimeMessage::BrokerMessage(BrokerDelivery {
            topic: req.topic_name.clone(),
            payload: req.payload.clone(),
        });
        self.ports
            .broadcaster
            .publish_dashboard(&subject, &message)
            .await
            .or_internal()
    }
}

impl Command for PublishMessageUseCase {
    type Caller = MessagingCaller;
    type Input = PublishMessageRequest;
    type Output = Result<(), AppError>;

    /// Publishes a message to a topic and shows it to the dashboards watching
    /// it. Records `messaging.message_published` with the topic and payload
    /// size, never the payload; the record reaches no colleague's feed.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session, key or consumer
    ///   credential no longer counts.
    /// - `AppError::Forbidden` when the person, or the consumer's roles, may
    ///   not publish, or the topic is not active.
    /// - `AppError::Domain` if the payload is larger than the bus accepts, or
    ///   a header is one the platform reserves.
    /// - `AppError::NotFound` if the topic doesn't exist.
    /// - `AppError::Internal` on publish, broadcast or audit failure.
    async fn execute(
        &self,
        caller: &MessagingCaller,
        auditor: &RequestAuditor,
        req: PublishMessageRequest,
    ) -> Result<(), AppError> {
        let tenant = caller.tenant();
        let actor = MessagingActor::of(
            caller,
            self.ports.tenant_authorities.as_ref(),
            self.ports.consumers.as_ref(),
        )
        .await?;
        let mut topic = self.admitted_topic(&tenant, &actor, &req).await?;

        let message = OutgoingMessage {
            payload: &req.payload,
            headers: &req.headers,
            message_type: req.message_type.as_ref(),
        };
        self.ports
            .message_publisher
            .publish(&tenant, topic.topic_name(), &message)
            .await
            .or_internal()?;
        self.broadcast(&tenant, &req).await?;

        auditor
            .dispatch_by(&actor.actor(), topic.take_events(&tenant))
            .await
            .or_internal()
    }
}

/// Refuses a payload larger than the bus accepts.
///
/// # Errors
///
/// `AppError::Domain(Validation)` above [`MAX_PAYLOAD_SIZE`].
fn ensure_payload_fits(payload: &[u8]) -> Result<(), AppError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(AppError::Domain(DomainError::invalid(message!(
            "messaging-payload-size-exceeds-maximum",
            format!(
                "payload size {} exceeds maximum {}",
                payload.len(),
                MAX_PAYLOAD_SIZE
            )
        ))));
    }
    Ok(())
}

/// Refuses a header in the platform's own `Ianua-` namespace.
///
/// Those headers are set only by ianua itself. The provenance header is the
/// one that matters: a reader treats a message carrying it as sent by the
/// agent it names, so a publisher able to set it could re-publish a captured
/// signed message and have it read as fresh.
///
/// # Errors
///
/// `AppError::Domain(Validation)` naming the first reserved header.
fn ensure_no_reserved_headers(headers: &[(String, String)]) -> Result<(), AppError> {
    let reserved = headers.iter().find(|(name, _)| {
        name.get(..RESERVED_HEADER_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(RESERVED_HEADER_PREFIX))
    });
    let Some((name, _)) = reserved else {
        return Ok(());
    };
    Err(AppError::Domain(DomainError::invalid(message!(
        "messaging-header-is-reserved-for-the-platform",
        format!("header {name} is reserved for the platform")
    ))))
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TokenHash;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{billing_sync, key_caller, sign_in_of, test_key_digest};
    use crate::test_support::messaging::{
        FakeMessagePublisher, FakeTopicStore, messaging_admin, topic_named, topics_of_test_tenant,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const PUBLISH: SystemPermission = SystemPermission::Messaging(MessagingAction::Publish);

    struct Bench {
        use_case: PublishMessageUseCase,
        publisher: Arc<FakeMessagePublisher>,
    }

    fn bench_over(
        topics: Arc<FakeTopicStore>,
        people: FakeTenantAuthorities,
        consumer_holds: &[SystemPermission],
    ) -> Bench {
        let publisher = Arc::new(FakeMessagePublisher::empty());
        let use_case = PublishMessageUseCase::new(PublishMessagePorts {
            topic_store: topics,
            message_publisher: publisher.clone(),
            tenant_authorities: Arc::new(people),
            consumers: sign_in_of(billing_sync(), consumer_holds),
            ..PublishMessagePorts::fakes()
        });
        Bench {
            use_case,
            publisher,
        }
    }

    fn bench(people: FakeTenantAuthorities) -> Bench {
        bench_over(
            topics_of_test_tenant(topic_named("orders.created")),
            people,
            &[],
        )
    }

    fn message(payload: Vec<u8>) -> PublishMessageRequest {
        PublishMessageRequest {
            topic_name: TopicName::new("orders.created").unwrap(),
            payload,
            headers: Vec::new(),
            message_type: None,
        }
    }

    fn person() -> MessagingCaller {
        MessagingCaller::Person(test_ctx())
    }

    fn billing_sync_with(digest: TokenHash) -> MessagingCaller {
        MessagingCaller::Consumer(key_caller(digest))
    }

    fn run(
        bench: &Bench,
        caller: &MessagingCaller,
        req: PublishMessageRequest,
    ) -> (Result<(), AppError>, Arc<FakeEventDispatcher>) {
        let audit = Arc::new(FakeEventDispatcher::new());
        let result = block_on(
            bench
                .use_case
                .execute(caller, &test_auditor(audit.clone()), req),
        );
        (result, audit)
    }

    /// Ann publishes to `orders.created`. The message reaches the bus and
    /// the publication is on record.
    #[test]
    fn a_person_publishes_to_an_active_topic() {
        let bench = bench(FakeTenantAuthorities::holding(&[PUBLISH]));

        let (result, audit) = run(&bench, &person(), message(b"hello".to_vec()));

        result.unwrap();
        assert_eq!(bench.publisher.count(), 1);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["messaging.message_published"]
        );
    }

    /// Ann publishes an `order.refund.requested` message. It reaches the bus
    /// as that type, so the subscriptions filtering on refunds get it.
    #[test]
    fn a_message_is_published_with_its_type() {
        let bench = bench(FakeTenantAuthorities::holding(&[PUBLISH]));
        let refund = MessageType::new("order.refund.requested").unwrap();
        let typed = PublishMessageRequest {
            message_type: Some(refund.clone()),
            ..message(b"hello".to_vec())
        };

        let (result, _) = run(&bench, &person(), typed);

        result.unwrap();
        assert_eq!(bench.publisher.published()[0].message_type, Some(refund));
    }

    /// "billing-sync" holds a role that may publish. It publishes with its
    /// own key, and the message reaches the bus.
    #[test]
    fn a_consumer_publishes_with_its_own_key() {
        let bench = bench_over(
            topics_of_test_tenant(topic_named("orders.created")),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &[PUBLISH],
        );

        let (result, _) = run(
            &bench,
            &billing_sync_with(test_key_digest()),
            message(b"hello".to_vec()),
        );

        result.unwrap();
        assert_eq!(bench.publisher.count(), 1);
    }

    /// A consumer without publish permission is forbidden from publishing,
    /// and no message reaches the bus.
    #[test]
    fn a_consumer_whose_roles_do_not_publish_is_refused() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, _) = run(
            &bench,
            &billing_sync_with(test_key_digest()),
            message(b"hello".to_vec()),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.publisher.count(), 0);
    }

    /// Messaging-view permission alone cannot publish a message. The request
    /// is forbidden, with no bus publication or audit event.
    #[test]
    fn a_person_without_the_publish_right_is_refused() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::View)]);
        let bench = bench(viewer);

        let (result, audit) = run(&bench, &person(), message(b"paid".to_vec()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.publisher.count(), 0);
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A signed-out person receives unauthenticated when publishing a message.
    #[test]
    fn a_signed_out_person_is_refused() {
        let bench = bench(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let (result, _) = run(&bench, &person(), message(b"hello".to_vec()));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A topic the tenant does not have is not found.
    #[test]
    fn publishing_to_an_unknown_topic_is_not_found() {
        let bench = bench_over(
            Arc::new(FakeTopicStore::empty()),
            FakeTenantAuthorities::holding_everything(),
            &[],
        );

        let (result, _) = run(&bench, &person(), message(b"data".to_vec()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Publishing to a paused topic is forbidden and sends no message to the bus.
    #[test]
    fn publishing_to_a_paused_topic_is_refused() {
        let mut topic = topic_named("orders.created");
        topic.pause(&messaging_admin()).unwrap();
        let bench = bench_over(
            topics_of_test_tenant(topic),
            FakeTenantAuthorities::holding_everything(),
            &[],
        );

        let (result, _) = run(&bench, &person(), message(b"data".to_vec()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(bench.publisher.count(), 0);
    }

    /// A message one byte over what the bus accepts is refused.
    #[test]
    fn a_payload_over_the_size_limit_is_refused() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, _) = run(&bench, &person(), message(vec![0u8; MAX_PAYLOAD_SIZE + 1]));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// The cap is the bus's own limit, so a message right at it must still go
    /// through rather than be refused a byte early.
    #[test]
    fn a_payload_at_the_size_limit_is_published() {
        let bench = bench(FakeTenantAuthorities::holding_everything());

        let (result, _) = run(&bench, &person(), message(vec![0u8; MAX_PAYLOAD_SIZE]));

        result.unwrap();
        assert_eq!(bench.publisher.count(), 1);
    }

    /// A captured provenance header re-published would read as a fresh
    /// message from the agent it names, so a publisher may not set one, in
    /// any letter case.
    #[test]
    fn a_publisher_cannot_set_the_provenance_header() {
        let bench = bench(FakeTenantAuthorities::holding_everything());
        let replayed = PublishMessageRequest {
            headers: vec![("ianua-provenance".to_owned(), "captured.token".to_owned())],
            ..message(b"hello".to_vec())
        };

        let (result, _) = run(&bench, &person(), replayed);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(bench.publisher.count(), 0);
    }
}
