//! Agent message relay, the only way one agent's message reaches another.
//!
//! Agents hold no broker credentials. They hand every message to ianua with
//! their task token, and ianua decides, reshapes, signs and records it:
//!
//! 1. the token authenticates and its delegation is live, for this tenant;
//! 2. the agent is in good standing;
//! 3. an agent publishes only in its own area (`agents.<its id>.…`), and
//!    reads another agent's area only through a channel a person opened;
//! 4. the delegation covers the topic for this direction;
//! 5. the topic exists, is active, and declares a schema;
//! 6. a published message is at most `MAX_MESSAGE_BYTES`, matches the
//!    schema, and is rewritten to its canonical form;
//! 7. the topic is cleared at least as high as the data the agent has
//!    touched, and the agent takes on the topic's class, checked last, so a
//!    refused message never raises the agent's mark;
//! 8. ianua signs the provenance of exactly the bytes it forwards.
//!
//! A reader receives only messages whose provenance verifies and names the
//! area's owner as sender, together with who sent them and for whom. Every decision past authentication is recorded
//!, an allow as [`AgentMessageAuthorized`], a refusal or a dropped message as
//! [`AgentMessageDenied`], before anything moves. Deny by default: any check
//! that cannot be made refuses.
//!
//! Publishing is [`RelayPublishUseCase`](crate::use_cases::messaging::channels::relay_publish::RelayPublishUseCase)
//! and reading [`RelayReadUseCase`](crate::use_cases::messaging::channels::relay_read::RelayReadUseCase); this
//! module holds the ports and the checks both directions share.

use std::sync::Arc;

use ianua_domain::domains::agents::authority::capability::PubSub;
use ianua_domain::domains::agents::authority::provenance::MessageProvenance;
use ianua_domain::domains::agents::events::enforcement::{
    AgentAtWork, AgentMessageAuthorized, AgentMessageDenied,
};
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActingFor, ActorRef, PrincipalRef, UntrustedText};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrNotFound};
use crate::ports::agents::{AgentExposureGate, AgentStandingCheck};
use crate::ports::broker::{AgentPrincipal, BrokerAuthenticator, TopicAuthorizer};
use crate::ports::messaging::{
    AgentChannelStore, MessageConsumer, MessagePublisher, MessageShape, TopicStore,
};
use crate::services::agents::standing::ensure_in_good_standing;
use crate::tenancy::ScopedTenant;
use crate::use_cases::messaging::channels::agent_message::AgentMessageChannel;

/// The largest message an agent may publish, in bytes.
pub(crate) const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// The most messages one read returns.
pub(crate) const MAX_READ_BATCH: usize = 100;

/// The header carrying the signed provenance of a relayed message.
pub(crate) const PROVENANCE_HEADER: &str = "Ianua-Provenance";

/// Ports the relay decides and forwards through, in both directions.
#[derive(Clone, ianua_macros::Fakes)]
pub struct AgentRelayPorts {
    /// Resolves a task token to a live agent principal.
    pub authenticator: Arc<dyn BrokerAuthenticator>,
    /// Whether the agent may act at all.
    pub standing: Arc<dyn AgentStandingCheck>,
    /// Matches the topic against the delegation's topic capabilities.
    pub authorizer: Arc<dyn TopicAuthorizer>,
    /// Loads the topic.
    pub topic_store: Arc<dyn TopicStore>,
    /// Holds a message to the topic's schema.
    pub shape: Arc<dyn MessageShape>,
    /// The agent's data high-water mark.
    pub exposure: Arc<dyn AgentExposureGate>,
    /// Seals and opens provenance.
    pub provenance: Arc<AgentMessageChannel>,
    /// The channels people opened between agents.
    pub channels: Arc<dyn AgentChannelStore>,
    /// Puts a message on the bus.
    pub publisher: Arc<dyn MessagePublisher>,
    /// Takes messages off the bus.
    pub consumer: Arc<dyn MessageConsumer>,
}

/// A message delivered to a reader, with the authorship ianua vouches for.
#[derive(Debug, Clone)]
pub struct RelayedMessage {
    /// The message in canonical form.
    pub payload: Vec<u8>,
    /// Who sent it, under which delegation, and for whom.
    pub provenance: MessageProvenance,
}

/// What an agent tried to do on a topic.
#[derive(Clone, Copy)]
pub(super) struct TopicAccess<'a> {
    /// The broker destination targeted by the agent's attempted operation.
    pub(super) topic: &'a TopicName,
    /// Publish or subscribe.
    pub(super) action: PubSub,
}

/// The agent principal `credential` resolves to, provided its token was
/// issued for `tenant`. Every failure is the same `Unauthenticated`, so the
/// answer reveals nothing about why.
///
/// # Errors
///
/// `AppError::Unauthenticated` when the token does not verify, its
/// delegation is revoked, or it belongs to another tenant.
pub(super) async fn authenticated_principal(
    ports: &AgentRelayPorts,
    tenant: &ScopedTenant,
    credential: &Secret,
) -> Result<AgentPrincipal, AppError> {
    let Ok(principal) = ports.authenticator.authenticate(credential).await else {
        return Err(AppError::Unauthenticated);
    };
    if principal.tenant_id != **tenant {
        return Err(AppError::Unauthenticated);
    }
    Ok(principal)
}

/// The topic, once the agent is in good standing, its delegation covers the
/// topic for `action`, and the topic carries agent messages.
///
/// # Errors
///
/// - `AppError::Forbidden` when any of those checks refuses.
/// - `AppError::NotFound` when the topic does not exist.
/// - `AppError::Internal` when a check cannot be made.
pub(super) async fn admitted_topic(
    ports: &AgentRelayPorts,
    tenant: &ScopedTenant,
    principal: &AgentPrincipal,
    access: TopicAccess<'_>,
) -> Result<Topic<ResolvedTenant>, AppError> {
    ensure_in_good_standing(ports.standing.as_ref(), tenant, &principal.agent_id).await?;
    ports
        .authorizer
        .authorize(principal, access.topic, access.action)
        .await
        .map_err(AppError::from_domain)?;
    agent_topic(ports, tenant, access.topic).await
}

/// The tenant's topic named `topic_name`, provided it carries agent messages.
///
/// # Errors
///
/// - `AppError::NotFound` when the topic does not exist.
/// - `AppError::Forbidden` when it takes no agent messages.
async fn agent_topic(
    ports: &AgentRelayPorts,
    tenant: &ScopedTenant,
    topic_name: &TopicName,
) -> Result<Topic<ResolvedTenant>, AppError> {
    let topic = ports
        .topic_store
        .find_by_name(tenant, topic_name)
        .await
        .map_err(AppError::from_domain)?
        .or_not_found(message!("messaging-topic-not-found-2", "topic not found"))?;
    if !topic.accepts_agent_messages() {
        return Err(AppError::Forbidden(message!(
            "messaging-the-topic-does-not-carry-agent",
            "the topic does not carry agent messages"
        )));
    }
    Ok(topic)
}

/// Raises the agent's data mark to the topic's class, refusing a topic
/// cleared below data the agent has already touched.
///
/// # Errors
///
/// `AppError::Forbidden` when the topic is cleared too low.
pub(super) async fn ensure_exposure_admitted(
    ports: &AgentRelayPorts,
    tenant: &ScopedTenant,
    principal: &AgentPrincipal,
    topic: &Topic<ResolvedTenant>,
) -> Result<(), AppError> {
    let admitted = ports
        .exposure
        .admit(tenant, &principal.agent_id, topic.data_class())
        .await
        .map_err(AppError::from_domain)?;
    if admitted {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "messaging-the-topic-is-cleared-below-data",
        "the topic is cleared below data this agent has touched"
    )))
}

/// Records the relay's decision on `access`: an allow, or a refusal the
/// agent caused. A failure on ianua's side is not a decision and records
/// nothing.
///
/// # Errors
///
/// `AppError::Internal` when the record cannot be written, audit failure is
/// operation failure, so nothing moves that is not on record.
pub(super) async fn record_decision<T>(
    auditor: &RequestAuditor,
    principal: &AgentPrincipal,
    access: TopicAccess<'_>,
    outcome: &Result<T, AppError>,
) -> Result<(), AppError> {
    let event = match outcome {
        Ok(_) => AgentMessageAuthorized::observed(
            at_work(principal),
            access.topic.clone(),
            access.action,
        ),
        Err(e) if e.is_client_error() => refusal(principal, access, &e.to_string()),
        Err(_) => return Ok(()),
    };
    record_by_agent(auditor, principal, vec![event]).await
}

/// The record of a refusal, or of a message dropped on the way to a reader,
/// for `reason`.
pub(super) fn refusal(
    principal: &AgentPrincipal,
    access: TopicAccess<'_>,
    reason: &str,
) -> DomainEvent {
    AgentMessageDenied::observed(
        at_work(principal),
        access.topic.clone(),
        access.action,
        UntrustedText::record(reason),
    )
}

/// Records `events` as the agent's own, with whoever it acts for.
///
/// # Errors
///
/// `AppError::Domain` when the record cannot be written.
pub(super) async fn record_by_agent(
    auditor: &RequestAuditor,
    principal: &AgentPrincipal,
    events: Vec<DomainEvent>,
) -> Result<(), AppError> {
    auditor
        .dispatch_by(&actor(principal), events)
        .await
        .map_err(AppError::from_domain)
}

/// The agent `principal` names, at work in its tenant under its
/// delegation.
fn at_work(principal: &AgentPrincipal) -> AgentAtWork {
    AgentAtWork::new(
        principal.tenant_id,
        principal.agent_id,
        principal.delegation_id,
    )
}

/// The agent, as the actor a record names, with whoever it acts for.
fn actor(principal: &AgentPrincipal) -> ActorRef {
    let on_behalf_of = match principal.on_behalf_of().first() {
        Some(subject) => ActingFor::Principal(Box::new(subject_actor(*subject))),
        None => ActingFor::Itself,
    };
    ActorRef::Agent {
        id: principal.agent_id,
        on_behalf_of,
    }
}

/// Whom an agent acts for, as the actor a record names.
fn subject_actor(subject: PrincipalRef) -> ActorRef {
    match subject {
        PrincipalRef::User(id) => ActorRef::User(id),
        PrincipalRef::OrgUser(id) => ActorRef::OrgUser(id),
        PrincipalRef::Consumer(id) => ActorRef::Service(id),
        PrincipalRef::Agent(id) => ActorRef::Agent {
            id,
            on_behalf_of: ActingFor::Itself,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::domains::agents::authority::capability::{
        CapabilitySet, TopicCapability, TopicPattern,
    };
    use ianua_domain::domains::agents::channels::channel::{
        AgentChannel, ChannelScope, OpenChannelParams,
    };
    use ianua_domain::domains::agents::identity::control::AgentControl;
    use ianua_domain::domains::agents::identity::standing::AgentStanding;
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::messaging::control::MessagingCreator;
    use ianua_domain::domains::messaging::schema::SchemaDefinition;
    use ianua_domain::domains::messaging::topic::{CreateTopicParams, RetentionPolicy};
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::events::data::FieldValue;
    use ianua_domain::test_support::authority::anyone_holding;
    use ianua_domain::types::{
        AgentId, DelegationId, Human, HumanAccount, Label, PersonKey, Seconds, Setting, TenantId,
        UserId,
    };

    use super::*;
    use crate::ports::messaging::{
        DeliveryReceipt, MessageKey, OpenDelivery, OutgoingMessage, PendingMessage, ReceivedMessage,
    };
    use crate::services::messaging::topic_authorizer::DelegationTopicAuthorizer;
    use crate::test_support::agents::{
        FakeAgentStandings, FakeBrokerAuthenticator, FakeExposureGate,
    };
    use crate::test_support::messaging::{
        FakeAgentChannelStore, FakeTopicStore, FirstByteHasher, MapProvenanceStore,
        ObjectsWithoutSpaces, messaging_admin,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor,
    };
    use crate::use_case::Command;
    use crate::use_cases::messaging::channels::{
        RelayPublishRequest, RelayPublishUseCase, RelayReadRequest, RelayReadUseCase,
    };

    const WRITER: &str = "writer-token";
    const READER: &str = "reader-token";
    const NARROW: &str = "narrow-token";

    #[derive(Default)]
    struct LoopbackBus {
        queued: Mutex<Vec<(TopicName, ReceivedMessage)>>,
        consumers: Mutex<Vec<String>>,
    }

    impl LoopbackBus {
        fn put(&self, topic: &str, payload: &[u8], headers: Vec<(String, String)>) {
            self.queued.lock().unwrap().push((
                TopicName::new(topic).unwrap(),
                ReceivedMessage {
                    key: MessageKey::new(format!("loopback-{topic}")),
                    payload: payload.to_vec(),
                    headers,
                    message_type: None,
                    published_at: ianua_domain::shared::clock::now(),
                },
            ));
        }

        fn payloads(&self) -> Vec<Vec<u8>> {
            self.queued
                .lock()
                .unwrap()
                .iter()
                .map(|(_, m)| m.payload.clone())
                .collect()
        }

        fn tamper(&self) {
            for (_, message) in self.queued.lock().unwrap().iter_mut() {
                message.payload[0] = b'[';
            }
        }
    }

    #[async_trait]
    impl MessagePublisher for LoopbackBus {
        async fn publish(
            &self,
            _tenant_id: &TenantId,
            topic_name: &TopicName,
            message: &OutgoingMessage<'_>,
        ) -> Result<(), DomainError> {
            self.put(
                topic_name.as_str(),
                message.payload,
                message.headers.to_vec(),
            );
            Ok(())
        }
    }

    #[async_trait]
    impl MessageConsumer for LoopbackBus {
        async fn ensure_consumer(
            &self,
            _tenant_id: &TenantId,
            _topic_name: &TopicName,
            consumer: &crate::ports::messaging::ConsumerSpec<'_>,
        ) -> Result<(), DomainError> {
            self.consumers
                .lock()
                .unwrap()
                .push(consumer.name.to_owned());
            Ok(())
        }

        async fn pull_messages(
            &self,
            _tenant_id: &TenantId,
            read: crate::ports::messaging::ConsumerRead<'_>,
            max_messages: usize,
        ) -> Result<Vec<ReceivedMessage>, DomainError> {
            let mut queued = self.queued.lock().unwrap();
            let (taken, kept): (Vec<_>, Vec<_>) = queued
                .drain(..)
                .partition(|(topic, _)| topic == read.topic_name);
            *queued = kept;
            Ok(taken
                .into_iter()
                .take(max_messages)
                .map(|(_, m)| m)
                .collect())
        }

        async fn fetch_pending(
            &self,
            _tenant_id: &TenantId,
            _read: crate::ports::messaging::ConsumerRead<'_>,
            _max_messages: usize,
        ) -> Result<Vec<PendingMessage>, DomainError> {
            Err(on_fetch_only())
        }

        async fn remove_lapsed(
            &self,
            _tenant_id: &TenantId,
            _topic_name: &TopicName,
            _retention: ianua_domain::domains::messaging::topic::RetentionPolicy,
        ) -> Result<(), DomainError> {
            Err(on_fetch_only())
        }

        async fn open_delivery(
            &self,
            _tenant_id: &TenantId,
            _topic_name: &TopicName,
            _consumer_name: &str,
            _receipt: &DeliveryReceipt,
        ) -> Result<Option<OpenDelivery>, DomainError> {
            Err(on_fetch_only())
        }

        async fn acknowledge(
            &self,
            _tenant_id: &TenantId,
            _topic_name: &TopicName,
            _consumer_name: &str,
            _receipt: &DeliveryReceipt,
        ) -> Result<(), DomainError> {
            Err(on_fetch_only())
        }

        async fn redeliver(
            &self,
            _tenant_id: &TenantId,
            _topic_name: &TopicName,
            _consumer_name: &str,
            _receipt: &DeliveryReceipt,
        ) -> Result<(), DomainError> {
            Err(on_fetch_only())
        }

        async fn dead_letter(
            &self,
            _tenant_id: &TenantId,
            _topic_name: &TopicName,
            _consumer_name: &str,
            _receipt: &DeliveryReceipt,
        ) -> Result<(), DomainError> {
            Err(on_fetch_only())
        }

        async fn delete_consumer(
            &self,
            _tenant_id: &TenantId,
            _topic_name: &TopicName,
            _consumer_name: &str,
        ) -> Result<(), DomainError> {
            Ok(())
        }
    }

    /// The loopback bus serves readers' own cursors only, which take each
    /// message as they fetch it, so nothing waits to be settled on it.
    fn on_fetch_only() -> DomainError {
        DomainError::infra_msg("the loopback bus acknowledges on fetch")
    }

    struct Fixture {
        relay_publish: RelayPublishUseCase,
        relay_read: RelayReadUseCase,
        tenant: TenantId,
        writer: AgentPrincipal,
        reader: AgentPrincipal,
        topic: String,
        topics: Arc<FakeTopicStore>,
        channels: Arc<FakeAgentChannelStore>,
        standings: Arc<FakeAgentStandings>,
        marks: Arc<FakeExposureGate>,
        bus: Arc<LoopbackBus>,
        provenance: Arc<AgentMessageChannel>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn principal(tenant: TenantId, pattern: &str, rights: PubSub) -> AgentPrincipal {
        AgentPrincipal {
            tenant_id: tenant,
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            subject: PrincipalRef::User(UserId::new()),
            caps: CapabilitySet::new(
                Vec::new(),
                vec![TopicCapability::new(
                    TopicPattern::new(pattern).unwrap(),
                    rights,
                )],
            ),
        }
    }

    /// Someone who manages agents, and so opens and closes their channels.
    fn agents_admin() -> AgentControl<'static> {
        AgentControl::new(anyone_holding(&[SystemPermission::ManageAgents]))
    }

    /// The person who owns the writing agent.
    fn writer_owner() -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new("owner@example.test").unwrap(),
        )
    }

    fn area(agent: &AgentPrincipal, rest: &str) -> String {
        format!("agents.{}.{rest}", agent.agent_id.as_uuid().as_simple())
    }

    /// A writer, a reader with a channel from the writer's area, and a task
    /// topic in the writer's area.
    fn fixture() -> Fixture {
        let f = fixture_without_channel();
        f.open_channel(DataClassLevel::Internal);
        f
    }

    /// Shared relay records keep requests and their observable effects together.
    struct RelayRecords {
        topics: Arc<FakeTopicStore>,
        channels: Arc<FakeAgentChannelStore>,
        standings: Arc<FakeAgentStandings>,
        marks: Arc<FakeExposureGate>,
        bus: Arc<LoopbackBus>,
        provenance: Arc<AgentMessageChannel>,
    }

    impl RelayRecords {
        /// Starts with no topics, channels, exposure marks or messages.
        fn empty() -> Self {
            let store = Arc::new(MapProvenanceStore::default());
            Self {
                topics: Arc::new(FakeTopicStore::empty()),
                channels: Arc::new(FakeAgentChannelStore::default()),
                standings: Arc::new(FakeAgentStandings::default()),
                marks: Arc::new(FakeExposureGate::default()),
                bus: Arc::new(LoopbackBus::default()),
                provenance: Arc::new(AgentMessageChannel::new(
                    Arc::new(FirstByteHasher),
                    store.clone(),
                    store,
                )),
            }
        }

        /// Connects the writer, reader and narrowly authorized agent to these records.
        fn ports(&self, writer: &AgentPrincipal, reader: &AgentPrincipal) -> AgentRelayPorts {
            let narrow = principal(writer.tenant_id, "orders.>", PubSub::Publish);
            AgentRelayPorts {
                authenticator: Arc::new(FakeBrokerAuthenticator::knowing([
                    (WRITER, writer.clone()),
                    (READER, reader.clone()),
                    (NARROW, narrow),
                ])),
                standing: self.standings.clone(),
                authorizer: Arc::new(DelegationTopicAuthorizer::new()),
                topic_store: self.topics.clone(),
                shape: Arc::new(ObjectsWithoutSpaces),
                exposure: self.marks.clone(),
                provenance: self.provenance.clone(),
                channels: self.channels.clone(),
                publisher: self.bus.clone(),
                consumer: self.bus.clone(),
                ..AgentRelayPorts::fakes()
            }
        }
    }

    /// Keeps a writer's task topic before any channel grants readers access.
    fn fixture_without_channel() -> Fixture {
        let tenant = TenantId::new();
        let writer = principal(tenant, "agents.>", PubSub::Publish);
        let reader = principal(tenant, "agents.>", PubSub::Subscribe);
        let records = RelayRecords::empty();
        let ports = records.ports(&writer, &reader);
        let fixture = Fixture {
            relay_publish: RelayPublishUseCase::new(ports.clone()),
            relay_read: RelayReadUseCase::new(ports),
            tenant,
            topic: area(&writer, "tasks"),
            writer,
            reader,
            topics: records.topics,
            channels: records.channels,
            standings: records.standings,
            marks: records.marks,
            bus: records.bus,
            provenance: records.provenance,
            audit: Arc::new(FakeEventDispatcher::new()),
        };
        fixture.add_topic(
            &fixture.topic,
            Some(r#"{"type":"object"}"#),
            DataClassLevel::Internal,
        );
        fixture
    }

    impl Fixture {
        fn add_topic(&self, name: &str, schema: Option<&str>, class: DataClassLevel) {
            let admin = messaging_admin();
            let params = CreateTopicParams {
                name: Label::new("name", name).unwrap(),
                topic_name: TopicName::new(name).unwrap(),
                description: None,
                schema: Setting::from_stored(
                    schema.map(|text| SchemaDefinition::new(text).unwrap()),
                ),
                retention: RetentionPolicy::Unlimited,
                data_class: class,
            };
            let topic: Topic<ResolvedTenant> =
                Topic::create(params, MessagingCreator::Person(&admin)).unwrap();
            block_on(
                self.topics
                    .save(&crate::tenancy::ScopedTenant::for_test(self.tenant), &topic),
            )
            .unwrap();
        }

        fn open_channel(&self, max_class: DataClassLevel) -> AgentChannel<ResolvedTenant> {
            let params = OpenChannelParams {
                sender: self.writer.agent_id,
                receiver: self.reader.agent_id,
                scope: ChannelScope::Topics(TopicPattern::new(area(&self.writer, ">")).unwrap()),
                max_class,
                lifetime_seconds: Seconds::new(3600),
            };
            let channel = AgentChannel::open(&agents_admin(), &writer_owner(), params).unwrap();
            block_on(self.channels.save(
                &crate::tenancy::ScopedTenant::for_test(self.tenant),
                &channel,
            ))
            .unwrap();
            channel
        }

        fn publish_to(&self, token: &str, topic: &str, payload: &[u8]) -> Result<(), AppError> {
            block_on(self.relay_publish.execute(
                &crate::tenancy::ScopedTenant::for_test(self.tenant),
                &test_auditor(self.audit.clone()),
                RelayPublishRequest {
                    credential: Secret::new(token),
                    topic: TopicName::new(topic).unwrap(),
                    payload: payload.to_vec(),
                },
            ))
        }

        fn publish(&self, payload: &[u8]) -> Result<(), AppError> {
            self.publish_to(WRITER, &self.topic, payload)
        }

        fn read_from(&self, topic: &str) -> Result<Vec<RelayedMessage>, AppError> {
            block_on(self.relay_read.execute(
                &crate::tenancy::ScopedTenant::for_test(self.tenant),
                &test_auditor(self.audit.clone()),
                RelayReadRequest {
                    credential: Secret::new(READER),
                    topic: TopicName::new(topic).unwrap(),
                    max_messages: 10,
                },
            ))
        }

        fn read(&self) -> Result<Vec<RelayedMessage>, AppError> {
            self.read_from(&self.topic)
        }

        fn scope(&self) -> ScopedTenant {
            ScopedTenant::for_test(self.tenant)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn denial_reason(&self) -> String {
            match self
                .audit
                .payload_of("agents.message_denied")
                .value("reason")
            {
                Some(FieldValue::Text(reason)) => reason.clone(),
                other => panic!("no denial reason: {other:?}"),
            }
        }
    }

    /// An agent publishes a task and another reads it through a channel. The
    /// reader gets the canonical message with the sender and delegation ianua
    /// vouches for, and both decisions are on record.
    #[test]
    fn a_reader_receives_the_message_with_the_sender_ianua_vouches_for() {
        let f = fixture();

        f.publish(br#"{"task": 1}"#).unwrap();
        let delivered = f.read().unwrap();

        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].payload, br#"{"task":1}"#);
        assert_eq!(delivered[0].provenance.sender(), &f.writer.agent_id);
        assert_eq!(
            delivered[0].provenance.delegation_id(),
            &f.writer.delegation_id
        );
        assert_eq!(
            f.recorded(),
            ["agents.message_authorized", "agents.message_authorized"]
        );
    }

    /// The bus carries the bytes ianua rewrote, never the agent's own layout.
    #[test]
    fn the_bus_carries_the_canonical_form() {
        let f = fixture();

        f.publish(br#"{ "task" : 1 }"#).unwrap();

        assert_eq!(f.bus.payloads(), [br#"{"task":1}"#.to_vec()]);
    }

    /// Publishing with an unknown task token returns an unauthenticated
    /// error and sends no payload to the bus.
    #[test]
    fn an_unknown_token_is_unauthenticated_and_sends_nothing() {
        let f = fixture();

        let result = f.publish_to("forged", &f.topic, b"{}");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(f.bus.payloads().is_empty());
    }

    /// Publishing with a token from another tenant returns an unauthenticated
    /// error and sends no payload to the bus.
    #[test]
    fn a_token_for_another_tenant_is_unauthenticated() {
        let f = fixture();

        let result = block_on(f.relay_publish.execute(
            &crate::tenancy::ScopedTenant::for_test(TenantId::new()),
            &test_auditor(f.audit.clone()),
            RelayPublishRequest {
                credential: Secret::new(WRITER),
                topic: TopicName::new(&f.topic).unwrap(),
                payload: b"{}".to_vec(),
            },
        ));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(f.bus.payloads().is_empty());
    }

    /// A suspended writer's publish request is forbidden, sends no payload
    /// and records a message denial.
    #[test]
    fn an_agent_out_of_good_standing_is_refused_and_recorded() {
        let f = fixture();
        f.standings
            .set(&f.scope(), f.writer.agent_id, AgentStanding::Suspended);

        let result = f.publish(b"{}");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(f.bus.payloads().is_empty());
        assert_eq!(f.recorded(), ["agents.message_denied"]);
    }

    /// Every agent message names its author in its address: an agent writes
    /// only below its own id.
    #[test]
    fn publishing_outside_the_agents_own_area_is_refused_and_recorded() {
        let f = fixture();
        let elsewhere = area(&f.reader, "tasks");
        f.add_topic(&elsewhere, Some("{}"), DataClassLevel::Internal);

        let result = f.publish_to(WRITER, &elsewhere, b"{}");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(f.bus.payloads().is_empty());
        assert!(f.denial_reason().contains("own area"));
    }

    /// An agent delegated order topics cannot publish to the writer's task
    /// topic; the forbidden request records a message denial.
    #[test]
    fn a_topic_outside_the_delegation_is_refused_and_recorded() {
        let f = fixture();
        let narrow = f.publish_to(NARROW, &f.topic, b"{}");

        assert!(matches!(narrow, Err(AppError::Forbidden(_))));
        assert_eq!(f.recorded(), ["agents.message_denied"]);
    }

    /// An agent delegated only to read cannot publish even in its own area;
    /// the forbidden request sends no payload to the bus.
    #[test]
    fn a_reader_cannot_publish_without_the_right() {
        let f = fixture();
        let own = area(&f.reader, "notes");
        f.add_topic(&own, Some("{}"), DataClassLevel::Internal);

        let result = f.publish_to(READER, &own, b"{}");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(f.bus.payloads().is_empty());
    }

    /// An agent publishes to a topic nobody made. It is not found, and the
    /// refusal is on record.
    #[test]
    fn a_topic_that_does_not_exist_is_not_found() {
        let f = fixture();

        let result = f.publish_to(WRITER, &area(&f.writer, "nowhere"), b"{}");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(f.recorded(), ["agents.message_denied"]);
    }

    /// Free text is where a covert signal hides; without a declared shape the
    /// topic takes nothing from an agent.
    #[test]
    fn a_topic_without_a_schema_takes_no_agent_messages() {
        let f = fixture();
        let chat = area(&f.writer, "chat");
        f.add_topic(&chat, None, DataClassLevel::Internal);

        let result = f.publish_to(WRITER, &chat, b"{}");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(f.bus.payloads().is_empty());
    }

    /// A message one byte over the size cap is forbidden and sends no
    /// payload to the bus.
    #[test]
    fn a_message_over_the_size_cap_is_refused() {
        let f = fixture();
        let oversized = [b' '; MAX_MESSAGE_BYTES + 1];

        let result = f.publish(&oversized);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(f.bus.payloads().is_empty());
    }

    /// Free text sent to a topic requiring an object fails validation,
    /// sends no payload, leaves the writer's data mark public and records
    /// a message denial.
    #[test]
    fn a_message_that_breaks_the_schema_is_refused_without_raising_the_mark() {
        let f = fixture();

        let result = f.publish(b"free text");

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert!(f.bus.payloads().is_empty());
        assert_eq!(
            f.marks.of(&f.scope(), &f.writer.agent_id),
            DataClassLevel::Public
        );
        assert_eq!(f.recorded(), ["agents.message_denied"]);
    }

    /// An agent that has touched restricted data cannot pass it to a topic
    /// cleared lower, however the other agent would later use it.
    #[test]
    fn publishing_below_the_agents_mark_is_refused() {
        let f = fixture();
        f.marks
            .set(&f.scope(), f.writer.agent_id, DataClassLevel::Restricted);

        let result = f.publish(b"{}");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(f.bus.payloads().is_empty());
    }

    /// Without a channel a person opened, one agent's area is closed to every
    /// other agent, whatever its delegation says.
    #[test]
    fn reading_another_agents_area_without_a_channel_is_refused() {
        let f = fixture_without_channel();
        f.publish(b"{}").unwrap();

        let result = f.read();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(f.denial_reason().contains("no open channel"));
    }

    /// Reading another agent's topic through a closed channel is forbidden.
    #[test]
    fn a_closed_channel_carries_nothing() {
        let f = fixture_without_channel();
        let mut channel = f.open_channel(DataClassLevel::Internal);
        channel.close(&agents_admin(), &writer_owner()).unwrap();
        block_on(
            f.channels
                .save(&crate::tenancy::ScopedTenant::for_test(f.tenant), &channel),
        )
        .unwrap();

        let result = f.read();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A channel cleared only for public data cannot read an internal topic;
    /// the read request returns a forbidden error.
    #[test]
    fn a_channel_cleared_below_the_topic_carries_nothing() {
        let f = fixture_without_channel();
        f.open_channel(DataClassLevel::Public);

        let result = f.read();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An agent reads a topic in its own area. It needs no channel.
    #[test]
    fn an_agent_reads_its_own_area_without_a_channel() {
        let f = fixture_without_channel();
        let own = area(&f.reader, "notes");
        f.add_topic(&own, Some("{}"), DataClassLevel::Internal);

        let result = f.read_from(&own);

        assert!(result.is_ok());
    }

    /// An agent reads a restricted topic in its own area. Its data mark rises to
    /// restricted.
    #[test]
    fn reading_a_topic_raises_the_readers_mark_to_its_class() {
        let f = fixture();
        let secrets = area(&f.reader, "secrets");
        f.add_topic(&secrets, Some("{}"), DataClassLevel::Restricted);

        f.read_from(&secrets).unwrap();

        assert_eq!(
            f.marks.of(&f.scope(), &f.reader.agent_id),
            DataClassLevel::Restricted
        );
    }

    /// An agent's read of `orders.created`, outside every agent area,
    /// returns a forbidden error.
    #[test]
    fn topics_outside_every_agent_area_are_not_read() {
        let f = fixture();
        f.add_topic("orders.created", Some("{}"), DataClassLevel::Internal);

        let result = f.read_from("orders.created");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A message on the bus carries no provenance. It is dropped, never
    /// delivered, and the drop is on record.
    #[test]
    fn a_message_without_provenance_is_dropped_and_recorded() {
        let f = fixture();
        f.bus.put(&f.topic, b"{}", Vec::new());

        let delivered = f.read().unwrap();

        assert!(delivered.is_empty());
        assert_eq!(
            f.recorded(),
            ["agents.message_authorized", "agents.message_denied"]
        );
        assert!(f.denial_reason().contains("no provenance"));
    }

    /// Altering a signed message's payload on the bus leaves the reader
    /// with no delivered message and records a provenance verification denial.
    #[test]
    fn a_message_altered_on_the_bus_is_dropped_and_recorded() {
        let f = fixture();
        f.publish(b"{}").unwrap();
        f.bus.tamper();

        let delivered = f.read().unwrap();

        assert!(delivered.is_empty());
        assert!(f.denial_reason().contains("does not verify"));
    }

    /// A valid signature by the wrong author is still a forgery here: the
    /// area's address names its author, and the two must agree.
    #[test]
    fn a_message_signed_by_someone_other_than_the_area_owner_is_dropped() {
        let f = fixture();
        let token = block_on(f.provenance.seal(&f.reader, b"{}")).unwrap();
        f.bus.put(
            &f.topic,
            b"{}",
            vec![(PROVENANCE_HEADER.to_owned(), token.as_str().to_owned())],
        );

        let delivered = f.read().unwrap();

        assert!(delivered.is_empty());
        assert!(f.denial_reason().contains("does not own the area"));
    }

    /// Audit failure is operation failure: nothing moves that is not on record.
    #[test]
    fn a_message_that_cannot_be_recorded_is_not_sent() {
        let f = fixture();

        let result = block_on(f.relay_publish.execute(
            &crate::tenancy::ScopedTenant::for_test(f.tenant),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            RelayPublishRequest {
                credential: Secret::new(WRITER),
                topic: TopicName::new(&f.topic).unwrap(),
                payload: b"{}".to_vec(),
            },
        ));

        assert!(result.is_err());
        assert!(f.bus.payloads().is_empty());
    }

    /// An agent reads a topic through a bus consumer named for it, so no other
    /// agent shares its cursor.
    #[test]
    fn each_agent_reads_each_topic_through_its_own_cursor() {
        let f = fixture();

        f.read().unwrap();

        let consumers = f.bus.consumers.lock().unwrap();
        assert_eq!(consumers.len(), 1);
        assert!(consumers[0].contains(&f.reader.agent_id.as_uuid().as_simple().to_string()));
    }
}
