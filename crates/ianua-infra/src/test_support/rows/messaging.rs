//! Rows the messaging store tests build from, and the consumers and agents
//! they point at, saved through those contexts' own stores.

use std::sync::Arc;

use ianua_app::ports::agents::AgentStore;
use ianua_app::ports::consumers::ConsumerStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::authority::capability::TopicPattern;
use ianua_domain::domains::agents::channels::channel::{AgentChannelRow, ChannelScope};
use ianua_domain::domains::agents::identity::agent::{
    AgentIdentity, AgentIdentityRow, AgentProof, Containment, OwnershipOffer,
};
use ianua_domain::domains::agents::identity::status::AgentStatus;
use ianua_domain::domains::consumers::consumer::{Consumer, ConsumerRow};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::messaging::control::CreatedBy;
use ianua_domain::domains::messaging::delivery::{AckPolicy, PushEndpoint, SubscriptionDelivery};
use ianua_domain::domains::messaging::schema::{
    CompatibilityMode, EventSchemaRow, SchemaDefinition, SchemaFormat, SchemaVersion,
};
use ianua_domain::domains::messaging::subscription::{SubscriptionRow, SubscriptionStatus};
use ianua_domain::domains::messaging::topic::{RetentionPolicy, TopicRow, TopicStatus};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{
    AgentChannelId, AgentId, ConsumerId, Ending, EventSchemaId, Label, MessageSubscriptionId,
    PrincipalRef, PublicHttpsUrl, Setting, TopicId, UserId,
};

use crate::postgres::agents::PgAgentStore;
use crate::postgres::consumers::PgConsumerStore;
use crate::test_support::TestDb;
use crate::test_support::rows::at;
use crate::test_support::rows::authorization::human;
use crate::test_support::rows::branding::sealed;
use crate::test_support::rows::consumers::consumer_row;
use crate::test_support::rows::oauth::a_person;

/// The JSON Schema every [`schema_row`]'s first version holds.
pub const ORDER_SCHEMA: &str = r#"{"type":"object","required":["id"]}"#;

/// An active topic services publish to as `topic_name`, holding no schema
/// and keeping messages until purged, carrying internal data, made at the
/// fixed moment by Ann.
///
/// # Panics
///
/// When `topic_name` is not a valid topic name, which is a mistake in the
/// test.
#[must_use]
pub fn topic_row(topic_name: &str) -> TopicRow {
    TopicRow {
        id: TopicId::new(),
        name: Label::new("name", topic_name).expect("a valid name"),
        topic_name: TopicName::new(topic_name).expect("a valid topic name"),
        description: None,
        schema: Setting::Unset,
        retention: RetentionPolicy::Unlimited,
        status: TopicStatus::Active,
        created_by: CreatedBy::Person(human(UserId::new(), "ann@acme.example")),
        data_class: DataClassLevel::Internal,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// An active pull subscription of `consumer` to `topic_name`, in no
/// consumer group, with the standard acknowledgement policy, made at the
/// fixed moment.
///
/// # Panics
///
/// When `topic_name` is not a valid topic name, which is a mistake in the
/// test.
#[must_use]
pub fn subscription_row(topic_name: &str, consumer: ConsumerId) -> SubscriptionRow {
    SubscriptionRow {
        id: MessageSubscriptionId::new(),
        topic_name: TopicName::new(topic_name).expect("a valid topic name"),
        consumer_id: consumer,
        consumer_group: Setting::Unset,
        delivery: SubscriptionDelivery::Pull,
        ack_policy: AckPolicy::standard(),
        filter: Setting::Unset,
        status: SubscriptionStatus::Active,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// Delivery by push to `https://hooks.acme.com/orders`, signed with
/// `secret` sealed.
///
/// # Panics
///
/// Never: the address is a fixed public HTTPS URL.
#[must_use]
pub fn pushed_to_acme(secret: &str) -> SubscriptionDelivery {
    let url = PublicHttpsUrl::new("https://hooks.acme.com/orders").expect("a public HTTPS URL");
    SubscriptionDelivery::Push(PushEndpoint::new(url, sealed(secret)))
}

/// A JSON Schema called `schema_name`, held to no compatibility mode,
/// registered at the fixed moment by Ann with [`ORDER_SCHEMA`] as its one
/// version.
///
/// # Panics
///
/// When `schema_name` is not a valid label, which is a mistake in the
/// test.
#[must_use]
pub fn schema_row(schema_name: &str) -> EventSchemaRow {
    EventSchemaRow {
        id: EventSchemaId::new(),
        name: Label::new("name", schema_name).expect("a valid name"),
        schema_name: Label::new("schema_name", schema_name).expect("a valid name"),
        description: None,
        format: SchemaFormat::JsonSchema,
        compatibility: CompatibilityMode::None,
        versions: vec![version(1, ORDER_SCHEMA, 0)],
        created_by: CreatedBy::Person(human(UserId::new(), "ann@acme.example")),
        created_at: at(0),
        updated_at: at(0),
    }
}

/// Version `number` of a schema, holding `definition`, registered at
/// `seconds` after the fixed moment.
///
/// # Panics
///
/// When `definition` is blank, which is a mistake in the test.
#[must_use]
pub fn version(number: u32, definition: &str, seconds: i64) -> SchemaVersion {
    SchemaVersion {
        version: number,
        definition: SchemaDefinition::new(definition).expect("a valid definition"),
        created_at: at(seconds),
    }
}

/// A channel opened by a person at the fixed moment for an hour, carrying
/// every topic in `sender`'s area to `receiver`, up to internal data.
///
/// # Panics
///
/// Never: the pattern names the sender's own area.
#[must_use]
pub fn channel_row(sender: AgentId, receiver: AgentId) -> AgentChannelRow {
    let area = format!("agents.{}.>", sender.as_uuid().simple());
    AgentChannelRow {
        id: AgentChannelId::new(),
        sender,
        receiver,
        scope: ChannelScope::Topics(TopicPattern::new(area).expect("a valid pattern")),
        max_class: DataClassLevel::Internal,
        opened_by: PrincipalRef::User(UserId::new()),
        opened_at: at(0),
        expires_at: at(3600),
        ending: Ending::Ongoing,
    }
}

/// The consumer `row` describes, saved in `tenant` through the consumer
/// store, for the rows that point at a service.
///
/// # Panics
///
/// When the row is inconsistent or cannot be saved, which is a mistake in
/// the test.
pub async fn a_consumer_from(db: &TestDb, tenant: &ScopedTenant, row: ConsumerRow) -> ConsumerId {
    let consumer: Consumer<ResolvedTenant> =
        Consumer::reconstitute(row).expect("a consistent consumer row");
    PgConsumerStore::new(Arc::clone(&db.databases))
        .save(tenant, &consumer)
        .await
        .expect("the consumer is saved");
    *consumer.id()
}

/// An active consumer named `name` saved in `tenant`.
///
/// # Panics
///
/// When it cannot be saved, which is a mistake in the test.
pub async fn a_consumer(db: &TestDb, tenant: &ScopedTenant, name: &str) -> ConsumerId {
    a_consumer_from(db, tenant, consumer_row(name)).await
}

/// An active agent saved in `tenant` through the agent store, owned by a
/// person saved there too, for the rows that point at an agent.
///
/// # Panics
///
/// When either cannot be saved, which is a mistake in the test.
pub async fn an_agent(db: &TestDb, tenant: &ScopedTenant) -> AgentId {
    let id = AgentId::new();
    let address = format!("owner-{}@acme.example", id.as_uuid().simple());
    let owner = a_person(db, tenant, &address).await;
    let agent: AgentIdentity<ResolvedTenant> = AgentIdentity::reconstitute(AgentIdentityRow {
        id,
        name: Label::new("agent_name", format!("agent-{}", id.as_uuid().simple()))
            .expect("a valid name"),
        description: None,
        owner: human(owner, &address),
        offer: OwnershipOffer::Unoffered,
        status: AgentStatus::Active,
        proof: AgentProof::EnrolledKey,
        containment: Containment::Free,
        last_attested_at: None,
        created_at: at(0),
        updated_at: at(0),
    })
    .expect("a consistent agent row");
    PgAgentStore::new(Arc::clone(&db.databases))
        .save(tenant, &agent)
        .await
        .expect("the agent is saved");
    id
}
