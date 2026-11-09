//! The names the plane keeps things under on the server: a consumer's, and
//! the subjects messages, replays and dead letters travel on, each subject
//! under the deployment's namespace.
//!
//! A consumer is named after its tenant and a digest of the name it was
//! given, so one tenant never reaches another's consumer by naming it, and
//! any name, a consumer group's with its dots included, is one safe
//! segment. It is kept inside the namespace's messages stream, so it needs
//! no namespace of its own.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_domain::domains::messaging::message_type::{MessageFilter, MessageType};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::types::TenantId;
use sha2::{Digest as _, Sha256};

use crate::namespace::Namespace;

/// The segment a message without a type is published under: a type cannot
/// hold an underscore, so no filter on types reaches it, and every message
/// of a topic stays under one wildcard, which a retention limit counts by.
const UNTYPED: &str = "_";

/// How many bytes of a name's digest name its consumer.
const NAME_DIGEST_BYTES: usize = 16;

/// Every published message's subject, under the namespace.
pub(super) const MESSAGE_SUBJECTS: &str = "msg.>";

/// Every replayed dead letter's subject, under the namespace.
pub(super) const REPLAY_SUBJECTS: &str = "replay.>";

/// Every dead letter's subject, under the namespace.
pub(super) const DEAD_SUBJECTS: &str = "dead.>";

/// A consumer's name on the server: its tenant's id, then a digest of the
/// name it was given, written in URL-safe base64.
pub(super) struct Durable(String);

impl Durable {
    pub(super) fn of(tenant_id: &TenantId, name: &str) -> Self {
        let digest = Sha256::digest(name.as_bytes());
        let short = digest.get(..NAME_DIGEST_BYTES).unwrap_or(&digest);
        Self(format!(
            "{}-{}",
            tenant_id.as_uuid().simple(),
            URL_SAFE_NO_PAD.encode(short)
        ))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The subject every message of `topic_name` is published under, before
/// its type.
fn topic_subject(namespace: &Namespace, tenant_id: &TenantId, topic_name: &TopicName) -> String {
    namespace.subject(&format!(
        "msg.{}.{}",
        tenant_id.as_uuid().simple(),
        topic_name.as_str().replace('.', "_")
    ))
}

/// The wildcard that covers every message of `topic_name`, typed or not,
/// and no replay of a dead letter.
pub(super) fn every_message_of(
    namespace: &Namespace,
    tenant_id: &TenantId,
    topic_name: &TopicName,
) -> String {
    format!("{}.>", topic_subject(namespace, tenant_id, topic_name))
}

/// The subject a message of `message_type` is published on.
pub(super) fn message_subject(
    namespace: &Namespace,
    tenant_id: &TenantId,
    topic_name: &TopicName,
    message_type: Option<&MessageType>,
) -> String {
    let topic = topic_subject(namespace, tenant_id, topic_name);
    match message_type {
        Some(message_type) => format!("{topic}.{message_type}"),
        None => format!("{topic}.{UNTYPED}"),
    }
}

/// What a consumer reads: the topic of a tenant, the types its filter
/// lets through, and the consumer it is.
pub(super) struct Reading<'a> {
    /// The tenant whose topic it reads.
    pub(super) tenant_id: &'a TenantId,
    /// Tenant-local message address used to construct the subscription's subjects.
    pub(super) topic_name: &'a TopicName,
    /// The types it reads, or every one.
    pub(super) filter: Option<&'a MessageFilter>,
    /// The consumer.
    pub(super) durable: &'a Durable,
}

/// The subjects a consumer reads: every message of its topic, or only the
/// types under its filter, and the dead letters put back for it alone.
pub(super) fn read_subjects(namespace: &Namespace, reading: &Reading<'_>) -> Vec<String> {
    let topic = topic_subject(namespace, reading.tenant_id, reading.topic_name);
    let replays = replay_subject(namespace, reading.tenant_id, reading.durable);
    match reading.filter {
        Some(filter) => vec![
            format!("{topic}.{filter}"),
            format!("{topic}.{filter}.>"),
            replays,
        ],
        None => vec![format!("{topic}.>"), topic, replays],
    }
}

/// The subject dead letters of `durable` are put back on.
pub(super) fn replay_subject(
    namespace: &Namespace,
    tenant_id: &TenantId,
    durable: &Durable,
) -> String {
    namespace.subject(&format!(
        "replay.{}.{}",
        tenant_id.as_uuid().simple(),
        durable.as_str()
    ))
}

/// The subject `durable`'s dead letters are kept on.
pub(super) fn dead_subject(
    namespace: &Namespace,
    tenant_id: &TenantId,
    durable: &Durable,
) -> String {
    namespace.subject(&format!(
        "dead.{}.{}",
        tenant_id.as_uuid().simple(),
        durable.as_str()
    ))
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn tenant() -> TenantId {
        TenantId::from_uuid(Uuid::now_v7())
    }

    /// Dots, wildcards and spaces in consumer names become safe subject segments;
    /// identical names in different tenants produce distinct durable names.
    #[test]
    fn every_consumer_name_becomes_one_safe_segment() {
        let tenant_id = tenant();

        for name in ["group-orders.created-billing.workers", "a*", "a>", "a b"] {
            let durable = Durable::of(&tenant_id, name);
            assert!(
                durable
                    .as_str()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "{name:?} gave {}",
                durable.as_str()
            );
        }
        assert_ne!(
            Durable::of(&tenant_id, "sub-1").as_str(),
            Durable::of(&tenant(), "sub-1").as_str()
        );
    }

    /// A topic's dots become one segment, so its type follows as segments
    /// of its own and a filter on the type cannot reach into the topic. The
    /// default namespace gives the subject the plane has always used.
    #[test]
    fn a_typed_message_is_published_after_its_topic() {
        let tenant_id = tenant();
        let topic = TopicName::new("orders.created").unwrap();
        let refund = MessageType::new("order.refund").unwrap();

        let subject = message_subject(&Namespace::default(), &tenant_id, &topic, Some(&refund));

        assert_eq!(
            subject,
            format!(
                "ianua.msg.{}.orders_created.order.refund",
                tenant_id.as_uuid().simple()
            )
        );
    }

    /// A message without a type sits under its topic's one wildcard, in a
    /// segment no type filter can name.
    #[test]
    fn an_untyped_message_sits_under_its_topics_wildcard() {
        let tenant_id = tenant();
        let topic = TopicName::new("orders.created").unwrap();

        let subject = message_subject(&Namespace::default(), &tenant_id, &topic, None);
        let every = every_message_of(&Namespace::default(), &tenant_id, &topic);

        assert_eq!(format!("{}_", every.trim_end_matches('>')), subject);
    }

    /// Every subject a consumer reads, and the dead letters it keeps, sit
    /// under its namespace, so another deployment's consumer of the same
    /// tenant and name reads none of them.
    #[test]
    fn every_subject_sits_under_its_namespace() {
        let tenant_id = tenant();
        let topic = TopicName::new("orders.created").unwrap();
        let durable = Durable::of(&tenant_id, "billing");
        let staging = Namespace::new("staging").unwrap();
        let reading = Reading {
            tenant_id: &tenant_id,
            topic_name: &topic,
            filter: None,
            durable: &durable,
        };

        let mut subjects = read_subjects(&staging, &reading);
        subjects.push(dead_subject(&staging, &tenant_id, &durable));

        assert!(
            subjects
                .iter()
                .all(|subject| subject.starts_with("staging."))
        );
        assert_eq!(
            dead_subject(&Namespace::default(), &tenant_id, &durable),
            format!(
                "ianua.dead.{}.{}",
                tenant_id.as_uuid().simple(),
                durable.as_str()
            )
        );
    }
}
