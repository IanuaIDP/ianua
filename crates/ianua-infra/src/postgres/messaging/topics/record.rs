//! A topic as its row holds it: read back into the aggregate, and written
//! out from it.

use std::num::{NonZeroU32, NonZeroU64};

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::messaging::schema::SchemaDefinition;
use ianua_domain::domains::messaging::topic::{RetentionPolicy, Topic, TopicRow};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{Label, Setting, TopicId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::messaging::creators::{CreatorColumns, creator_from};

const TOPIC: Stored = Stored("topic");

/// A topic as it is read. The store's checked queries fill it.
pub(super) struct TopicRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) topic_name: String,
    pub(super) description: Option<String>,
    pub(super) schema_definition: Option<String>,
    pub(super) retention_kind: String,
    pub(super) retention_amount: Option<i64>,
    pub(super) status: String,
    pub(super) created_by_kind: String,
    pub(super) created_by_id: Uuid,
    pub(super) created_by_person: Option<String>,
    pub(super) data_class: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl TopicRecord {
    /// The topic the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the topic
    /// keeps.
    pub(super) fn into_topic(self) -> Result<Topic<ResolvedTenant>, DomainError> {
        let schema = self
            .schema_definition
            .map(|text| TOPIC.value("schema", SchemaDefinition::new(text)))
            .transpose()?;
        Topic::reconstitute(TopicRow {
            id: TopicId::from_uuid(self.id),
            name: TOPIC.value("name", Label::new("name", self.name))?,
            topic_name: TOPIC.value("topic name", TopicName::new(self.topic_name))?,
            description: self
                .description
                .map(|text| TOPIC.value("description", Label::new("description", text)))
                .transpose()?,
            schema: Setting::from_stored(schema),
            retention: retention_from(&self.retention_kind, self.retention_amount)?,
            status: TOPIC.choice(&self.status)?,
            created_by: creator_from(
                TOPIC,
                &self.created_by_kind,
                self.created_by_id,
                self.created_by_person,
            )?,
            data_class: DataClassLevel::from_stored(&self.data_class)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The retention the two retention columns hold.
fn retention_from(kind: &str, amount: Option<i64>) -> Result<RetentionPolicy, DomainError> {
    let unreadable = || DomainError::corrupt_row(TOPIC.0, "a retention rule that does not read");
    match (kind, amount) {
        ("unlimited", None) => Ok(RetentionPolicy::Unlimited),
        ("duration", Some(seconds)) => u32::try_from(seconds)
            .ok()
            .and_then(NonZeroU32::new)
            .map(RetentionPolicy::Duration)
            .ok_or_else(unreadable),
        ("message_count", Some(count)) => u64::try_from(count)
            .ok()
            .and_then(NonZeroU64::new)
            .map(RetentionPolicy::MessageCount)
            .ok_or_else(unreadable),
        _ => Err(unreadable()),
    }
}

/// A topic's columns, as they are written.
pub(super) struct TopicColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) topic_name: &'a str,
    pub(super) description: Option<&'a str>,
    pub(super) schema_definition: Option<&'a str>,
    pub(super) retention_kind: &'static str,
    pub(super) retention_amount: Option<i64>,
    pub(super) status: &'static str,
    pub(super) created_by: CreatorColumns<'a>,
    pub(super) data_class: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> TopicColumns<'a> {
    /// The columns `topic` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a message count does not
    /// fit its column.
    pub(super) fn of(topic: &'a Topic<ResolvedTenant>) -> Result<Self, DomainError> {
        let (retention_kind, retention_amount) = retention_columns(topic.retention())?;
        Ok(Self {
            id: topic.id().as_uuid(),
            name: topic.name().as_str(),
            topic_name: topic.topic_name().as_str(),
            description: topic.description().map(Label::as_str),
            schema_definition: topic.schema().map(SchemaDefinition::as_str),
            retention_kind,
            retention_amount,
            status: topic.status().word(),
            created_by: CreatorColumns::of(topic.created_by()),
            data_class: topic.data_class().as_str(),
            created_at: topic.created_at(),
            updated_at: topic.updated_at(),
        })
    }
}

/// The two retention columns `retention` is written to.
fn retention_columns(
    retention: RetentionPolicy,
) -> Result<(&'static str, Option<i64>), DomainError> {
    match retention {
        RetentionPolicy::Unlimited => Ok(("unlimited", None)),
        RetentionPolicy::Duration(seconds) => Ok(("duration", Some(i64::from(seconds.get())))),
        RetentionPolicy::MessageCount(count) => {
            let count = i64::try_from(count.get()).map_err(DomainError::infra)?;
            Ok(("message_count", Some(count)))
        }
    }
}
