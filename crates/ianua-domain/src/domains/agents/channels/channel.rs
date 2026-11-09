//! A person's permission for two agents to exchange data.
//!
//! Agents exchange data in two ways ianua can see. They send messages, and
//! they hold rights on the same object. Both need a channel a person opened.
//!
//! - **Messages.** An agent publishes only in its own area, see
//!   [`AgentArea`](crate::domains::agents::channels::area::AgentArea). Nothing
//!   it writes there reaches another agent until a channel allows it. The
//!   channel names both agents and the sender's topics the receiver may read.
//!   It also names the most sensitive data that may travel, and when it ends.
//! - **Shared resources.** If one agent can write an object another can read,
//!   they can pass messages through it. So giving two agents rights on the
//!   same object, where either may write, needs a channel naming the object.
//!
//! Only a person opens a channel. A channel decides which agents may talk at
//! all. An agent that could open one could talk to anyone. The person must
//! also have a say over the sending agent, because the channel hands what it
//! holds to the receiver.
//!
//! A closed or expired channel carries nothing. Nor does a channel whose scope
//! does not cover the request.

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::agents::authority::capability::{Relation, ResourceRef, TopicPattern};
use crate::domains::agents::channels::area::AgentArea;
use crate::domains::agents::events::channels::{AgentChannelClosed, AgentChannelOpened};
use crate::domains::agents::identity::control::AgentControl;
use crate::domains::authorization::permission::AgentAction;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::messaging::topic::Topic;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::numeric::validate_range;
use crate::types::{AgentChannelId, AgentId, Ending, Human, PrincipalRef, Seconds};

/// The longest a channel may stay open, in seconds (30 days).
const MAX_LIFETIME_SECONDS: u32 = 30 * 24 * 60 * 60;
/// The shortest a channel may stay open, in seconds.
const MIN_LIFETIME_SECONDS: u32 = 60;

/// What a channel lets travel between its two agents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelScope {
    /// Topics in the sender's area the receiver may read.
    Topics(TopicPattern),
    /// One object both agents may hold rights on, at least one of them to
    /// write.
    Resource(ResourceRef),
}

impl ChannelScope {
    /// The topic pattern or resource reference, as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Topics(pattern) => pattern.as_str(),
            Self::Resource(resource) => resource.as_str(),
        }
    }

    /// The stored name of the kind: `topics` or `resource`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Topics(_) => "topics",
            Self::Resource(_) => "resource",
        }
    }

    /// Rebuilds a scope from its stored kind and value.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the kind is unknown, or the value
    ///   is not a valid pattern or reference. Stored data that does not parse
    ///   is corrupted, not invalid input.
    pub fn from_stored(kind: &str, value: &str) -> Result<Self, DomainError> {
        let corrupted = |_| DomainError::infra_msg("stored channel scope does not parse");
        match kind {
            "topics" => TopicPattern::new(value)
                .map(Self::Topics)
                .map_err(corrupted),
            "resource" => ResourceRef::new(value)
                .map(Self::Resource)
                .map_err(corrupted),
            _ => Err(DomainError::corrupt_row(
                "agent channel",
                "an unknown scope kind",
            )),
        }
    }
}

/// Whether two agents holding these relations on the same object could pass
/// data through it. If so, granting the second relation needs a channel.
///
/// Two readers cannot pass data. A writer and anyone else can.
#[must_use]
pub fn sharing_needs_channel(held: &Relation, granted: &Relation) -> bool {
    held.may_write() || granted.may_write()
}

/// An object two agents would hold rights on, with how sensitive its data
/// is.
#[derive(Debug, Clone, Copy)]
pub struct SharedObject<'a> {
    /// The object.
    pub resource: &'a ResourceRef,
    /// The most sensitive data it holds.
    pub class: DataClassLevel,
}

/// What a person asks for when opening a channel.
pub struct OpenChannelParams {
    /// The agent whose area the messages come from.
    pub sender: AgentId,
    /// The agent that may read them.
    pub receiver: AgentId,
    /// What may travel.
    pub scope: ChannelScope,
    /// The most sensitive data that may travel through the channel.
    pub max_class: DataClassLevel,
    /// How long the channel stays open, in seconds.
    pub lifetime_seconds: Seconds,
}

/// Persisted state for reconstitution.
pub struct AgentChannelRow {
    /// Unique identifier.
    pub id: AgentChannelId,
    /// The agent whose area the messages come from.
    pub sender: AgentId,
    /// The agent that may read them.
    pub receiver: AgentId,
    /// What may travel.
    pub scope: ChannelScope,
    /// The most sensitive data that may travel.
    pub max_class: DataClassLevel,
    /// The person who opened it.
    pub opened_by: PrincipalRef,
    /// When it was opened.
    pub opened_at: OffsetDateTime,
    /// When it closes by itself.
    pub expires_at: OffsetDateTime,
    /// Whether it has ended, and when.
    pub ending: Ending,
}

/// A person's permission for two agents to exchange messages or share an
/// object.
#[derive(Debug)]
pub struct AgentChannel<T: TenantScope> {
    id: AgentChannelId,
    sender: AgentId,
    receiver: AgentId,
    scope: ChannelScope,
    max_class: DataClassLevel,
    opened_by: PrincipalRef,
    opened_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    /// Whether it has ended, and when.
    ending: Ending,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// Checks that the channel runs between two different agents, over topics
/// the sender owns, for a lifetime in range.
fn ensure_openable(params: &OpenChannelParams) -> Result<(), DomainError> {
    if params.sender == params.receiver {
        return Err(DomainError::invalid(message!(
            "agents-an-agent-reads-its-own-area",
            "an agent reads its own area without a channel"
        )));
    }
    if let ChannelScope::Topics(topics) = &params.scope
        && !AgentArea::of(params.sender).covers(topics)
    {
        return Err(DomainError::invalid(message!(
            "agents-a-channel-carries-only-topics-in",
            "a channel carries only topics in the sender's own area"
        )));
    }
    validate_range(
        "lifetime_seconds",
        params.lifetime_seconds.get(),
        MIN_LIFETIME_SECONDS..=MAX_LIFETIME_SECONDS,
    )?;
    Ok(())
}

impl<T: TenantScope> AgentChannel<T> {
    /// Opens a channel from the agent `sender_owner` owns.
    ///
    /// The person opening it must own the sending agent, or hold the agent
    /// permission to change agents. The channel hands what the sender holds
    /// to the receiver. Sam may only view agents. Without this check, Sam
    /// opens a channel from Ann's finance agent to his own agent and reads
    /// its topics.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person opening it neither owns
    ///   the sending agent nor may change agents.
    /// - [`DomainError::Validation`] when the sender and receiver are the same
    ///   agent.
    /// - [`DomainError::Validation`] when a topic scope reaches outside the
    ///   sender's area.
    /// - [`DomainError::Validation`] when the lifetime is under a minute or
    ///   over 30 days.
    ///
    /// Raises `messaging.channel_opened`.
    pub fn open(
        control: &AgentControl<'_>,
        sender_owner: &Human,
        params: OpenChannelParams,
    ) -> Result<Self, DomainError> {
        control.ensure_may(sender_owner, AgentAction::Update)?;
        ensure_openable(&params)?;
        let now = crate::shared::clock::now();
        let mut channel = Self {
            id: AgentChannelId::new(),
            sender: params.sender,
            receiver: params.receiver,
            scope: params.scope,
            max_class: params.max_class,
            opened_by: control.by().principal(),
            opened_at: now,
            expires_at: now
                .saturating_add(Duration::seconds(i64::from(params.lifetime_seconds.get()))),
            ending: Ending::Ongoing,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        channel.raised.raise(AgentChannelOpened {
            channel_id: channel.id,
            sender: channel.sender,
            receiver: channel.receiver,
            scope: channel.scope.clone(),
            max_class: channel.max_class,
            expires_at: channel.expires_at,
            occurred_at: now,
        });
        Ok(channel)
    }

    /// Rebuilds a channel from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row breaks a rule of
    ///   [`open`](Self::open): a person opens it, between two agents, over
    ///   topics the sender owns, for a lifetime in range.
    /// - [`DomainError::Infrastructure`] when it closed before it was opened.
    pub fn reconstitute(row: AgentChannelRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            sender: row.sender,
            receiver: row.receiver,
            scope: row.scope,
            max_class: row.max_class,
            opened_by: row.opened_by,
            opened_at: row.opened_at,
            expires_at: row.expires_at,
            ending: row.ending,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &AgentChannelRow) -> Result<(), DomainError> {
        RowCheck::of("agent channel")
            .holds(opened_as_allowed(row), "opened by an agent, from an agent to itself, or over topics outside the sender's area")
            .holds(lifetime_in_range(row), "a lifetime no channel may be opened for")
            .in_order_if(row.opened_at, row.ending.ended_at(), "closed before it was opened")
            .finish()
    }

    /// Unique identifier.
    #[must_use]
    pub fn id(&self) -> &AgentChannelId {
        &self.id
    }

    /// The agent whose area the messages come from.
    #[must_use]
    pub fn sender(&self) -> &AgentId {
        &self.sender
    }

    /// The agent that may read them.
    #[must_use]
    pub fn receiver(&self) -> &AgentId {
        &self.receiver
    }

    /// What may travel.
    #[must_use]
    pub fn scope(&self) -> &ChannelScope {
        &self.scope
    }

    /// The most sensitive data that may travel.
    #[must_use]
    pub fn max_class(&self) -> DataClassLevel {
        self.max_class
    }

    /// The person who opened it.
    #[must_use]
    pub fn opened_by(&self) -> &PrincipalRef {
        &self.opened_by
    }

    /// When it was opened.
    #[must_use]
    pub fn opened_at(&self) -> OffsetDateTime {
        self.opened_at
    }

    /// When it closes by itself.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When a person closed it, if they did.
    #[must_use]
    pub fn closed_at(&self) -> Option<OffsetDateTime> {
        self.ending.ended_at()
    }

    /// Whether the channel is open at `now`: not closed, not expired.
    #[must_use]
    pub fn is_open(&self, now: OffsetDateTime) -> bool {
        !self.ending.has_ended() && now < self.expires_at
    }

    /// Whether `receiver` may read `topic` through this channel at `now`.
    ///
    /// The class comes from the topic, never from the caller. The topic must
    /// also take agent messages, see [`Topic::accepts_agent_messages`]. Bob's
    /// agent asks to read a restricted topic through a channel for internal
    /// data. If the caller named the class, it could call the topic internal
    /// and read it.
    #[must_use]
    pub fn carries(&self, receiver: &AgentId, topic: &Topic<T>, now: OffsetDateTime) -> bool {
        let ChannelScope::Topics(topics) = &self.scope else {
            return false;
        };
        let Ok(requested) = TopicPattern::new(topic.topic_name().as_str()) else {
            return false;
        };
        self.is_open(now)
            && self.receiver == *receiver
            && topic.accepts_agent_messages()
            && topic.data_class() <= self.max_class
            && topics.covers(&requested)
    }

    /// Whether this channel lets agents `a` and `b` hold rights on `object`
    /// together at `now`, in either direction.
    ///
    /// The object's class must sit within the channel's, the same as a
    /// topic's. A channel opened for internal data does not let two agents
    /// pass restricted records through a shared document.
    #[must_use]
    pub fn shares(
        &self,
        a: &AgentId,
        b: &AgentId,
        object: SharedObject<'_>,
        now: OffsetDateTime,
    ) -> bool {
        let ChannelScope::Resource(shared) = &self.scope else {
            return false;
        };
        let pair = (self.sender == *a && self.receiver == *b)
            || (self.sender == *b && self.receiver == *a);
        self.is_open(now) && pair && shared == object.resource && object.class <= self.max_class
    }

    /// Refuses the person `control` names unless they may close the
    /// channel: they opened it, own the sending agent, whose owner is
    /// `sender_owner`, or may change agents. Sam cannot close the channels
    /// Ann's agents rely on.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person neither opened it nor has
    ///   a say over the sending agent.
    pub fn ensure_closable_by(
        &self,
        control: &AgentControl<'_>,
        sender_owner: &Human,
    ) -> Result<(), DomainError> {
        if control.by().principal() == self.opened_by {
            return Ok(());
        }
        control.ensure_may(sender_owner, AgentAction::Update)
    }

    /// Closes the channel. Nothing travels through it afterwards.
    /// Raises `messaging.channel_closed`.
    ///
    /// Only someone [`Self::ensure_closable_by`] lets through closes it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person neither opened it nor has
    ///   a say over the sending agent.
    /// - [`DomainError::InvalidTransition`] when it is already closed.
    pub fn close(
        &mut self,
        control: &AgentControl<'_>,
        sender_owner: &Human,
    ) -> Result<(), DomainError> {
        self.ensure_closable_by(control, sender_owner)?;
        if self.ending.has_ended() {
            return Err(DomainError::invalid_transition(message!(
                "agents-the-channel-is-already-closed",
                "the channel is already closed"
            )));
        }
        let at = crate::shared::clock::now();
        self.ending = Ending::Ended { at };
        self.raised.raise(AgentChannelClosed {
            channel_id: self.id,
            scope: self.scope.clone(),
            occurred_at: at,
        });
        Ok(())
    }
}

impl<T: TenantScope> Raises for AgentChannel<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for AgentChannel<T> {
    type Id = AgentChannelId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.opened_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.ending.ended_at().unwrap_or(self.opened_at)
    }
}

/// Whether a stored channel keeps the rules it was opened under: opened by a
/// person, between two agents, over topics the sender owns.
fn opened_as_allowed(row: &AgentChannelRow) -> bool {
    let by_a_person = matches!(
        row.opened_by,
        PrincipalRef::User(_) | PrincipalRef::OrgUser(_)
    );
    let within_area = match &row.scope {
        ChannelScope::Topics(topics) => AgentArea::of(row.sender).covers(topics),
        ChannelScope::Resource(_) => true,
    };
    by_a_person && row.sender != row.receiver && within_area
}

/// Whether a stored channel's lifetime is one a channel may be opened for.
fn lifetime_in_range(row: &AgentChannelRow) -> bool {
    let lifetime = crate::shared::clock::between(row.opened_at, row.expires_at).whole_seconds();
    (i64::from(MIN_LIFETIME_SECONDS)..=i64::from(MAX_LIFETIME_SECONDS)).contains(&lifetime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::domains::messaging::control::MessagingCreator;
    use crate::domains::messaging::fixtures::{creating_service, messaging_admin};
    use crate::domains::messaging::schema::SchemaDefinition;
    use crate::domains::messaging::topic::{CreateTopicParams, RetentionPolicy};
    use crate::domains::messaging::topic_name::TopicName;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::builders::label;
    use crate::test_support::events::raised_names;
    use crate::types::{HumanAccount, PersonKey, Seconds, Setting, TenantId, UserId};

    fn area_topic(agent: AgentId, rest: &str) -> String {
        format!("agents.{}.{rest}", agent.as_uuid().as_simple())
    }

    fn person(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    fn holding<'a>(by: &'a Human, system: &'a [SystemPermission]) -> AgentControl<'a> {
        AgentControl::new(assumed_authority(by, TenantId::new(), system, &[]))
    }

    fn params(sender: AgentId, receiver: AgentId) -> OpenChannelParams {
        OpenChannelParams {
            sender,
            receiver,
            scope: ChannelScope::Topics(TopicPattern::new(area_topic(sender, ">")).unwrap()),
            max_class: DataClassLevel::Internal,
            lifetime_seconds: Seconds::new(3600),
        }
    }

    /// `params` opened by Ann, who owns the sending agent.
    fn opened(params: OpenChannelParams) -> Result<AgentChannel<ResolvedTenant>, DomainError> {
        let ann = person("ann@corp.test");
        AgentChannel::open(&holding(&ann, &[]), &ann, params)
    }

    fn open(sender: AgentId, receiver: AgentId) -> AgentChannel<ResolvedTenant> {
        opened(params(sender, receiver)).unwrap()
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// The topic `rest` in `agent`'s area, with a schema and `data_class`.
    fn topic(agent: AgentId, rest: &str, data_class: DataClassLevel) -> Topic<ResolvedTenant> {
        let params = CreateTopicParams {
            name: label("Tasks"),
            topic_name: TopicName::new(area_topic(agent, rest)).unwrap(),
            description: None,
            schema: Setting::Set(SchemaDefinition::new(r#"{"type":"object"}"#).unwrap()),
            retention: RetentionPolicy::Unlimited,
            data_class,
        };
        Topic::create(params, MessagingCreator::Consumer(&creating_service())).unwrap()
    }

    /// Ann opens a channel over everything in the sender's area. The receiver
    /// may read the sender's internal `tasks` topic.
    #[test]
    fn an_open_channel_carries_the_senders_topics_to_the_receiver() {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        let channel = open(sender, receiver);
        let tasks = topic(sender, "tasks", DataClassLevel::Internal);

        assert!(channel.carries(&receiver, &tasks, now()));
    }

    /// A channel to one receiver carries no topic to a third agent, even
    /// when the topic is public.
    #[test]
    fn it_carries_nothing_to_any_other_agent() {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        let channel = open(sender, receiver);
        let tasks = topic(sender, "tasks", DataClassLevel::Public);

        assert!(!channel.carries(&AgentId::new(), &tasks, now()));
    }

    /// A channel limited to internal data refuses the sender's restricted
    /// salaries topic even for the designated receiver.
    #[test]
    fn it_carries_nothing_more_sensitive_than_it_allows() {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        let channel = open(sender, receiver);
        let salaries = topic(sender, "salaries", DataClassLevel::Restricted);

        assert!(!channel.carries(&receiver, &salaries, now()));
    }

    /// A channel carries neither a topic without a schema nor a paused
    /// topic, even when its receiver and data class otherwise match.
    #[test]
    fn it_carries_nothing_from_a_topic_that_takes_no_agent_messages() {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        let channel = open(sender, receiver);
        let admin = messaging_admin();
        let mut free_text = topic(sender, "notes", DataClassLevel::Public);
        free_text.change_schema(Setting::Unset, &admin).unwrap();
        let mut paused = topic(sender, "tasks", DataClassLevel::Public);
        paused.pause(&admin).unwrap();

        assert!(!channel.carries(&receiver, &free_text, now()));
        assert!(!channel.carries(&receiver, &paused, now()));
    }

    /// One channel is closed by a person. Another reaches its expiry time.
    /// Neither carries even a public topic afterwards.
    #[test]
    fn it_carries_nothing_once_closed_or_expired() {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        let tasks = topic(sender, "tasks", DataClassLevel::Public);
        let mut closed = open(sender, receiver);
        let ann = person("ann@corp.test");
        closed.close(&holding(&ann, &[]), &ann).unwrap();
        let expiring = open(sender, receiver);

        assert!(!closed.carries(&receiver, &tasks, now()));
        assert!(!expiring.carries(&receiver, &tasks, expiring.expires_at()));
    }

    /// Ann opens a channel over the sender's `tasks` topic only. The receiver
    /// asks for the sender's `secrets` topic and is refused.
    #[test]
    fn a_narrow_channel_carries_only_its_topics() {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        let channel = opened(OpenChannelParams {
            scope: ChannelScope::Topics(TopicPattern::new(area_topic(sender, "tasks")).unwrap()),
            ..params(sender, receiver)
        })
        .unwrap();
        let other = topic(sender, "secrets", DataClassLevel::Public);

        assert!(!channel.carries(&receiver, &other, now()));
    }

    /// A viewer cannot open a channel from another person's agent, while
    /// someone allowed to update agents can open the same channel.
    #[test]
    fn only_the_senders_owner_or_someone_changing_agents_opens_a_channel() {
        let (ann, sam, bob) = (
            person("ann@corp.test"),
            person("sam@corp.test"),
            person("bob@corp.test"),
        );
        let view = [SystemPermission::Agents(AgentAction::View)];
        let update = [SystemPermission::Agents(AgentAction::Update)];
        let (finance, sams_agent) = (AgentId::new(), AgentId::new());

        let by_sam = AgentChannel::<ResolvedTenant>::open(
            &holding(&sam, &view),
            &ann,
            params(finance, sams_agent),
        );
        let by_bob = AgentChannel::<ResolvedTenant>::open(
            &holding(&bob, &update),
            &ann,
            params(finance, sams_agent),
        );

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_bob.is_ok());
    }

    /// Ann opens a channel through her tenant account. The channel records
    /// that account as the one that opened it.
    #[test]
    fn a_channel_records_the_person_who_opened_it() {
        let ann = person("ann@corp.test");

        let channel = AgentChannel::<ResolvedTenant>::open(
            &holding(&ann, &[]),
            &ann,
            params(AgentId::new(), AgentId::new()),
        )
        .unwrap();

        assert_eq!(channel.opened_by(), &ann.principal());
    }

    /// Channel creation refuses global topic wildcards and the receiver's
    /// area because those scopes reach beyond the sender's topics.
    #[test]
    fn a_channel_cannot_reach_outside_the_senders_area() {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        for topics in [
            ">".to_owned(),
            "agents.>".to_owned(),
            area_topic(receiver, ">"),
        ] {
            let result = opened(OpenChannelParams {
                scope: ChannelScope::Topics(TopicPattern::new(topics.clone()).unwrap()),
                ..params(sender, receiver)
            });

            assert!(
                matches!(result, Err(DomainError::Validation(_))),
                "{topics}"
            );
        }
    }

    /// A person opens a channel whose sender and receiver are the same agent.
    /// It is refused, because an agent already reads its own area.
    #[test]
    fn an_agent_needs_no_channel_to_itself() {
        let agent = AgentId::new();

        let result = opened(params(agent, agent));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// Lifetimes of 0 seconds, 59 seconds and one second over 30 days are all
    /// refused.
    #[test]
    fn a_channel_lives_between_a_minute_and_thirty_days() {
        let (sender, receiver) = (AgentId::new(), AgentId::new());
        for lifetime_seconds in [0, 59, MAX_LIFETIME_SECONDS + 1] {
            let result = opened(OpenChannelParams {
                lifetime_seconds: Seconds::new(lifetime_seconds),
                ..params(sender, receiver)
            });

            assert!(result.is_err(), "{lifetime_seconds}");
        }
    }

    /// A person closes a channel that is already closed. It fails as an
    /// invalid transition, so the first close time stays on record.
    #[test]
    fn closing_twice_is_refused() {
        let mut channel = open(AgentId::new(), AgentId::new());
        let ann = person("ann@corp.test");
        channel.close(&holding(&ann, &[]), &ann).unwrap();

        assert!(matches!(
            channel.close(&holding(&ann, &[]), &ann),
            Err(DomainError::InvalidTransition(_))
        ));
    }

    /// Someone who neither opened the channel nor controls its sender cannot
    /// close it; the channel remains open after the forbidden attempt.
    #[test]
    fn only_the_opener_or_someone_with_a_say_closes_a_channel() {
        let mut channel = open(AgentId::new(), AgentId::new());
        let ann = person("ann@corp.test");
        let sam = person("sam@corp.test");

        let by_sam = channel.close(&holding(&sam, &[]), &ann);

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(channel.is_open(now()));
    }

    /// A resource channel permits its document at internal classification but
    /// refuses the same document when classified restricted.
    #[test]
    fn a_resource_channel_shares_nothing_above_its_class() {
        let (a, b) = (AgentId::new(), AgentId::new());
        let channel = resource_channel(a, b, "doc:1");
        let doc = ResourceRef::new("doc:1").unwrap();

        assert!(channel.shares(
            &a,
            &b,
            SharedObject {
                resource: &doc,
                class: DataClassLevel::Internal
            },
            now()
        ));
        assert!(!channel.shares(
            &a,
            &b,
            SharedObject {
                resource: &doc,
                class: DataClassLevel::Restricted
            },
            now()
        ));
    }

    fn resource_channel(a: AgentId, b: AgentId, resource: &str) -> AgentChannel<ResolvedTenant> {
        opened(OpenChannelParams {
            scope: ChannelScope::Resource(ResourceRef::new(resource).unwrap()),
            ..params(a, b)
        })
        .unwrap()
    }

    /// A channel over `doc:1` lets its two agents share it in either order. A
    /// third agent, or another document, is not covered.
    #[test]
    fn a_resource_channel_lets_its_two_agents_share_the_object_either_way() {
        let (a, b) = (AgentId::new(), AgentId::new());
        let channel = resource_channel(a, b, "doc:1");
        let doc = ResourceRef::new("doc:1").unwrap();
        let public_doc = SharedObject {
            resource: &doc,
            class: DataClassLevel::Public,
        };

        assert!(channel.shares(&a, &b, public_doc, now()));
        assert!(channel.shares(&b, &a, public_doc, now()));
        assert!(!channel.shares(&a, &AgentId::new(), public_doc, now()));
        assert!(!channel.shares(
            &a,
            &b,
            SharedObject {
                resource: &ResourceRef::new("doc:2").unwrap(),
                class: DataClassLevel::Public
            },
            now()
        ));
    }

    /// A channel over a document does not carry topic messages. A channel over
    /// topics does not allow sharing a document. Each covers only its own kind.
    #[test]
    fn a_resource_channel_carries_no_messages_and_a_topic_channel_shares_no_object() {
        let (a, b) = (AgentId::new(), AgentId::new());
        let resource = resource_channel(a, b, "doc:1");
        let topics = open(a, b);
        let tasks = topic(a, "tasks", DataClassLevel::Public);

        assert!(!resource.carries(&b, &tasks, now()));
        assert!(!topics.shares(
            &a,
            &b,
            SharedObject {
                resource: &ResourceRef::new("doc:1").unwrap(),
                class: DataClassLevel::Public
            },
            now()
        ));
    }

    /// Two agents that only read a document cannot pass data through it. Once
    /// either holds `editor`, sharing the document needs a channel.
    #[test]
    fn two_readers_share_freely_but_a_writer_needs_a_channel() {
        let reader = Relation::new("reader").unwrap();
        let editor = Relation::new("editor").unwrap();

        assert!(!sharing_needs_channel(&reader, &reader));
        assert!(sharing_needs_channel(&editor, &reader));
        assert!(sharing_needs_channel(&reader, &editor));
    }

    /// A topic scope and a resource scope read back equal from their stored
    /// kind and value. An unknown kind such as `pigeon` is an infrastructure
    /// error, since it means corrupted storage.
    #[test]
    fn a_scope_round_trips_through_its_stored_form_and_rejects_corruption() {
        let topics = ChannelScope::Topics(TopicPattern::new("agents.x.>").unwrap());
        let resource = ChannelScope::Resource(ResourceRef::new("doc:1").unwrap());

        for scope in [topics, resource] {
            assert_eq!(
                ChannelScope::from_stored(scope.kind(), scope.as_str()).unwrap(),
                scope
            );
        }
        assert!(matches!(
            ChannelScope::from_stored("pigeon", "x"),
            Err(DomainError::Infrastructure(_))
        ));
    }

    fn stored(channel: &AgentChannel<ResolvedTenant>) -> AgentChannelRow {
        AgentChannelRow {
            id: channel.id,
            sender: channel.sender,
            receiver: channel.receiver,
            scope: channel.scope.clone(),
            max_class: channel.max_class,
            opened_by: channel.opened_by,
            opened_at: channel.opened_at,
            expires_at: channel.expires_at,
            ending: channel.ending,
        }
    }

    /// A freshly opened channel, saved and read back, is accepted.
    #[test]
    fn a_stored_channel_reads_back() {
        let channel = open(AgentId::new(), AgentId::new());

        assert!(AgentChannel::<ResolvedTenant>::reconstitute(stored(&channel)).is_ok());
    }

    /// Stored channels opened by an agent or connecting an agent to itself
    /// are refused as corrupt when reconstructed.
    #[test]
    fn a_stored_channel_its_opening_rules_forbid_is_refused() {
        let mut by_an_agent = stored(&open(AgentId::new(), AgentId::new()));
        by_an_agent.opened_by = PrincipalRef::Agent(by_an_agent.sender);
        let mut to_itself = stored(&open(AgentId::new(), AgentId::new()));
        to_itself.receiver = to_itself.sender;

        for row in [by_an_agent, to_itself] {
            assert!(refused_as_corrupt(
                &AgentChannel::<ResolvedTenant>::reconstitute(row)
            ));
        }
    }

    /// A stored channel expires 31 days after it opened. No channel may be
    /// opened that long, so the row is refused as corrupt.
    #[test]
    fn a_stored_channel_open_longer_than_any_may_be_is_refused() {
        let mut row = stored(&open(AgentId::new(), AgentId::new()));
        row.expires_at = row.opened_at + time::Duration::days(31);

        assert!(refused_as_corrupt(
            &AgentChannel::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Ann opens a channel from her agent to Bob's. The opening is raised.
    #[test]
    fn opening_raises_messaging_channel_opened() {
        let mut channel = open(AgentId::new(), AgentId::new());

        assert_eq!(raised_names(&mut channel), ["messaging.channel_opened"]);
    }

    /// Ann closes the channel she opened. The close is raised.
    #[test]
    fn closing_raises_messaging_channel_closed() {
        let ann = person("ann@corp.test");
        let mut channel = open(AgentId::new(), AgentId::new());
        raised_names(&mut channel);

        channel.close(&holding(&ann, &[]), &ann).unwrap();

        assert_eq!(raised_names(&mut channel), ["messaging.channel_closed"]);
    }

    /// Closing someone else's channel without control of its sender is
    /// refused without raising a closure event.
    #[test]
    fn a_refused_close_raises_nothing() {
        let (ann, sam) = (person("ann@corp.test"), person("sam@corp.test"));
        let mut channel = open(AgentId::new(), AgentId::new());
        raised_names(&mut channel);

        let refused = channel.close(&holding(&sam, &[]), &ann);

        assert!(refused.is_err());
        assert!(raised_names(&mut channel).is_empty());
    }

    /// A channel is read back from storage. Loading it is no change, so it
    /// has raised nothing.
    #[test]
    fn a_channel_read_back_from_storage_has_raised_nothing() {
        let channel = open(AgentId::new(), AgentId::new());

        let mut read = AgentChannel::<ResolvedTenant>::reconstitute(stored(&channel)).unwrap();

        assert!(raised_names(&mut read).is_empty());
    }
}
