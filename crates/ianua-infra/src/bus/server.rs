//! A message bus on a bus server every node reaches: any server that
//! speaks the NATS protocol with its persistent streams.
//!
//! The protocol client is the only part of the crate that knows which
//! protocol is spoken. Every subject and stream is put under the
//! deployment's [`Namespace`] here, and every subject heard taken out of it
//! again, so two deployments sharing one server never hear each other.
//! Events go to one persistent stream, `<namespace>-events`, holding every
//! `<namespace>.tenant.>`, `<namespace>.org.>` and `<namespace>.platform.>`
//! subject, for a week and a few gigabytes at most, the oldest going first;
//! the server keeps one copy of an id published again within the stream's
//! duplicate window, and a publish counts only once the server confirmed
//! it. The worker's durable consumers are kept inside that stream, so
//! their names are the namespace's through it. Broadcasts are plain
//! publishes, kept nowhere. A follower reads the stream through an ordered
//! consumer of its own, from the next event on, which the server forgets
//! once the follower is gone. Every call is held to a deadline.

mod messaging;

use std::future::IntoFuture;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use async_nats::jetstream::consumer::push::{Ordered, OrderedConfig};
use async_nats::jetstream::consumer::{AckPolicy, DeliverPolicy, pull};
use async_nats::jetstream::{self, AckKind, stream};
use async_nats::{Client, ConnectOptions, HeaderMap};
use async_trait::async_trait;
use futures_util::StreamExt as _;
use ianua_domain::shared::security::secret::Secret;

pub use self::messaging::{BusDeadLetters, BusMessageConsumer, BusMessagePublisher, MessagePlane};
use crate::bus::stream::{
    Bus, BusError, EventFeed, EventShare, Handed, Heard, HeardEvent, Listener, SealedEvent, Settle,
    Settled, SharedFeed,
};
use crate::crypto::SEAL_HEADER;
use crate::namespace::Namespace;

/// The role of the stream every event is kept in.
const EVENTS: &str = "events";

/// The subjects that stream holds, under the namespace.
const EVENT_SUBJECTS: [&str; 3] = ["tenant.>", "org.>", "platform.>"];

/// How long the server remembers an id, to keep one copy of it.
const DUPLICATE_WINDOW: Duration = Duration::from_secs(120);

/// How long the stream keeps an event. The audit trail is the record and
/// the outbox holds every event until the bus took it, so the stream only
/// has to outlast a consumer that is down: a week covers a long weekend's
/// outage with room to notice it, after which the worker's consumers and
/// the cache followers catch up from where they stopped.
const EVENTS_KEPT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The most the stream holds, in bytes, so a flood cannot fill the bus
/// server's disk: past it the oldest events go first.
const EVENTS_MOST_BYTES: i64 = 8 * 1024 * 1024 * 1024;

/// The configuration of the stream every event under `namespace` is kept
/// in.
fn events_stream(namespace: &Namespace) -> stream::Config {
    stream::Config {
        name: namespace.stream(EVENTS),
        subjects: EVENT_SUBJECTS
            .iter()
            .map(|subject| namespace.subject(subject))
            .collect(),
        duplicate_window: DUPLICATE_WINDOW,
        max_age: EVENTS_KEPT,
        max_bytes: EVENTS_MOST_BYTES,
        discard: stream::DiscardPolicy::Old,
        ..stream::Config::default()
    }
}

/// The header a published event's id travels in.
const ID_HEADER: &str = "Nats-Msg-Id";

/// The error the protocol client answered, as the bus not reached.
type ClientError = Box<dyn std::error::Error + Send + Sync>;

fn unreachable_by<E: Into<ClientError>>(error: E) -> BusError {
    BusError::Unreachable(error.into())
}

/// One persistent publication, including its destination and protocol headers.
struct Publication {
    subject: String,
    headers: HeaderMap,
    payload: Vec<u8>,
}

/// Publishes the message on its persistent stream, done once the
/// server confirmed it within `deadline`.
async fn publish_and_confirm(
    streams: &jetstream::Context,
    deadline: Duration,
    publication: Publication,
) -> Result<(), BusError> {
    let Publication {
        subject,
        headers,
        payload,
    } = publication;
    let published = async {
        streams
            .publish_with_headers(subject, headers, payload.into())
            .await
            .map_err(unreachable_by)?
            .await
            .map_err(unreachable_by)
    };
    tokio::time::timeout(deadline, published)
        .await
        .map_err(|_| BusError::TimedOut)??;
    Ok(())
}

/// What `work` answers, held to `deadline`.
async fn in_time<T, E: Into<ClientError>>(
    deadline: Duration,
    work: impl IntoFuture<Output = Result<T, E>>,
) -> Result<T, BusError> {
    tokio::time::timeout(deadline, work.into_future())
        .await
        .map_err(|_| BusError::TimedOut)?
        .map_err(unreachable_by)
}

/// A message bus on a bus server, every name on it under one namespace.
#[derive(Clone)]
pub struct ServerBus {
    client: Client,
    events: jetstream::Context,
    namespace: Namespace,
    deadline: Duration,
}

impl std::fmt::Debug for ServerBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBus")
            .field("namespace", &self.namespace)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// How the platform signs in to the bus server.
///
/// `Debug` names the kind of sign-in and never the token.
#[derive(Clone)]
pub enum BusSignIn {
    /// The server takes anyone who reaches it.
    Open,
    /// A token the server was set up with.
    Token(Secret),
    /// A credentials file: the user's JWT and its key's seed.
    CredentialsFile(PathBuf),
}

impl std::fmt::Debug for BusSignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => f.write_str("BusSignIn::Open"),
            Self::Token(_) => f.write_str("BusSignIn::Token(redacted)"),
            Self::CredentialsFile(path) => f
                .debug_tuple("BusSignIn::CredentialsFile")
                .field(path)
                .finish(),
        }
    }
}

impl BusSignIn {
    /// The protocol client's options for this sign-in. A credentials file
    /// is read now.
    async fn options(&self) -> Result<ConnectOptions, BusError> {
        match self {
            Self::Open => Ok(ConnectOptions::new()),
            Self::Token(token) => Ok(ConnectOptions::with_token(token.expose().to_owned())),
            Self::CredentialsFile(path) => ConnectOptions::with_credentials_file(path.clone())
                .await
                .map_err(unreachable_by),
        }
    }
}

impl ServerBus {
    /// The bus on the server at `url`, taking anyone who reaches it, every
    /// name under `namespace`, its event stream made if it is not there yet
    /// and brought to the current retention if it is, each call held to
    /// `deadline`.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the server cannot be reached or the stream
    /// cannot be made or updated in time.
    pub async fn connect(
        url: &str,
        namespace: &Namespace,
        deadline: Duration,
    ) -> Result<Self, BusError> {
        Self::connect_as(url, &BusSignIn::Open, namespace, deadline).await
    }

    /// The bus on the server at `url`, signed in as `sign_in`, as
    /// [`connect`](Self::connect) makes it.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the credentials file cannot be read, the
    /// server cannot be reached or refuses the sign-in, or the stream
    /// cannot be made or updated in time.
    pub async fn connect_as(
        url: &str,
        sign_in: &BusSignIn,
        namespace: &Namespace,
        deadline: Duration,
    ) -> Result<Self, BusError> {
        let options = sign_in.options().await?;
        let client = in_time(deadline, options.connect(url)).await?;
        let events = jetstream::new(client.clone());
        in_time(
            deadline,
            events.create_or_update_stream(events_stream(namespace)),
        )
        .await?;
        Ok(Self {
            client,
            events,
            namespace: namespace.clone(),
            deadline,
        })
    }

    /// The stream every event of this bus is kept in, as the server has it.
    async fn stream_of_events(&self) -> Result<stream::Stream, BusError> {
        in_time(
            self.deadline,
            self.events.get_stream(self.namespace.stream(EVENTS)),
        )
        .await
    }
}

#[cfg(feature = "test-support")]
impl ServerBus {
    /// Hands every event of type `event_type` on the stream out once more,
    /// with its own seal and no id for the server to keep one copy by, as
    /// a delivery repeated past the duplicate window arrives. Says how
    /// many it handed out again.
    ///
    /// # Errors
    ///
    /// Returns [`BusError`] when the stream cannot be read or an event
    /// cannot be published in time.
    pub async fn deliver_again(&self, event_type: &str) -> Result<usize, BusError> {
        let events = self.stream_of_events().await?;
        let state = in_time(self.deadline, events.get_info()).await?.state;
        let suffix = format!(".{event_type}");
        let mut again = 0_usize;
        for sequence in state.first_sequence..=state.last_sequence {
            let Ok(stored) = events.get_raw_message(sequence).await else {
                continue;
            };
            if !stored.subject.as_str().ends_with(&suffix) {
                continue;
            }
            let mut headers = HeaderMap::new();
            if let Some(seal) = stored.headers.get(SEAL_HEADER) {
                headers.insert(SEAL_HEADER, seal.clone());
            }
            let publication = Publication {
                subject: stored.subject.to_string(),
                headers,
                payload: stored.payload.to_vec(),
            };
            publish_and_confirm(&self.events, self.deadline, publication).await?;
            again = again.saturating_add(1);
        }
        Ok(again)
    }
}

#[async_trait]
impl Bus for ServerBus {
    async fn publish(&self, event: &SealedEvent<'_>) -> Result<(), BusError> {
        let mut headers = HeaderMap::new();
        headers.insert(ID_HEADER, event.id);
        headers.insert(SEAL_HEADER, event.seal);
        publish_and_confirm(
            &self.events,
            self.deadline,
            Publication {
                subject: self.namespace.subject(event.subject),
                headers,
                payload: event.payload.to_vec(),
            },
        )
        .await
    }

    async fn broadcast(&self, subject: &str, payload: &[u8]) -> Result<(), BusError> {
        in_time(
            self.deadline,
            self.client
                .publish(self.namespace.subject(subject), payload.to_vec().into()),
        )
        .await
    }

    async fn listen(&self, subject: &str) -> Result<Box<dyn Listener>, BusError> {
        let subscriber = in_time(
            self.deadline,
            self.client.subscribe(self.namespace.subject(subject)),
        )
        .await?;
        Ok(Box::new(ServerListener { subscriber }))
    }

    async fn follow(&self) -> Result<Box<dyn EventFeed>, BusError> {
        let events = self.stream_of_events().await?;
        let config = OrderedConfig {
            deliver_subject: self.client.new_inbox(),
            deliver_policy: DeliverPolicy::New,
            ..OrderedConfig::default()
        };
        let consumer = in_time(self.deadline, events.create_consumer(config)).await?;
        let messages = in_time(self.deadline, consumer.messages()).await?;
        Ok(Box::new(ServerFeed {
            messages: Box::pin(messages),
            namespace: self.namespace.clone(),
        }))
    }

    async fn share(&self, share: &EventShare) -> Result<Box<dyn SharedFeed>, BusError> {
        let events = self.stream_of_events().await?;
        let config = pull::Config {
            durable_name: Some(share.name.clone()),
            filter_subjects: share
                .subjects
                .iter()
                .map(|subject| self.namespace.subject(subject))
                .collect(),
            deliver_policy: DeliverPolicy::New,
            ack_policy: AckPolicy::Explicit,
            ack_wait: share.ack_wait,
            max_deliver: i64::from(share.max_deliver),
            ..pull::Config::default()
        };
        let consumer = in_time(self.deadline, events.create_consumer(config)).await?;
        let messages = in_time(self.deadline, consumer.messages()).await?;
        Ok(Box::new(ServerShare {
            messages: Box::pin(messages),
            namespace: self.namespace.clone(),
            max_deliver: share.max_deliver,
            deadline: self.deadline,
        }))
    }

    async fn ping(&self) -> Result<(), BusError> {
        tokio::time::timeout(self.deadline, self.client.flush())
            .await
            .map_err(|_| BusError::TimedOut)?
            .map_err(|error| BusError::Unreachable(Box::new(error)))
    }
}

/// The broadcasts on one subject of the bus server.
struct ServerListener {
    subscriber: async_nats::Subscriber,
}

#[async_trait]
impl Listener for ServerListener {
    async fn next(&mut self) -> Option<Vec<u8>> {
        self.subscriber
            .next()
            .await
            .map(|message| message.payload.to_vec())
    }
}

/// The events one follower of the bus server hears, each subject read
/// under the follower's namespace.
struct ServerFeed {
    messages: Pin<Box<Ordered>>,
    namespace: Namespace,
}

#[async_trait]
impl EventFeed for ServerFeed {
    async fn next(&mut self) -> Option<Heard> {
        loop {
            let Ok(message) = self.messages.next().await? else {
                return Some(Heard::Missed);
            };
            if let Some(event) = heard_of(&message.message, &self.namespace) {
                return Some(Heard::Event(event));
            }
        }
    }
}

/// The events one reader of a share on the bus server is handed, each
/// subject read under the reader's namespace.
struct ServerShare {
    messages: Pin<Box<pull::Stream>>,
    namespace: Namespace,
    max_deliver: u32,
    deadline: Duration,
}

#[async_trait]
impl SharedFeed for ServerShare {
    async fn next(&mut self) -> Option<Handed> {
        loop {
            let Ok(message) = self.messages.next().await? else {
                continue;
            };
            let Ok(info) = message.info() else {
                continue;
            };
            let delivery = u32::try_from(info.delivered).unwrap_or(u32::MAX);
            let Some(event) = heard_of(&message.message, &self.namespace) else {
                continue;
            };
            let settle = ServerSettle {
                message,
                deadline: self.deadline,
            };
            return Some(Handed::new(
                event,
                delivery,
                self.max_deliver,
                Box::new(settle),
            ));
        }
    }
}

/// The event `message` carries, with the seal it came with, its subject
/// read under `namespace`. `None` for a subject outside it, which a stream
/// under the namespace never holds.
fn heard_of(message: &async_nats::Message, namespace: &Namespace) -> Option<HeardEvent> {
    let subject = namespace.relative(message.subject.as_str())?;
    let seal = message
        .headers
        .as_ref()
        .and_then(|headers| headers.get(SEAL_HEADER))
        .map(|seal| seal.as_str().to_owned());
    Some(HeardEvent {
        subject: subject.to_owned(),
        payload: message.payload.to_vec(),
        seal,
    })
}

/// Settles one event a reader of a share was handed, on the server.
struct ServerSettle {
    message: jetstream::Message,
    deadline: Duration,
}

#[async_trait]
impl Settle for ServerSettle {
    async fn settle(self: Box<Self>, settled: Settled) -> Result<(), BusError> {
        let kind = match settled {
            Settled::Done => AckKind::Ack,
            Settled::AgainAfter(wait) => AckKind::Nak(Some(wait)),
            Settled::SetAside => AckKind::Term,
        };
        in_time(self.deadline, self.message.ack_with(kind)).await
    }
}

#[cfg(test)]
mod tests {
    use async_nats::HeaderValue;

    use super::*;
    use crate::test_support::bus::{test_server, test_server_in};

    /// A namespace no other test uses: `t` and the random end of a fresh
    /// id.
    fn fresh_namespace() -> Namespace {
        let id = uuid::Uuid::now_v7().simple().to_string();
        Namespace::new(&format!("t{}", &id[20..])).unwrap()
    }

    /// An event published twice under one id is kept once by the server,
    /// in the stream and on the subject the default namespace has always
    /// named.
    #[tokio::test]
    async fn an_event_published_twice_is_kept_once() {
        let bus = test_server().await;
        let id = uuid::Uuid::now_v7().to_string();
        let subject = format!("platform.test.{}", uuid::Uuid::now_v7().simple());

        for payload in [b"first".as_slice(), b"again"] {
            let event = SealedEvent {
                subject: &subject,
                id: &id,
                payload,
                seal: "the-seal",
            };
            bus.publish(&event).await.unwrap();
        }

        let stream = bus.events.get_stream("ianua-events").await.unwrap();
        let first = stream
            .get_last_raw_message_by_subject(&format!("ianua.{subject}"))
            .await
            .unwrap();
        assert_eq!(first.payload.as_ref(), b"first");
        assert_eq!(
            first.headers.get(SEAL_HEADER).map(HeaderValue::as_str),
            Some("the-seal")
        );
    }

    /// Formatting token sign-in identifies its kind without exposing the token.
    #[test]
    fn a_token_sign_in_never_prints_its_token() {
        let sign_in = BusSignIn::Token(Secret::new("s3cr3t-bus-token"));

        let shown = format!("{sign_in:?}");

        assert!(!shown.contains("s3cr3t-bus-token"));
        assert!(shown.contains("Token"));
    }

    /// Missing credentials fail while constructing connection options with an unreachable error.
    #[tokio::test]
    async fn a_missing_credentials_file_is_refused() {
        let sign_in = BusSignIn::CredentialsFile(PathBuf::from("/nonexistent/ianua/bus.creds"));

        let options = sign_in.options().await;

        assert!(matches!(options, Err(BusError::Unreachable(_))));
    }

    /// A listener hears a broadcast on its subject.
    #[tokio::test]
    async fn a_listener_hears_a_broadcast() {
        let bus = test_server().await;
        let subject = format!("realtime.test.{}", uuid::Uuid::now_v7().simple());
        let mut listener = bus.listen(&subject).await.unwrap();

        bus.broadcast(&subject, b"hello").await.unwrap();

        let heard = tokio::time::timeout(Duration::from_secs(2), listener.next())
            .await
            .unwrap();
        assert_eq!(heard, Some(b"hello".to_vec()));
    }

    /// Reconnecting replaces an unbounded event stream's retention with the
    /// configured age and byte limits.
    #[tokio::test]
    async fn connecting_brings_the_event_stream_to_its_retention() {
        let bus = test_server().await;
        let unbounded = stream::Config {
            max_age: Duration::ZERO,
            max_bytes: -1,
            ..events_stream(&bus.namespace)
        };
        bus.events.update_stream(unbounded).await.unwrap();

        let again = test_server().await;

        let info = again
            .stream_of_events()
            .await
            .unwrap()
            .get_info()
            .await
            .unwrap();
        assert_eq!(info.config.max_age, EVENTS_KEPT);
        assert_eq!(info.config.max_bytes, EVENTS_MOST_BYTES);
    }

    /// A job keyed once holds its key while it is kept. An event stays on
    /// the bus for a consumer that was down to catch up from, so the job
    /// outlives every event that could be delivered again.
    #[test]
    fn an_ended_job_is_kept_longer_than_any_event_could_come_again() {
        let kept_days = ianua_app::use_cases::scheduling::ENDED_JOBS_KEPT_DAYS;
        let kept = Duration::from_secs(u64::from(kept_days) * 24 * 60 * 60);

        assert!(kept > EVENTS_KEPT);
    }

    /// A follower hears an event published after it began following, with
    /// its seal.
    #[tokio::test]
    async fn a_follower_hears_a_published_event() {
        let bus = test_server().await;
        let subject = format!("platform.test.{}", uuid::Uuid::now_v7().simple());
        let mut feed = bus.follow().await.unwrap();
        let event = SealedEvent {
            subject: &subject,
            id: &uuid::Uuid::now_v7().to_string(),
            payload: b"followed",
            seal: "the-seal",
        };
        bus.publish(&event).await.unwrap();

        let heard = loop {
            let next = tokio::time::timeout(Duration::from_secs(5), feed.next())
                .await
                .unwrap();
            match next {
                Some(Heard::Event(heard)) if heard.subject == subject => break heard,
                Some(_) => continue,
                None => panic!("the feed ended before the event came"),
            }
        };
        assert_eq!(heard.payload, b"followed");
        assert_eq!(heard.seal.as_deref(), Some("the-seal"));
    }

    /// A share of the events on its own subject, read under a fresh name.
    fn test_share(subject: &str) -> EventShare {
        EventShare {
            name: format!("test-{}", uuid::Uuid::now_v7().simple()),
            subjects: vec![subject.to_owned()],
            max_deliver: 3,
            ack_wait: Duration::from_secs(30),
        }
    }

    async fn publish_one(bus: &ServerBus, subject: &str, payload: &[u8]) {
        let event = SealedEvent {
            subject,
            id: &uuid::Uuid::now_v7().to_string(),
            payload,
            seal: "the-seal",
        };
        bus.publish(&event).await.unwrap();
    }

    async fn handed(feed: &mut Box<dyn SharedFeed>) -> Handed {
        tokio::time::timeout(Duration::from_secs(5), feed.next())
            .await
            .unwrap()
            .unwrap()
    }

    /// Two workers read one share: an event published once is handed to
    /// one of them, with its seal, and to neither again once it is done.
    #[tokio::test]
    async fn a_share_hands_an_event_to_one_reader() {
        let bus = test_server().await;
        let subject = format!("platform.test.{}", uuid::Uuid::now_v7().simple());
        let share = test_share(&subject);
        let mut first = bus.share(&share).await.unwrap();
        let mut second = bus.share(&share).await.unwrap();
        publish_one(&bus, &subject, b"shared").await;

        let got = tokio::select! {
            got = first.next() => got,
            got = second.next() => got,
        }
        .unwrap();
        let seal = got.event.seal.clone();
        got.acknowledge().await.unwrap();
        let again = tokio::time::timeout(Duration::from_millis(500), async {
            tokio::join!(first.next(), second.next())
        })
        .await;

        assert_eq!(seal.as_deref(), Some("the-seal"));
        assert!(again.is_err());
    }

    /// A requested retry delivers the same payload a second time with attempts remaining.
    #[tokio::test]
    async fn a_share_hands_an_event_failed_on_again() {
        let bus = test_server().await;
        let subject = format!("platform.test.{}", uuid::Uuid::now_v7().simple());
        let mut feed = bus.share(&test_share(&subject)).await.unwrap();
        publish_one(&bus, &subject, b"again").await;

        let first = handed(&mut feed).await;
        first.again_after(Duration::from_millis(100)).await.unwrap();
        let second = handed(&mut feed).await;

        assert_eq!(second.delivery, 2);
        assert_eq!(second.event.payload, b"again");
        assert!(!second.last);
    }

    /// Separate namespaces on one server keep each share's events distinct;
    /// a follower also receives only its namespace's payload and relative subject.
    #[tokio::test]
    async fn two_namespaces_never_hear_each_others_events() {
        let (ours, theirs) = (fresh_namespace(), fresh_namespace());
        let bus = test_server_in(&ours).await;
        let other = test_server_in(&theirs).await;
        let subject = format!(
            "tenant.{}.tenant.provisioned",
            uuid::Uuid::now_v7().simple()
        );
        let share = provisioning_share();
        let mut feed = bus.follow().await.unwrap();
        let mut shared = bus.share(&share).await.unwrap();
        let mut theirs_shared = other.share(&share).await.unwrap();
        publish_one(&other, &subject, b"theirs").await;
        publish_one(&bus, &subject, b"ours").await;

        let heard = tokio::time::timeout(Duration::from_secs(5), feed.next())
            .await
            .unwrap();
        let ours_handed = handed(&mut shared).await;
        let theirs_handed = handed(&mut theirs_shared).await;
        let more = tokio::time::timeout(Duration::from_millis(500), shared.next()).await;

        let Some(Heard::Event(heard)) = heard else {
            panic!("the follower heard no event");
        };
        assert_eq!((heard.subject, heard.payload), (subject, b"ours".to_vec()));
        assert_eq!(ours_handed.event.payload, b"ours");
        assert_eq!(theirs_handed.event.payload, b"theirs");
        assert!(more.is_err());
    }

    /// Uses the same durable name and tenant filter in both namespace-isolation fixtures.
    fn provisioning_share() -> EventShare {
        EventShare {
            name: "worker-provisioning".to_owned(),
            subjects: vec!["tenant.>".to_owned()],
            max_deliver: 3,
            ack_wait: Duration::from_secs(30),
        }
    }

    /// A listener skips another namespace's broadcast and receives its own.
    #[tokio::test]
    async fn two_namespaces_never_hear_each_others_broadcasts() {
        let bus = test_server_in(&fresh_namespace()).await;
        let other = test_server_in(&fresh_namespace()).await;
        let subject = "fleet.threats";
        let mut listener = bus.listen(subject).await.unwrap();

        other.broadcast(subject, b"theirs").await.unwrap();
        bus.broadcast(subject, b"ours").await.unwrap();

        let heard = tokio::time::timeout(Duration::from_secs(2), listener.next())
            .await
            .unwrap();
        assert_eq!(heard, Some(b"ours".to_vec()));
    }

    /// Each namespace keeps its events in a stream of its own, named after
    /// it and holding only its subjects.
    #[tokio::test]
    async fn a_namespace_keeps_its_events_in_its_own_stream() {
        let namespace = fresh_namespace();
        let bus = test_server_in(&namespace).await;

        let info = bus
            .stream_of_events()
            .await
            .unwrap()
            .get_info()
            .await
            .unwrap();

        assert_eq!(info.config.name, format!("{namespace}-events"));
        assert_eq!(
            info.config.subjects,
            [
                format!("{namespace}.tenant.>"),
                format!("{namespace}.org.>"),
                format!("{namespace}.platform.>"),
            ]
        );
    }
}
