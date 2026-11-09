//! Starting workflows on what a service sends: registering a workflow's
//! trigger at the service, keeping it registered, removing it, and reading
//! what the service delivers once its signature checks out.
//!
//! The platform makes each registration's secret and its own address,
//! keeps the registrations, and remembers which deliveries started a run.
//! An integration only talks to its service and reads what it sent.
//!
//! Most services take one registration per workflow, and need only
//! [`Events::register`], [`Events::renew`], [`Events::unregister`] and
//! [`Events::read`]. The rest of the trait is for those that do not:
//!
//! - A service that checks the address, or hands over a secret, answers
//!   through [`Events::greet`].
//! - A service with one address per account says so in
//!   [`Events::account_setup`], and its registration is made once, through
//!   [`Events::open_channel`], [`Events::renew_channel`] and
//!   [`Events::close_channel`], if the platform makes it at all.
//! - A service whose deliveries only announce a change says so in
//!   [`Events::pulls_history`], and reads what changed in [`Events::pull`].

use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::domains::workflows::triggers::EventFilter;
use ianua_domain::shared::security::secret::Secret;
use time::OffsetDateTime;

use crate::Renewed;

/// The account's credential while one registration is made, renewed or
/// removed. A service whose grants rotate hands back a new one on a call;
/// the next call of the same registration uses it, and the platform keeps
/// it once the registration is done. It also holds the secret a service
/// shows only once in its answer, until the platform has sealed it.
pub struct HeldCredential {
    current: Mutex<Secret>,
    renewed: Mutex<bool>,
    given: Mutex<Option<Secret>>,
}

impl HeldCredential {
    /// `credential` as the account holds it.
    #[must_use]
    pub fn new(credential: Secret) -> Self {
        Self {
            current: Mutex::new(credential),
            renewed: Mutex::new(false),
            given: Mutex::new(None),
        }
    }

    /// Keeps `secret`, which the service chose and showed once in its
    /// answer to a registration, as the one its deliveries are proven with.
    /// Stripe's webhook endpoint secret is one.
    pub fn keep_given_secret(&self, secret: Secret) {
        *self.given.lock().unwrap_or_else(PoisonError::into_inner) = Some(secret);
    }

    /// The secret the service showed once, if it did.
    #[must_use]
    pub fn given_secret(&self) -> Option<Secret> {
        self.given
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The credential to call with now.
    #[must_use]
    pub fn current(&self) -> Secret {
        self.current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Keeps `renewed`, which the service issued in the credential's place.
    pub fn replace(&self, renewed: Secret) {
        *self.current.lock().unwrap_or_else(PoisonError::into_inner) = renewed;
        *self.renewed.lock().unwrap_or_else(PoisonError::into_inner) = true;
    }

    /// The credential to keep from now on, once the registration is done.
    #[must_use]
    pub fn into_renewed(self) -> Renewed {
        let renewed = self
            .renewed
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        let current = self
            .current
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        match renewed {
            true => Renewed::To(current),
            false => Renewed::Unchanged,
        }
    }
}

/// One workflow's trigger, as its service is asked to send it.
#[derive(Clone, Copy)]
pub struct Watch<'a> {
    /// The event the trigger starts on.
    pub event: &'a ServiceEventKey,
    /// The filters the trigger set, such as the repository.
    pub filters: &'a [EventFilter],
    /// The platform's address for this registration, where the service
    /// sends what it sends.
    pub address: &'a str,
    /// The registration's secret, which the service signs with.
    pub secret: &'a Secret,
    /// The service's name for the registration, once it took it.
    pub remote: Option<&'a str>,
}

impl<'a> Watch<'a> {
    /// The value the trigger set for the filter `name`, if it set one.
    #[must_use]
    pub fn filter(&self, name: &str) -> Option<&'a str> {
        self.filters
            .iter()
            .find(|filter| filter.name().as_str() == name)
            .map(|filter| filter.value().as_str())
    }
}

/// What a service answered a registration with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watching {
    /// Its name for the registration, such as a webhook's id.
    pub remote: String,
    /// When it lapses unless renewed; `None` for one that does not.
    pub lapses: Option<OffsetDateTime>,
    /// The key its events name it by when every event of the deployment's
    /// app reaches one address, such as a Slack workspace's id; `None` when
    /// they reach the registration's own address.
    pub routed_by: Option<String>,
}

/// Why a registration could not be made, renewed or removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchFailure {
    /// The service refused it, for this reason in the integration's words.
    Refused(String),
    /// The service could not be reached or was busy.
    Unreachable,
}

/// One request a service sent, as it arrived.
#[derive(Clone, Copy)]
pub struct Delivery<'a> {
    /// The full address it was sent to, as the service signed it.
    pub address: &'a str,
    /// Its headers, names in lowercase.
    pub headers: &'a [(String, String)],
    /// Its body, as sent.
    pub body: &'a [u8],
}

impl Delivery<'_> {
    /// The value of the header `name`, written in lowercase, if it was sent
    /// once.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let mut sent = self
            .headers
            .iter()
            .filter(|(header, _)| header == name)
            .map(|(_, value)| value.as_str());
        let first = sent.next()?;
        match sent.next() {
            Some(_) => None,
            None => Some(first),
        }
    }
}

/// What a delivery says, once its signature was checked.
#[derive(Debug, Clone, PartialEq)]
pub enum Read {
    /// The signature did not check out; nothing else of it was read.
    Forged,
    /// It is the trigger's event and passes its filters.
    Start {
        /// The service's id for the delivery, which a resent one keeps.
        delivery: String,
        /// The event's values, as the workflow receives them.
        input: FlowData,
        /// The most sensitive data in them.
        exposure: DataClassLevel,
    },
    /// It asks the platform to prove it holds the address; this is the
    /// answer.
    Answer(Vec<u8>),
    /// Something else, signed, that starts nothing: a ping, another event,
    /// or one the filters leave out.
    Skip,
}

/// Where a delivery to the one address of the deployment's app goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRoute {
    /// To the registrations its events name by this key.
    Keyed(String),
    /// The app answers with this body, as Slack asks it to prove it holds
    /// the address.
    Answer(Vec<u8>),
    /// Nowhere: unsigned, or signed with anything but the app's secret.
    Refused,
}

/// How an integration's one channel per account gets ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSetup {
    /// The platform registers it with a call to [`Events::open_channel`],
    /// as Telegram's `setWebhook` and Gmail's `users.watch` are.
    Registered,
    /// A person gives the service the address and pastes the service's key
    /// into the platform, as HubSpot's app secret and a shared secret in a
    /// Salesforce callout are.
    PastedKey,
    /// The service sends a token to the address, which [`Events::greet`]
    /// hands over, and a person pastes it back at the service, as Notion
    /// asks.
    TokenFromService,
}

/// What a request to an address is, before it is read as a delivery.
#[derive(Debug)]
pub enum Greeting {
    /// An ordinary delivery.
    NotOne,
    /// The service asks the platform to prove it holds the address.
    Prove(CheckReply),
    /// The service hands over the secret its deliveries will be proven
    /// with. It is kept only while the address is waiting for one, and the
    /// answer is sent only then.
    HandsSecret {
        /// What the service handed over, in the clear; sealed before it is
        /// kept.
        secret: Secret,
        /// What the service is answered.
        reply: CheckReply,
    },
}

/// What the platform answers a check that it holds an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReply {
    /// The body answered with.
    pub body: CheckBody,
    /// A header answered with, as Asana asks its `X-Hook-Secret` echoed.
    pub header: Option<(&'static str, String)>,
}

/// The body of an answer to a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckBody {
    /// None: answered `204`.
    Empty,
    /// These bytes as plain text: answered `200`, as Microsoft Graph asks
    /// its `validationToken` returned.
    PlainText(Vec<u8>),
}

/// An account's channel, as its service is asked about it.
#[derive(Clone, Copy)]
pub struct ChannelWatch<'a> {
    /// The platform's address for the channel.
    pub address: &'a str,
    /// The channel's secret, which proves what the service sends.
    pub secret: &'a Secret,
    /// The service's name for the registration, once it took it.
    pub remote: Option<&'a str>,
    /// Where the service's history was last read up to.
    pub cursor: Option<&'a str>,
}

/// What a service answered about an account's channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelWatching {
    /// Its name for the registration.
    pub remote: String,
    /// When it lapses unless renewed; `None` for one that does not.
    pub lapses: Option<OffsetDateTime>,
    /// Where its history can be read from, for a service that has one.
    pub cursor: Option<String>,
}

/// The most events one [`Events::pull`] may hand back. A service with more
/// hands back this many and the cursor where it stopped; the rest come
/// with its next delivery.
pub const MOST_PULLED: usize = 100;

/// What a delivery that only announced a change came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pulled {
    /// It did not prove it came from the service.
    Forged,
    /// These events, each read through [`Events::read`] as if delivered,
    /// and where the history was read up to.
    Fetched {
        /// Each event's body, at most [`MOST_PULLED`].
        deliveries: Vec<Vec<u8>>,
        /// The cursor to keep once they all started.
        cursor: String,
    },
}

/// Starting workflows on one integration's service's events.
///
/// Every call to the service follows no redirect and is held to a time
/// limit. `read` and `route` check the signature before anything else is
/// read, comparing in constant time.
#[async_trait]
pub trait Events: Send + Sync {
    /// Registers `watch` at the service through `credential`, which keeps
    /// a credential the service replaced on the way.
    async fn register(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure>;

    /// Renews `watch`, registered under `watch.remote`, before it lapses.
    /// A service whose registrations never lapse answers as it stands.
    async fn renew(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure>;

    /// Removes `watch` from the service. One the service no longer knows
    /// counts as removed.
    async fn unregister(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<(), WatchFailure>;

    /// What `delivery`, sent for `watch` and signed with its secret, says.
    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read;

    /// Where a delivery to the one address of the deployment's app goes,
    /// checked with the app's own secret. Only a service that sends every
    /// event there, such as Slack, routes any.
    fn route(&self, _delivery: Delivery<'_>) -> AppRoute {
        AppRoute::Refused
    }

    /// What `delivery` is, before it is read: for a service that checks the
    /// address or hands over a secret there. It runs before any proof, so
    /// it must trust nothing it is sent beyond what the platform lets a
    /// greeting do.
    fn greet(&self, _delivery: Delivery<'_>) -> Greeting {
        Greeting::NotOne
    }

    /// How this service's one channel per account gets ready; `None` for a
    /// service with one registration per workflow.
    fn account_setup(&self) -> Option<AccountSetup> {
        None
    }

    /// Registers `watch`, the account's channel. Called again when it
    /// lapsed, so it must take the same channel twice.
    async fn open_channel(
        &self,
        _credential: &HeldCredential,
        _watch: ChannelWatch<'_>,
    ) -> Result<ChannelWatching, WatchFailure> {
        Err(no_channels())
    }

    /// Renews `watch` before it lapses.
    async fn renew_channel(
        &self,
        _credential: &HeldCredential,
        _watch: ChannelWatch<'_>,
    ) -> Result<ChannelWatching, WatchFailure> {
        Err(no_channels())
    }

    /// Takes `watch` off the service. One it no longer knows counts as
    /// taken off.
    async fn close_channel(
        &self,
        _credential: &HeldCredential,
        _watch: ChannelWatch<'_>,
    ) -> Result<(), WatchFailure> {
        Err(no_channels())
    }

    /// Whether this service's deliveries only announce a change, so what
    /// changed is read through [`Events::pull`].
    fn pulls_history(&self) -> bool {
        false
    }

    /// Proves `delivery` and reads what it announced, past `watch.cursor`.
    /// Called only for a service whose [`Events::pulls_history`] is true.
    async fn pull(
        &self,
        _credential: &HeldCredential,
        _watch: ChannelWatch<'_>,
        _delivery: Delivery<'_>,
    ) -> Result<Pulled, WatchFailure> {
        Ok(Pulled::Forged)
    }
}

/// The refusal of a service with no channels asked about one.
fn no_channels() -> WatchFailure {
    WatchFailure::Refused("this service has no channel per account".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Plain;

    #[async_trait]
    impl Events for Plain {
        async fn register(
            &self,
            _credential: &HeldCredential,
            _watch: Watch<'_>,
        ) -> Result<Watching, WatchFailure> {
            Err(WatchFailure::Unreachable)
        }

        async fn renew(
            &self,
            _credential: &HeldCredential,
            _watch: Watch<'_>,
        ) -> Result<Watching, WatchFailure> {
            Err(WatchFailure::Unreachable)
        }

        async fn unregister(
            &self,
            _credential: &HeldCredential,
            _watch: Watch<'_>,
        ) -> Result<(), WatchFailure> {
            Ok(())
        }

        fn read(&self, _watch: Watch<'_>, _delivery: Delivery<'_>) -> Read {
            Read::Forged
        }
    }

    fn delivery() -> Delivery<'static> {
        Delivery {
            address: "https://ianua.test/events/one",
            headers: &[],
            body: b"{}",
        }
    }

    fn channel(secret: &Secret) -> ChannelWatch<'_> {
        ChannelWatch {
            address: "https://ianua.test/events/channels/one",
            secret,
            remote: None,
            cursor: None,
        }
    }

    /// A service that says nothing of channels or checks has none: a
    /// request is an ordinary delivery, it pulls nothing, and asking it
    /// for a channel is refused.
    #[tokio::test]
    async fn a_service_that_declares_nothing_offers_nothing() {
        let secret = Secret::new("the secret words".to_owned());
        let held = HeldCredential::new(Secret::new("token".to_owned()));

        let opened = Plain.open_channel(&held, channel(&secret)).await;
        let pulled = Plain.pull(&held, channel(&secret), delivery()).await;

        assert!(matches!(Plain.greet(delivery()), Greeting::NotOne));
        assert_eq!(Plain.account_setup(), None);
        assert!(!Plain.pulls_history());
        assert!(matches!(opened, Err(WatchFailure::Refused(_))));
        assert_eq!(pulled, Ok(Pulled::Forged));
    }

    /// Stripe shows its webhook's secret once, in its answer. The held
    /// credential keeps it for the platform to seal, and leaves the
    /// account's credential as it was.
    #[test]
    fn a_secret_shown_once_is_held_beside_the_credential() {
        let held = HeldCredential::new(Secret::new("token".to_owned()));

        held.keep_given_secret(Secret::new("whsec words".to_owned()));

        assert_eq!(held.given_secret().unwrap().expose(), "whsec words");
        assert_eq!(held.current().expose(), "token");
        assert!(matches!(held.into_renewed(), Renewed::Unchanged));
    }
}
