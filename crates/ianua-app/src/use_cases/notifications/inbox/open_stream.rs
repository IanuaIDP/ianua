//! Open notification stream: the live feed of the caller's own
//! notifications, as the dashboard's WebSocket shows them.
//!
//! The stored listing hides the notifications a tenant user may not see,
//! and the live feed must hide them too: each update reaches a tenant user
//! only when what they hold lets them see its category, or when it is about
//! their own account's safety, which shows whatever they hold. An update
//! that is no notification at all never reaches them.
//!
//! A stream stays open long after it opened, and the user's rights can be
//! taken away meanwhile. So the stream is asked again from time to time
//! through its [`StreamNarrowing`]: what it shows narrows to what the user
//! may still see, and it closes once they may no longer read their inbox.
//! It never widens; the dashboard connects again to see more after a new
//! role.

use std::sync::{Arc, RwLock};

use ianua_domain::domains::authorization::permission::SystemPermission;

use crate::error::{AppError, OrInternal};
use crate::ports::realtime::{NotificationReceiver, NotificationSubscriber, RealtimeMessage};
use crate::use_case::Query;
use crate::use_cases::notifications::inbox::reader::{Inbox, NotificationReader, ReaderPorts};

/// The ports [`OpenStreamUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OpenStreamPorts {
    /// Opens a live subscription to one inbox.
    pub subscriber: Arc<dyn NotificationSubscriber>,
    /// Whose inbox the caller reads.
    pub readers: ReaderPorts,
}

/// What a stream lets through.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Visibility {
    /// Everything sent to the inbox: an operator's or a member's own.
    Everything,
    /// Notifications whose category needs one of these, and those about the
    /// reader's own account, which show whatever they hold.
    Holding(Vec<SystemPermission>),
    /// Nothing: the reader may no longer read the inbox at all.
    Nothing,
}

impl Visibility {
    /// What is left of this once the reader may see only `now`: never more
    /// than before.
    fn narrowed_to(&self, now: Self) -> Self {
        match (self, now) {
            (Self::Nothing, _) | (_, Self::Nothing) => Self::Nothing,
            (Self::Everything, now) => now,
            (Self::Holding(was), Self::Everything) => Self::Holding(was.clone()),
            (Self::Holding(was), Self::Holding(now)) => Self::Holding(
                was.iter()
                    .copied()
                    .filter(|permission| now.contains(permission))
                    .collect(),
            ),
        }
    }

    /// Whether this lets nothing through any more. A reader holding no
    /// right is still told about their own account, so only a reader who
    /// may no longer read the inbox is spent.
    fn is_spent(&self) -> bool {
        matches!(self, Self::Nothing)
    }

    /// Whether `message` gets through.
    fn lets_through(&self, message: &RealtimeMessage) -> bool {
        let held = match self {
            Self::Everything => return true,
            Self::Nothing => return false,
            Self::Holding(held) => held,
        };
        let RealtimeMessage::Notification(update) = message else {
            return false;
        };
        update
            .reach
            .shows(update.category.required_permission(), held)
    }
}

/// Whether a stream may go on after it was asked again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamStanding {
    /// The reader may still read it; it shows what they may still see.
    Open,
    /// The reader may no longer read it, or may see nothing it carries.
    Closed,
}

/// The live feed of one reader's notifications, filtered to what they may
/// see. It holds the subscription; dropping it closes it.
pub struct NotificationStream {
    receiver: Box<dyn NotificationReceiver>,
    visibility: Arc<RwLock<Visibility>>,
    readers: ReaderPorts,
}

impl NotificationStream {
    /// The next update the reader may see, or `None` once the subscription
    /// ends. Updates they may not see are dropped on the way.
    pub async fn next_update(&mut self) -> Option<RealtimeMessage> {
        loop {
            let message = self.receiver.recv().await?;
            if self.shows(&message) {
                return Some(message);
            }
        }
    }

    /// What asks this stream's reader again, and narrows what it shows to
    /// their answer, while the stream is being read.
    #[must_use]
    pub fn narrowing(&self) -> StreamNarrowing {
        StreamNarrowing {
            visibility: Arc::clone(&self.visibility),
            readers: self.readers.clone(),
        }
    }

    /// Whether the reader may see `message`. A visibility that cannot be
    /// read shows nothing.
    fn shows(&self, message: &RealtimeMessage) -> bool {
        let Ok(visibility) = self.visibility.read() else {
            return false;
        };
        visibility.lets_through(message)
    }
}

/// Asks a stream's reader again what they may still see, and narrows the
/// stream to it.
pub struct StreamNarrowing {
    visibility: Arc<RwLock<Visibility>>,
    readers: ReaderPorts,
}

impl StreamNarrowing {
    /// Asks again for `reader`, whose stream this is. What the stream shows
    /// narrows to the categories they may still see, besides what happens
    /// to their own account; it is closed when their session or key no
    /// longer counts. A closed stream shows nothing from then on.
    pub async fn recheck(&self, reader: &NotificationReader) -> StreamStanding {
        let now = match self.readers.inbox(reader).await {
            Ok(inbox) => visibility(inbox),
            Err(_) => Visibility::Nothing,
        };
        let Ok(mut current) = self.visibility.write() else {
            return StreamStanding::Closed;
        };
        *current = current.narrowed_to(now);
        if current.is_spent() {
            return StreamStanding::Closed;
        }
        StreamStanding::Open
    }
}

/// Opens the caller's live notification feed.
pub struct OpenStreamUseCase {
    ports: OpenStreamPorts,
}

impl OpenStreamUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OpenStreamPorts) -> Self {
        Self { ports }
    }

    /// A live subscription to `inbox`.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the subscription cannot be opened.
    async fn receiver(&self, inbox: &Inbox) -> Result<Box<dyn NotificationReceiver>, AppError> {
        let subscriber = self.ports.subscriber.as_ref();
        let opened = match inbox {
            Inbox::Operator(operator_id) => subscriber.subscribe_operator(operator_id).await,
            Inbox::Member {
                organization_id,
                org_user_id,
            } => {
                subscriber
                    .subscribe_org_user(organization_id, org_user_id)
                    .await
            }
            Inbox::TenantUser {
                tenant, user_id, ..
            } => subscriber.subscribe_tenant_user(tenant, user_id).await,
        };
        opened.or_internal()
    }
}

impl Query for OpenStreamUseCase {
    type Caller = NotificationReader;
    type Input = ();
    type Output = Result<NotificationStream, AppError>;

    /// The live feed of `reader`'s own notifications. A tenant user's shows
    /// only notifications what they hold when it opens lets them see, and
    /// narrows to what they still hold each time its
    /// [`NotificationStream::narrowing`] asks again; the socket is opened
    /// again to see more after a new role.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not act where they ask,
    ///   or is an organization member acting in a tenant, whose
    ///   notifications are in the organization.
    /// - `AppError::Internal` when the subscription cannot be opened.
    async fn execute(
        &self,
        reader: &NotificationReader,
        (): (),
    ) -> Result<NotificationStream, AppError> {
        let inbox = self.ports.readers.inbox(reader).await?;
        let receiver = self.receiver(&inbox).await?;
        Ok(NotificationStream {
            receiver,
            visibility: Arc::new(RwLock::new(visibility(inbox))),
            readers: self.ports.readers.clone(),
        })
    }
}

/// What a stream to `inbox` lets through: everything sent to an operator or
/// a member, and to a tenant user only what they hold now lets them see.
fn visibility(inbox: Inbox) -> Visibility {
    match inbox {
        Inbox::Operator(_) | Inbox::Member { .. } => Visibility::Everything,
        Inbox::TenantUser { visible, .. } => Visibility::Holding(visible),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ianua_domain::domains::authorization::permission::UserAction;
    use ianua_domain::domains::notifications::reach::NotificationReach;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{OperatorId, OrgUserId, OrganizationId, TenantId, UserId};

    use super::*;
    use crate::ports::realtime::NotificationUpdate;
    use crate::test_support::acting::{ChangingTenantAuthorities, FakeTenantAuthorities, Refusal};
    use crate::test_support::notifications::{
        key_rotated, own_account_locked, someone_elses_account_locked, user_registered,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Hands every subscription the same messages, in order.
    struct Scripted(Mutex<Vec<RealtimeMessage>>);

    /// Yields its messages, then ends.
    struct Replay(Vec<RealtimeMessage>);

    #[async_trait]
    impl NotificationReceiver for Replay {
        async fn recv(&mut self) -> Option<RealtimeMessage> {
            (!self.0.is_empty()).then(|| self.0.remove(0))
        }
    }

    impl Scripted {
        /// A receiver yielding the scripted messages.
        fn replay(&self) -> Box<dyn NotificationReceiver> {
            Box::new(Replay(self.0.lock().unwrap().clone()))
        }
    }

    #[async_trait]
    impl NotificationSubscriber for Scripted {
        async fn subscribe_operator(
            &self,
            _: &OperatorId,
        ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
            Ok(self.replay())
        }

        async fn subscribe_org_user(
            &self,
            _: &OrganizationId,
            _: &OrgUserId,
        ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
            Ok(self.replay())
        }

        async fn subscribe_tenant_user(
            &self,
            _: &TenantId,
            _: &UserId,
        ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
            Ok(self.replay())
        }

        async fn subscribe_dashboard(
            &self,
            _: &str,
        ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
            Ok(self.replay())
        }
    }

    /// Everything a tenant user's stream shows, opened with `authorities`,
    /// when a user registration and a key rotation are sent.
    fn shown(authorities: FakeTenantAuthorities) -> Result<Vec<RealtimeMessage>, AppError> {
        let sent = [user_registered(NotificationSeverity::Info), key_rotated()]
            .iter()
            .map(|notification| {
                RealtimeMessage::Notification(NotificationUpdate::from(notification))
            })
            .collect();
        let uc = OpenStreamUseCase::new(OpenStreamPorts {
            subscriber: Arc::new(Scripted(Mutex::new(sent))),
            readers: ReaderPorts {
                tenant_authorities: Arc::new(authorities),
                ..ReaderPorts::fakes()
            },
        });
        let mut stream = block_on(uc.execute(&NotificationReader::Tenant(test_ctx()), ()))?;
        let mut seen = Vec::new();
        while let Some(message) = block_on(stream.next_update()) {
            seen.push(message);
        }
        Ok(seen)
    }

    /// Ann may view users but not keys. Her live feed shows the new user
    /// and not the rotated key.
    #[test]
    fn a_tenant_user_sees_only_what_they_may_see() {
        let seen = shown(FakeTenantAuthorities::holding(&[SystemPermission::Users(
            UserAction::View,
        )]))
        .unwrap();

        assert_eq!(seen.len(), 1);
    }

    /// A tenant user without permissions receives neither user registration
    /// nor key rotation notifications from the live feed.
    #[test]
    fn a_tenant_user_holding_nothing_sees_nothing() {
        let seen = shown(FakeTenantAuthorities::holding(&[])).unwrap();

        assert!(seen.is_empty());
    }

    /// Opening the live feed with a signed-out session returns an
    /// unauthenticated error.
    #[test]
    fn a_signed_out_caller_gets_no_feed() {
        let result = shown(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// The permission a key rotation's category needs.
    fn key_permission() -> SystemPermission {
        NotificationUpdate::from(&key_rotated())
            .category
            .required_permission()
    }

    /// A tenant user's stream over a user registration and a key rotation,
    /// opened while `authorities` answers as it does now.
    fn opened(authorities: &Arc<ChangingTenantAuthorities>) -> NotificationStream {
        let sent = [user_registered(NotificationSeverity::Info), key_rotated()]
            .iter()
            .map(|notification| {
                RealtimeMessage::Notification(NotificationUpdate::from(notification))
            })
            .collect();
        let uc = OpenStreamUseCase::new(OpenStreamPorts {
            subscriber: Arc::new(Scripted(Mutex::new(sent))),
            readers: ReaderPorts {
                tenant_authorities: authorities.clone(),
                ..ReaderPorts::fakes()
            },
        });
        block_on(uc.execute(&NotificationReader::Tenant(test_ctx()), ())).unwrap()
    }

    /// Whether `stream` goes on once its reader is asked again.
    fn rechecked(stream: &NotificationStream) -> StreamStanding {
        let reader = NotificationReader::Tenant(test_ctx());
        block_on(stream.narrowing().recheck(&reader))
    }

    /// Everything `stream` still shows.
    fn drained(mut stream: NotificationStream) -> Vec<RealtimeMessage> {
        let mut seen = Vec::new();
        while let Some(message) = block_on(stream.next_update()) {
            seen.push(message);
        }
        seen
    }

    /// Rechecking after user viewing rights are lost keeps the feed open
    /// for key rotations and excludes the user registration.
    #[test]
    fn a_right_lost_mid_stream_stops_that_category() {
        let authorities = Arc::new(ChangingTenantAuthorities::starting(
            FakeTenantAuthorities::holding_everything(),
        ));
        let stream = opened(&authorities);
        authorities.change_to(FakeTenantAuthorities::holding(&[key_permission()]));

        let standing = rechecked(&stream);

        assert_eq!(standing, StreamStanding::Open);
        let seen = drained(stream);
        assert_eq!(seen.len(), 1);
        assert!(matches!(
            &seen[0],
            RealtimeMessage::Notification(update)
                if update.category.required_permission() == key_permission()
        ));
    }

    /// A right granted while the stream is open does not widen it: the
    /// dashboard connects again to see more.
    #[test]
    fn a_right_gained_mid_stream_does_not_widen_it() {
        let authorities = Arc::new(ChangingTenantAuthorities::starting(
            FakeTenantAuthorities::holding(&[key_permission()]),
        ));
        let stream = opened(&authorities);
        authorities.change_to(FakeTenantAuthorities::holding_everything());

        let standing = rechecked(&stream);

        assert_eq!(standing, StreamStanding::Open);
        assert_eq!(drained(stream).len(), 1);
    }

    /// Rechecking after all permissions are lost keeps the feed open but
    /// excludes its queued user registration and key rotation notifications.
    #[test]
    fn a_stream_with_no_right_left_shows_nothing_of_others() {
        let authorities = Arc::new(ChangingTenantAuthorities::starting(
            FakeTenantAuthorities::holding_everything(),
        ));
        let stream = opened(&authorities);
        authorities.change_to(FakeTenantAuthorities::holding(&[]));

        let standing = rechecked(&stream);

        assert_eq!(standing, StreamStanding::Open);
        assert!(drained(stream).is_empty());
    }

    /// Carol holds no right at all and has her feed open when an admin
    /// resets her factors. The notice about her own account reaches her
    /// live; the notice of another account's lock does not.
    #[test]
    fn a_plain_user_sees_their_own_account_notices_live() {
        let sent = [own_account_locked(), someone_elses_account_locked()]
            .iter()
            .map(|notification| {
                RealtimeMessage::Notification(NotificationUpdate::from(notification))
            })
            .collect();
        let uc = OpenStreamUseCase::new(OpenStreamPorts {
            subscriber: Arc::new(Scripted(Mutex::new(sent))),
            readers: ReaderPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
                ..ReaderPorts::fakes()
            },
        });
        let stream = block_on(uc.execute(&NotificationReader::Tenant(test_ctx()), ())).unwrap();

        let seen = drained(stream);

        assert_eq!(seen.len(), 1);
        assert!(matches!(
            &seen[0],
            RealtimeMessage::Notification(update) if update.reach == NotificationReach::OwnAccount
        ));
    }

    /// Rechecking after the session ends closes the feed and excludes its
    /// queued notifications.
    #[test]
    fn a_stream_whose_session_ended_closes() {
        let authorities = Arc::new(ChangingTenantAuthorities::starting(
            FakeTenantAuthorities::holding_everything(),
        ));
        let stream = opened(&authorities);
        authorities.change_to(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let standing = rechecked(&stream);

        assert_eq!(standing, StreamStanding::Closed);
        assert!(drained(stream).is_empty());
    }
}
