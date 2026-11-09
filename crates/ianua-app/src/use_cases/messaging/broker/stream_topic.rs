//! Stream topic: watch a topic's messages live, as they are published.
//!
//! Every message published to a topic is broadcast on the topic's live
//! subject, payload and all. Watching that subject hands the caller the
//! same messages pulling from a subscription would, so it takes what
//! pulling takes: the right to consume, and clearance for the topic's
//! class. A stream stays open long after it was admitted, and the class
//! can be raised or the session ended meanwhile, so the stream asks again
//! before it passes on each message, and closes on the first refusal.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;

use crate::acting::{ConsumerAuthorities, TenantAuthorities};
use crate::error::AppError;
use crate::ports::messaging::TopicStore;
use crate::use_case::Query;
use crate::use_cases::messaging::bus::live_subject;
use crate::use_cases::messaging::caller::{MessagingActor, MessagingCaller};
use crate::use_cases::messaging::lookup::existing_named_topic;

/// Which topic to watch.
pub struct StreamTopicRequest {
    /// The broker destination whose new publications the caller wants to watch.
    pub topic_name: TopicName,
}

/// A topic the caller may watch now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicStream {
    subject: String,
}

impl TopicStream {
    /// The subject the topic's messages are broadcast on, to subscribe to.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

/// The ports [`StreamTopicUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StreamTopicPorts {
    /// The topics, whose state and class are checked now.
    pub topic_store: Arc<dyn TopicStore>,
    /// What a person holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// What a consumer's roles give it, once it signed in.
    pub consumers: Arc<dyn ConsumerAuthorities>,
}

/// Admits a caller to a topic's live messages.
pub struct StreamTopicUseCase {
    ports: StreamTopicPorts,
}

impl StreamTopicUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: StreamTopicPorts) -> Self {
        Self { ports }
    }
}

impl Query for StreamTopicUseCase {
    type Caller = MessagingCaller;
    type Input = StreamTopicRequest;
    type Output = Result<TopicStream, AppError>;

    /// The live subject of `request.topic_name`, once the caller may read
    /// what is published there.
    ///
    /// The stream calls this before it subscribes, and again before it
    /// passes on each message: a refusal at any point closes it, so a
    /// raised class, a paused topic or a session that stopped counting
    /// ends the stream at the next message.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session, key or consumer
    ///   credential no longer counts.
    /// - `AppError::Forbidden` when the person, or the consumer's roles, may
    ///   not consume, the topic is not active, or its class is above the
    ///   caller's clearance.
    /// - `AppError::NotFound` if the topic doesn't exist.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &MessagingCaller,
        request: StreamTopicRequest,
    ) -> Result<TopicStream, AppError> {
        let tenant = caller.tenant();
        let actor = MessagingActor::of(
            caller,
            self.ports.tenant_authorities.as_ref(),
            self.ports.consumers.as_ref(),
        )
        .await?;
        actor.ensure_holds(SystemPermission::Messaging(MessagingAction::Consume))?;
        let topic = existing_named_topic(
            self.ports.topic_store.as_ref(),
            &tenant,
            &request.topic_name,
        )
        .await?;
        ensure_flowing(&topic)?;
        actor.reading(|reader| topic.ensure_readable_by(reader))?;
        Ok(TopicStream {
            subject: live_subject(&tenant, topic.topic_name()),
        })
    }
}

/// Refuses watching a topic that takes no messages now: a paused or
/// archived one.
///
/// # Errors
///
/// `AppError::Forbidden` unless the topic is active.
fn ensure_flowing(topic: &Topic<ResolvedTenant>) -> Result<(), AppError> {
    if topic.is_active() {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "messaging-cannot-stream-from-an-inactive-topic",
        "cannot stream from an inactive topic"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::DataAccessAction;
    use ianua_domain::domains::data_classification::level::DataClassLevel;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::consumers::{billing_sync, key_caller, sign_in_of, test_key_digest};
    use crate::test_support::messaging::{
        FakeTopicStore, messaging_admin, topic_classed, topic_named, topics_of_test_tenant,
    };
    use crate::test_support::{block_on, test_ctx};

    const CONSUME: SystemPermission = SystemPermission::Messaging(MessagingAction::Consume);

    fn watch(
        topics: Arc<FakeTopicStore>,
        people: FakeTenantAuthorities,
        caller: &MessagingCaller,
        name: &str,
    ) -> Result<TopicStream, AppError> {
        let use_case = StreamTopicUseCase::new(StreamTopicPorts {
            topic_store: topics,
            tenant_authorities: Arc::new(people),
            consumers: sign_in_of(billing_sync(), &[CONSUME]),
        });
        let request = StreamTopicRequest {
            topic_name: TopicName::new(name).unwrap(),
        };
        block_on(use_case.execute(caller, request))
    }

    fn person() -> MessagingCaller {
        MessagingCaller::Person(test_ctx())
    }

    fn orders() -> Arc<FakeTopicStore> {
        topics_of_test_tenant(topic_named("orders.created"))
    }

    /// Ann may consume and watches `orders.created`. She is given its live
    /// subject, under her tenant.
    #[test]
    fn a_person_who_may_consume_watches_a_topic() {
        let stream = watch(
            orders(),
            FakeTenantAuthorities::holding(&[CONSUME]),
            &person(),
            "orders.created",
        )
        .unwrap();

        let tenant = test_ctx().tenant_id().as_uuid().as_simple().to_string();
        assert_eq!(
            stream.subject(),
            format!("ianua.msg.{tenant}.orders.created")
        );
    }

    /// "billing-sync" may consume and watches the topic with its own key.
    #[test]
    fn a_consumer_that_may_consume_watches_a_topic() {
        let caller = MessagingCaller::Consumer(key_caller(test_key_digest()));

        let stream = watch(
            orders(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &caller,
            "orders.created",
        );

        assert!(stream.is_ok());
    }

    /// Messaging-view permission alone cannot admit a person to a topic stream.
    #[test]
    fn a_person_who_may_only_view_is_refused() {
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::View)]);

        let result = watch(orders(), viewer, &person(), "orders.created");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A confidential topic refuses a person with internal clearance but
    /// admits one with consume permission and confidential clearance.
    #[test]
    fn a_person_watches_only_within_their_clearance() {
        let salaries =
            || topics_of_test_tenant(topic_classed("salaries.paid", DataClassLevel::Confidential));
        let fay = FakeTenantAuthorities::holding(&[
            CONSUME,
            SystemPermission::Data(DataAccessAction::Confidential),
        ]);

        let by_sam = watch(
            salaries(),
            FakeTenantAuthorities::holding(&[CONSUME]),
            &person(),
            "salaries.paid",
        );
        let by_fay = watch(salaries(), fay, &person(), "salaries.paid");

        assert!(matches!(by_sam, Err(AppError::Forbidden(_))));
        assert!(by_fay.is_ok());
    }

    /// Once a topic is raised to restricted, a stream admission request
    /// from a person with only consume permission is forbidden.
    #[test]
    fn a_topic_raised_above_the_watchers_clearance_is_refused_from_then_on() {
        let mut payroll = topic_named("payroll.events");
        payroll
            .raise_data_class(DataClassLevel::Restricted, &messaging_admin())
            .unwrap();

        let result = watch(
            topics_of_test_tenant(payroll),
            FakeTenantAuthorities::holding(&[CONSUME]),
            &person(),
            "payroll.events",
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A paused topic refuses stream admission even to a fully authorized person.
    #[test]
    fn a_paused_topic_is_not_watched() {
        let mut topic = topic_named("orders.created");
        topic.pause(&messaging_admin()).unwrap();

        let result = watch(
            topics_of_test_tenant(topic),
            FakeTenantAuthorities::holding_everything(),
            &person(),
            "orders.created",
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out person receives unauthenticated when requesting a topic stream.
    #[test]
    fn a_signed_out_person_is_refused() {
        let result = watch(
            orders(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &person(),
            "orders.created",
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A topic the tenant does not have is not found.
    #[test]
    fn an_unknown_topic_is_not_found() {
        let result = watch(
            orders(),
            FakeTenantAuthorities::holding_everything(),
            &person(),
            "orders.deleted",
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
