//! Post a notification to one of an organization's destinations outside
//! the app, a Slack or Teams channel or a webhook, as the worker runs a
//! queued post.
//!
//! The destination is read again when the post runs: one deleted since is
//! not posted to, nor one paused or whose filter no longer covers the
//! notification. A post the destination does not take fails, so the queue
//! tries it again; one whose address no longer reaches a public host is
//! given up on at once, since trying again changes nothing.

use std::sync::Arc;

use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::NotificationDestinationId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::notifications::{
    DestinationPoster, NotificationDestinationStore, destination_endpoint_place,
};
use crate::use_case::Command;
use crate::use_cases::notifications::delivery::job::DestinationPost;

/// The ports [`PostUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct PostPorts {
    /// The organization's destinations, read again for each post.
    pub destinations: Arc<dyn NotificationDestinationStore>,
    /// Posts to a destination, with a timeout and its address checked
    /// again.
    pub poster: Arc<dyn DestinationPoster>,
}

/// How one queued post came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posted {
    /// The destination took it.
    Delivered,
    /// Nothing was posted: the destination is gone, paused, or no longer
    /// takes the notification.
    Skipped,
    /// The destination's address no longer reaches a public host, so the
    /// post is given up on.
    Unreachable,
}

/// Posts one queued notification to one destination.
///
/// No one calls it: the worker runs it for a queued post, so its caller is
/// `()`.
pub struct PostUseCase {
    ports: PostPorts,
}

impl PostUseCase {
    /// A use case posting through `ports`.
    #[must_use]
    pub fn new(ports: PostPorts) -> Self {
        Self { ports }
    }
}

impl Command for PostUseCase {
    type Caller = ();
    type Input = DestinationPost;
    type Output = Result<Posted, AppError>;

    /// Posts `post`'s notification to its destination, when the
    /// destination is still there, active and covering it. Records
    /// nothing: telling a channel is not a change anyone made.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the destination cannot be read, the
    ///   carried notification is broken, or the destination does not take
    ///   the post in time; the queue tries it again.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        post: DestinationPost,
    ) -> Result<Posted, AppError> {
        let notification = post.notification.notification()?;
        let Some(destination) = self
            .ports
            .destinations
            .find(&post.organization_id, &post.destination_id)
            .await
            .or_internal()?
        else {
            return Ok(Posted::Skipped);
        };
        if !destination.receives(notification.category(), notification.severity()) {
            return Ok(Posted::Skipped);
        }
        let sealed_for = destination_endpoint_place(&post.organization_id, destination.id());
        let sent = self
            .ports
            .poster
            .post(destination.endpoint(), &sealed_for, &notification)
            .await;
        posted(sent, destination.id())
    }
}

/// What the post to the destination `id` came to: delivered, given up on
/// an address that no longer reaches a public host, or failed for the
/// queue to try again.
fn posted(
    sent: Result<(), DomainError>,
    id: &NotificationDestinationId,
) -> Result<Posted, AppError> {
    match sent {
        Ok(()) => Ok(Posted::Delivered),
        Err(DomainError::Validation(_)) => {
            tracing::warn!(
                destination_id = %id,
                "destination post given up: its address no longer reaches a public host"
            );
            Ok(Posted::Unreachable)
        }
        Err(other) => Err(AppError::from_domain(other)),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::destination::DestinationState;
    use ianua_domain::domains::notifications::notification::{
        AboutResource, CreateNotificationParams, Notification,
    };
    use ianua_domain::domains::notifications::reach::ToldAs;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::types::{
        EventType, Label, NotificationDestinationId, NotificationId, OrganizationId,
    };

    use super::*;
    use crate::test_support::notification_delivery::{
        FakeDestinationPoster, FakeDestinationStore, destination_in_state, webhook_destination,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::notifications::delivery::job::PostedNotification;

    /// A topic paused in Acme, as the app tells it.
    fn topic_paused() -> PostedNotification {
        PostedNotification::of(&Notification::create(CreateNotificationParams {
            id: NotificationId::new(),
            event_type: EventType::parse("tenant.provisioned").unwrap(),
            severity: NotificationSeverity::Info,
            title: Label::new("title", "Tenant provisioned").unwrap(),
            body: None,
            resource_id: AboutResource::Nothing,
            told_as: ToldAs::Overseer,
        }))
    }

    fn run(
        destinations: FakeDestinationStore,
        poster: Arc<FakeDestinationPoster>,
        post: DestinationPost,
    ) -> Result<Posted, AppError> {
        let use_case = PostUseCase::new(PostPorts {
            destinations: Arc::new(destinations),
            poster,
        });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(&(), &auditor, post))
    }

    /// The post of a paused topic to `destination_id` of `organization_id`.
    fn to(
        organization_id: OrganizationId,
        destination_id: NotificationDestinationId,
    ) -> DestinationPost {
        DestinationPost {
            organization_id,
            destination_id,
            notification: topic_paused(),
        }
    }

    /// Acme's on-call webhook takes everything. Its queued post goes out.
    #[test]
    fn a_queued_post_reaches_its_destination() {
        let acme = OrganizationId::new();
        let hook = webhook_destination(acme, NotificationSeverity::Info);
        let post = to(acme, *hook.id());
        let poster = Arc::new(FakeDestinationPoster::posting());

        let posted = run(FakeDestinationStore::holding([hook]), poster.clone(), post);

        assert_eq!(posted.unwrap(), Posted::Delivered);
        assert_eq!(poster.posted(), 1);
    }

    /// Acme paused its webhook after the post was queued. The post is
    /// skipped, not sent.
    #[test]
    fn a_destination_paused_since_is_not_posted_to() {
        let acme = OrganizationId::new();
        let hook = destination_in_state(acme, NotificationSeverity::Info, DestinationState::Paused);
        let post = to(acme, *hook.id());
        let poster = Arc::new(FakeDestinationPoster::posting());

        let posted = run(FakeDestinationStore::holding([hook]), poster.clone(), post);

        assert_eq!(posted.unwrap(), Posted::Skipped);
        assert_eq!(poster.posted(), 0);
    }

    /// A post naming a destination from another organization is skipped
    /// without sending a notification.
    #[test]
    fn a_post_under_another_organization_finds_nothing() {
        let hook = webhook_destination(OrganizationId::new(), NotificationSeverity::Info);
        let post = to(OrganizationId::new(), *hook.id());
        let poster = Arc::new(FakeDestinationPoster::posting());

        let posted = run(FakeDestinationStore::holding([hook]), poster.clone(), post);

        assert_eq!(posted.unwrap(), Posted::Skipped);
        assert_eq!(poster.posted(), 0);
    }

    /// Acme's webhook is down. The post fails, so the queue tries it
    /// again.
    #[test]
    fn a_destination_that_refuses_fails_the_post_for_a_retry() {
        let acme = OrganizationId::new();
        let hook = webhook_destination(acme, NotificationSeverity::Info);
        let post = to(acme, *hook.id());

        let posted = run(
            FakeDestinationStore::holding([hook]),
            Arc::new(FakeDestinationPoster::refusing()),
            post,
        );

        assert!(posted.is_err());
    }
}
