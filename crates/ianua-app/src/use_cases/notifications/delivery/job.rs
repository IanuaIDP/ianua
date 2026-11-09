//! The job that posts one notification to one destination, as the queue
//! carries it, and the handler the worker runs it with.
//!
//! The fan-out queues one job per destination instead of posting inline, so
//! a slow Slack or a webhook that times out holds up neither the event
//! pipeline nor the other destinations, and a post that fails is tried
//! again on the queue's backoff.

use std::num::NonZeroU32;

use async_trait::async_trait;
use ianua_domain::domains::notifications::notification::{
    AboutResource, Notification, NotificationRow, ReadState, title_label,
};
use ianua_domain::domains::notifications::reach::NotificationReach;
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::domains::scheduling::job::ScheduledJob;
use ianua_domain::domains::scheduling::job_key::JobKey;
use ianua_domain::domains::scheduling::job_type::JobType;
use ianua_domain::shared::clock;
use ianua_domain::types::{
    EventType, NotificationDestinationId, NotificationId, OrganizationId, Text,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command as _;
use crate::use_cases::notifications::delivery::post::PostUseCase;
use crate::use_cases::scheduling::{Handled, JobHandler};

/// The job type that posts a notification to a destination.
pub const DESTINATION_POST_JOB: &str = "notifications.destination_post";

/// How many times the worker tries a post before it gives up on it.
pub(crate) const DESTINATION_POST_ATTEMPTS: NonZeroU32 = NonZeroU32::MIN.saturating_add(4);

/// What a destination post carries: which destination of which
/// organization, and the notification it is told.
///
/// The one definition of the payload, so the side that queues the job and
/// the worker that runs it cannot disagree on a field name. It carries no
/// address: the worker reads the destination again, so one deleted, paused
/// or filtering it out since is not posted to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DestinationPost {
    /// The organization the destination belongs to.
    pub organization_id: OrganizationId,
    /// The destination posted to.
    pub destination_id: NotificationDestinationId,
    /// The notification it is told.
    pub notification: PostedNotification,
}

/// A notification as a destination post carries it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PostedNotification {
    /// The notification's id.
    pub id: NotificationId,
    /// The event it is about, by name.
    pub event_type: String,
    /// How urgent it is.
    pub severity: NotificationSeverity,
    /// The heading displayed to the recipient.
    pub title: String,
    /// Its text, if it has any.
    pub body: Option<String>,
    /// The record it is about, if any.
    pub resource_id: Option<Uuid>,
    /// When it was made, in seconds since the epoch.
    pub created_at: i64,
}

impl PostedNotification {
    /// `notification`, as a post carries it.
    #[must_use]
    pub fn of(notification: &Notification) -> Self {
        Self {
            id: notification.id(),
            event_type: notification.event_type().as_str().to_owned(),
            severity: notification.severity(),
            title: notification.title().as_str().to_owned(),
            body: notification.body().map(|body| body.as_str().to_owned()),
            resource_id: notification.resource_id().into(),
            created_at: notification.created_at().unix_timestamp(),
        }
    }

    /// The notification this carries, checked again as storage would be.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when a field is not a notification's.
    pub fn notification(&self) -> Result<Notification, AppError> {
        let event_type = EventType::parse(&self.event_type)
            .ok_or_else(|| AppError::internal_msg("a posted notification names no known event"))?;
        let body = self
            .body
            .as_deref()
            .map(|body| Text::new("body", body))
            .transpose()
            .or_internal()?;
        Notification::reconstitute(NotificationRow {
            id: self.id,
            event_type,
            severity: self.severity,
            title: title_label(self.title.as_str()).or_internal()?,
            body,
            resource_id: AboutResource::from_stored(self.resource_id),
            reach: NotificationReach::ByRights,
            read: ReadState::Unread,
            created_at: OffsetDateTime::from_unix_timestamp(self.created_at).or_internal()?,
        })
        .or_internal()
    }
}

impl DestinationPost {
    /// The job that makes this post, due now, keyed once by the notification
    /// and the destination so the same post is queued once, even after it
    /// went out.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the job cannot be built.
    pub fn scheduled(&self) -> Result<ScheduledJob, AppError> {
        let job_type = JobType::new(DESTINATION_POST_JOB).or_internal()?;
        let key = JobKey::of(self.notification.id, self.destination_id).or_internal()?;
        let payload = serde_json::to_string(self).map_err(AppError::internal)?;
        Ok(
            ScheduledJob::new(job_type, payload, clock::now(), DESTINATION_POST_ATTEMPTS)
                .keyed_once(key),
        )
    }

    /// The post `job` carries.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the payload is not a destination
    /// post's.
    pub fn read(job: &ScheduledJob) -> Result<Self, AppError> {
        serde_json::from_str(job.payload()).map_err(AppError::internal)
    }
}

/// Runs destination post jobs through [`PostUseCase`].
pub struct PostHandler {
    job_type: JobType,
    posting: PostUseCase,
}

impl PostHandler {
    /// A handler posting through `posting`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the job type is not a valid name.
    pub fn new(posting: PostUseCase) -> Result<Self, AppError> {
        Ok(Self {
            job_type: JobType::new(DESTINATION_POST_JOB).or_internal()?,
            posting,
        })
    }
}

#[async_trait]
impl JobHandler for PostHandler {
    fn job_type(&self) -> &JobType {
        &self.job_type
    }

    async fn handle(
        &self,
        job: &ScheduledJob,
        auditor: &RequestAuditor,
    ) -> Result<Handled, AppError> {
        let post = DestinationPost::read(job)?;
        self.posting.execute(&(), auditor, post).await?;
        Ok(Handled::Done)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::notification::CreateNotificationParams;
    use ianua_domain::domains::notifications::reach::ToldAs;
    use ianua_domain::types::Label;

    use super::*;

    fn post() -> DestinationPost {
        let notification = Notification::create(CreateNotificationParams {
            id: NotificationId::new(),
            event_type: EventType::parse("tenant.provisioned").unwrap(),
            severity: NotificationSeverity::Warning,
            title: Label::new("title", "Tenant provisioned").unwrap(),
            body: Some(Text::new("body", "Ann provisioned the tenant Acme.").unwrap()),
            resource_id: AboutResource::Resource(Uuid::now_v7()),
            told_as: ToldAs::Overseer,
        });
        DestinationPost {
            organization_id: OrganizationId::new(),
            destination_id: NotificationDestinationId::new(),
            notification: PostedNotification::of(&notification),
        }
    }

    /// A post to Acme's webhook reads back from its job as the same
    /// destination and notification it was queued with.
    #[test]
    fn a_scheduled_post_reads_back_as_the_same_payload() {
        let sent = post();

        let scheduled = sent.scheduled().unwrap();

        assert_eq!(scheduled.job_type().as_str(), DESTINATION_POST_JOB);
        assert_eq!(DestinationPost::read(&scheduled).unwrap(), sent);
    }

    /// The notification a post carries comes back with its title, text and
    /// urgency, so the destination is told what the app shows.
    #[test]
    fn a_posted_notification_comes_back_as_it_was() {
        let sent = post();

        let notification = sent.notification.notification().unwrap();

        assert_eq!(notification.id(), sent.notification.id);
        assert_eq!(notification.title().as_str(), "Tenant provisioned");
        assert_eq!(notification.severity(), NotificationSeverity::Warning);
        assert_eq!(
            notification.body().map(Text::as_str),
            Some("Ann provisioned the tenant Acme.")
        );
    }

    /// Reconstructing a posted notification with an unknown event name
    /// returns an internal error.
    #[test]
    fn a_post_naming_no_known_event_is_refused() {
        let mut sent = post();
        sent.notification.event_type = "nothing.ever".to_owned();

        let read = sent.notification.notification();

        assert!(matches!(read, Err(AppError::Internal(_))));
    }
}
