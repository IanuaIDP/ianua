//! The live security dashboard's feed of the requests the gateway decided.
//!
//! Queued and published in batches like the request records: no task per
//! request, and a bus that is slow or gone costs entries on the feed, never
//! a request's time.

use std::sync::Arc;
use std::time::Duration;

use ianua_app::ports::realtime::{
    NotificationPublisher, PLATFORM_DASHBOARD_SUBJECT, ProxyAuditEntry, RealtimeMessage,
};
use ianua_app::ports::runtime::{DroppedRecords, RequestObserver};
use ianua_boot::shutdown::Shutdown;
use ianua_domain::domains::proxy::observation::RequestObservation;

use crate::observability::batching::{BatchLimits, Batched, Deliver, Queueing};

/// The longest publishing one batch may take; what is left of it then is
/// dropped.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// Publishes each finished request to the platform dashboard's live feed.
pub(crate) struct DashboardFeed {
    queue: Batched<ProxyAuditEntry>,
}

impl DashboardFeed {
    /// Starts publishing through `publisher` until `shutdown` stops,
    /// counting what the queue drops into `dropped`.
    #[must_use]
    pub(crate) fn start(
        publisher: Arc<dyn NotificationPublisher>,
        dropped: Arc<dyn DroppedRecords>,
        shutdown: &Shutdown,
    ) -> Self {
        let feed = Feed {
            publisher,
            timeout: PUBLISH_TIMEOUT,
        };
        let queueing = Queueing::new(BatchLimits::DEFAULT, dropped);
        Self {
            queue: Batched::start(feed, queueing, shutdown),
        }
    }
}

impl RequestObserver for DashboardFeed {
    fn observe(&self, observation: &RequestObservation) {
        self.queue.record(ProxyAuditEntry::from(observation));
    }
}

/// The bus the dashboard listens on, and how long a batch may take there.
struct Feed {
    publisher: Arc<dyn NotificationPublisher>,
    timeout: Duration,
}

impl Feed {
    /// Publishes every entry of `batch`, stopping at the first the bus
    /// refuses, since the rest would most likely be refused too; how many
    /// were not published when it stopped.
    async fn publish(&self, batch: Vec<ProxyAuditEntry>) -> Result<(), usize> {
        let total = batch.len();
        for (sent, entry) in batch.into_iter().enumerate() {
            let message = RealtimeMessage::ProxyAudit(entry);
            if let Err(error) = self
                .publisher
                .publish_dashboard(PLATFORM_DASHBOARD_SUBJECT, &message)
                .await
            {
                tracing::debug!(%error, "a dashboard entry was not published");
                return Err(total - sent);
            }
        }
        Ok(())
    }
}

impl Deliver<ProxyAuditEntry> for Feed {
    async fn deliver(&self, batch: Vec<ProxyAuditEntry>) {
        let entries = batch.len();
        match tokio::time::timeout(self.timeout, self.publish(batch)).await {
            Ok(Ok(())) => {}
            Ok(Err(lost)) => tracing::warn!(lost, "dashboard entries not published"),
            Err(_) => tracing::warn!(entries, "dashboard entries not published in time"),
        }
    }

    fn name(&self) -> &'static str {
        "dashboard feed"
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_app::test_support::request_observation;
    use ianua_domain::domains::proxy::observation::RequestOutcome;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{OperatorId, OrgUserId, OrganizationId, TenantId, UserId};

    use super::*;

    /// A bus that takes every message and never answers.
    struct Hung;

    #[async_trait]
    impl NotificationPublisher for Hung {
        async fn publish_to_operator(
            &self,
            _: &OperatorId,
            _: &RealtimeMessage,
        ) -> Result<(), DomainError> {
            std::future::pending().await
        }

        async fn publish_to_org_user(
            &self,
            _: &OrganizationId,
            _: &OrgUserId,
            _: &RealtimeMessage,
        ) -> Result<(), DomainError> {
            std::future::pending().await
        }

        async fn publish_to_tenant_user(
            &self,
            _: &TenantId,
            _: &UserId,
            _: &RealtimeMessage,
        ) -> Result<(), DomainError> {
            std::future::pending().await
        }

        async fn publish_dashboard(&self, _: &str, _: &RealtimeMessage) -> Result<(), DomainError> {
            std::future::pending().await
        }
    }

    /// Delivery to a publisher that never answers returns within the outer
    /// deadline because the batch has its own timeout.
    #[tokio::test]
    async fn a_hung_bus_is_given_up_after_the_timeout() {
        let timeout = Duration::from_millis(50);
        let feed = Feed {
            publisher: Arc::new(Hung),
            timeout,
        };
        let entry = ProxyAuditEntry::from(&request_observation(RequestOutcome::Undecided));

        let delivered = tokio::time::timeout(timeout * 20, feed.deliver(vec![entry])).await;

        assert!(delivered.is_ok(), "the delivery outlived its timeout");
    }
}
