//! A tenant's setup, step by step, as a live update for whoever watches it
//! come up.
//!
//! Each step that ends is broadcast twice: on the tenant's own setup
//! subject, for the page of that one tenant, and on its organization's, for
//! the list of every tenant. Both are dashboard subjects, so the update
//! travels as every other live update does. Nothing is kept: the setup
//! itself holds how far it got, so an update nobody hears is lost on
//! purpose, and one that cannot be sent is logged and dropped.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::provisioning::{SetupProgress, SetupProgressObserver};
use ianua_app::ports::realtime::{
    NotificationPublisher as _, RealtimeMessage, org_setup_subject, setup_subject,
};

use crate::bus::realtime::BusNotificationPublisher;
use crate::bus::stream::Bus;
use crate::crypto::BroadcastSeal;

/// Setup progress broadcast on the bus.
pub struct BusSetupProgressObserver {
    publisher: BusNotificationPublisher,
}

impl BusSetupProgressObserver {
    /// An observer broadcasting on `bus`, sealing every update with
    /// `seal`, the control plane's: setup progress is never the gateway's
    /// to send.
    #[must_use]
    pub fn new(bus: Arc<dyn Bus>, seal: BroadcastSeal) -> Self {
        Self {
            publisher: BusNotificationPublisher::new(bus, seal),
        }
    }

    /// Broadcasts `message` on `subject`, logging a failure instead of
    /// handing it back.
    async fn announce(&self, subject: &str, message: &RealtimeMessage) {
        let Err(error) = self.publisher.publish_dashboard(subject, message).await else {
            return;
        };
        tracing::warn!(%error, "a setup progress update could not be broadcast");
    }
}

#[async_trait]
impl SetupProgressObserver for BusSetupProgressObserver {
    async fn on_progress(&self, progress: &SetupProgress) {
        let message = RealtimeMessage::SetupProgress(progress.clone());
        let tenant = setup_subject(&progress.organization_id, &progress.tenant_id);
        let organization = org_setup_subject(&progress.organization_id);
        self.announce(&tenant, &message).await;
        self.announce(&organization, &message).await;
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::provisioning::StepOutcome;
    use ianua_app::ports::realtime::NotificationSubscriber as _;
    use ianua_domain::domains::tenant::setup::SetupStep;
    use ianua_domain::shared::model::steps::RunOutcome;
    use ianua_domain::types::{OrganizationId, TenantId};
    use uuid::Uuid;

    use super::*;
    use crate::bus::{BusNotificationSubscriber, MemoryBus};
    use crate::crypto::BroadcastCheck;
    use crate::crypto::keys::tests::test_root;

    /// An observer on `bus` sealing as the control plane, and a subscriber
    /// checking its seals.
    fn watching(bus: Arc<MemoryBus>) -> (BusSetupProgressObserver, BusNotificationSubscriber) {
        let observer = BusSetupProgressObserver::new(
            Arc::clone(&bus) as Arc<dyn Bus>,
            BroadcastSeal::control_plane(&test_root()),
        );
        let check = BroadcastCheck::new(
            BroadcastSeal::control_plane(&test_root()),
            BroadcastSeal::data_plane(&test_root()),
        );
        (observer, BusNotificationSubscriber::new(bus, check))
    }

    fn progress() -> SetupProgress {
        SetupProgress {
            tenant_id: TenantId::from_uuid(Uuid::now_v7()),
            organization_id: OrganizationId::from_uuid(Uuid::now_v7()),
            step: SetupStep::Database,
            step_outcome: StepOutcome::Done,
            done_steps: 1,
            total_steps: 4,
            setup: RunOutcome::Running,
            failure_reason: None,
        }
    }

    fn the_same(sent: &SetupProgress, heard: &RealtimeMessage) -> bool {
        format!("{:?}", RealtimeMessage::SetupProgress(sent.clone())) == format!("{heard:?}")
    }

    /// A step that ended reaches the page watching that one tenant.
    #[tokio::test]
    async fn a_step_reaches_the_tenants_own_subject() {
        let bus = Arc::new(MemoryBus::new(16));
        let (observer, subscriber) = watching(bus);
        let sent = progress();
        let mut receiver = subscriber
            .subscribe_dashboard(&setup_subject(&sent.organization_id, &sent.tenant_id))
            .await
            .unwrap();

        observer.on_progress(&sent).await;

        assert!(the_same(&sent, &receiver.recv().await.unwrap()));
    }

    /// A step that ended reaches the list of every tenant of the
    /// organization, on one subject.
    #[tokio::test]
    async fn a_step_reaches_the_organizations_subject() {
        let bus = Arc::new(MemoryBus::new(16));
        let (observer, subscriber) = watching(bus);
        let sent = progress();
        let mut receiver = subscriber
            .subscribe_dashboard(&org_setup_subject(&sent.organization_id))
            .await
            .unwrap();

        observer.on_progress(&sent).await;

        assert!(the_same(&sent, &receiver.recv().await.unwrap()));
    }

    /// A subscriber receives its organization's setup update after an update
    /// for another organization is sent, without receiving the other update.
    #[tokio::test]
    async fn a_step_never_reaches_another_organization() {
        let bus = Arc::new(MemoryBus::new(16));
        let (observer, subscriber) = watching(bus);
        let theirs = progress();
        let ours = progress();
        let mut receiver = subscriber
            .subscribe_dashboard(&org_setup_subject(&ours.organization_id))
            .await
            .unwrap();

        observer.on_progress(&theirs).await;
        observer.on_progress(&ours).await;

        assert!(the_same(&ours, &receiver.recv().await.unwrap()));
    }
}
