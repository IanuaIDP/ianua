//! Fakes for the realtime ports: a publisher that sends nowhere and a subscriber that hears nothing.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OperatorId, OrgUserId, OrganizationId, TenantId, UserId};

use crate::ports::realtime::{
    NotificationPublisher, NotificationReceiver, NotificationSubscriber, RealtimeMessage,
};
use crate::test_support::Fake;

/// Broadcaster that discards every message, with subscriptions that never
/// receive one.
pub struct NoopBroadcaster;

struct NoopReceiver;

#[async_trait]
impl NotificationReceiver for NoopReceiver {
    async fn recv(&mut self) -> Option<RealtimeMessage> {
        std::future::pending().await
    }
}

#[async_trait]
impl NotificationPublisher for NoopBroadcaster {
    async fn publish_to_operator(
        &self,
        _: &OperatorId,
        _: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn publish_to_org_user(
        &self,
        _: &OrganizationId,
        _: &OrgUserId,
        _: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn publish_to_tenant_user(
        &self,
        _: &TenantId,
        _: &UserId,
        _: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn publish_dashboard(&self, _: &str, _: &RealtimeMessage) -> Result<(), DomainError> {
        Ok(())
    }
}

#[async_trait]
impl NotificationSubscriber for NoopBroadcaster {
    async fn subscribe_operator(
        &self,
        _: &OperatorId,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
        Ok(Box::new(NoopReceiver))
    }

    async fn subscribe_org_user(
        &self,
        _: &OrganizationId,
        _: &OrgUserId,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
        Ok(Box::new(NoopReceiver))
    }

    async fn subscribe_tenant_user(
        &self,
        _: &TenantId,
        _: &UserId,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
        Ok(Box::new(NoopReceiver))
    }

    async fn subscribe_dashboard(
        &self,
        _: &str,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
        Ok(Box::new(NoopReceiver))
    }
}

/// Publisher keeping the dashboard subjects it was asked to push on, in
/// order.
#[derive(Default)]
pub struct RecordingPublisher {
    subjects: std::sync::Mutex<Vec<String>>,
}

impl RecordingPublisher {
    /// The subjects pushed on so far.
    ///
    /// # Panics
    ///
    /// Panics if the lock was poisoned.
    #[must_use]
    pub fn subjects(&self) -> Vec<String> {
        self.subjects.lock().expect("a held list").clone()
    }
}

#[async_trait]
impl NotificationPublisher for RecordingPublisher {
    async fn publish_to_operator(
        &self,
        _: &OperatorId,
        _: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn publish_to_org_user(
        &self,
        _: &OrganizationId,
        _: &OrgUserId,
        _: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn publish_to_tenant_user(
        &self,
        _: &TenantId,
        _: &UserId,
        _: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn publish_dashboard(
        &self,
        subject: &str,
        _: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        self.subjects
            .lock()
            .expect("a held list")
            .push(subject.to_owned());
        Ok(())
    }
}

impl Fake for Arc<dyn NotificationPublisher> {
    fn fake() -> Self {
        Arc::new(NoopBroadcaster)
    }
}

impl Fake for Arc<dyn NotificationSubscriber> {
    fn fake() -> Self {
        Arc::new(NoopBroadcaster)
    }
}
