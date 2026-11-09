//! Live updates over the bus: what one node publishes for an operator, a
//! member, a tenant's user or a dashboard reaches the sockets open on every
//! node.
//!
//! Each recipient listens on a subject of its own under `realtime.`, so
//! live updates never mix with the events stream; a bus server puts it
//! under the deployment's namespace, as `ianua.realtime.` by default. A dashboard subject is
//! taken only when it names one exact subject: an empty segment, a space
//! or a wildcard is refused, so a subscriber never listens to more than it
//! asked for.
//!
//! Every update travels sealed by its publisher, as `<seal>.<update>`,
//! the seal over the subject and the update. A listener hands on only an
//! update whose seal holds: the control plane's for any update, the data
//! plane's only for a request the gateway decided. An update that carries
//! no seal, one whose seal does not hold, one the data plane may not send,
//! and one that does not read back are dropped, and the receiver waits for
//! the next one.

mod wire;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::realtime::{
    NotificationPublisher, NotificationReceiver, NotificationSubscriber, RealtimeMessage,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{OperatorId, OrgUserId, OrganizationId, TenantId, UserId};

use self::wire::Wire;
use crate::bus::stream::{Bus, Listener};
use crate::crypto::{BroadcastCheck, BroadcastSeal, Vouched};

/// What stands between an update's seal and the update in a broadcast.
const SEAL_END: u8 = b'.';

fn operator_subject(operator_id: &OperatorId) -> String {
    format!("realtime.operator.{}", operator_id.as_uuid().simple())
}

fn member_subject(organization_id: &OrganizationId, org_user_id: &OrgUserId) -> String {
    format!(
        "realtime.org.{}.{}",
        organization_id.as_uuid().simple(),
        org_user_id.as_uuid().simple()
    )
}

fn tenant_user_subject(tenant_id: &TenantId, user_id: &UserId) -> String {
    format!(
        "realtime.tenant.{}.{}",
        tenant_id.as_uuid().simple(),
        user_id.as_uuid().simple()
    )
}

/// The bus subject a dashboard subject travels on, refused when it would
/// name more than one subject.
fn dashboard_subject(subject: &str) -> Result<String, DomainError> {
    let exact = subject.split('.').all(|segment| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|c| c.is_ascii_graphic() && c != '*' && c != '>')
    });
    match exact {
        true => Ok(format!("realtime.dashboard.{subject}")),
        false => Err(DomainError::invalid(message!(
            "infra-a-dashboard-subject-names-one-exact",
            "a dashboard subject names one exact subject"
        ))),
    }
}

/// `update`, broadcast on `subject`, behind `seal`'s seal on it.
fn sealed(seal: &BroadcastSeal, subject: &str, update: &[u8]) -> Vec<u8> {
    let mut framed = seal.seal(subject, update).into_bytes();
    framed.push(SEAL_END);
    framed.extend_from_slice(update);
    framed
}

/// The seal and the update `payload` carries, or `None` when it carries
/// no seal.
fn unsealed(payload: &[u8]) -> Option<(&str, &[u8])> {
    let end = payload.iter().position(|byte| *byte == SEAL_END)?;
    let (seal, rest) = payload.split_at(end);
    Some((std::str::from_utf8(seal).ok()?, rest.get(1..)?))
}

/// Live updates published on a bus, each sealed by this publisher.
pub struct BusNotificationPublisher {
    bus: Arc<dyn Bus>,
    seal: BroadcastSeal,
}

impl BusNotificationPublisher {
    /// A publisher broadcasting on `bus`, sealing every update with
    /// `seal`: the control plane's, or the data plane's in the gateway.
    #[must_use]
    pub fn new(bus: Arc<dyn Bus>, seal: BroadcastSeal) -> Self {
        Self { bus, seal }
    }

    async fn send(&self, subject: &str, message: &RealtimeMessage) -> Result<(), DomainError> {
        let update = serde_json::to_vec(&Wire::from(message)).map_err(DomainError::infra)?;
        let payload = sealed(&self.seal, subject, &update);
        Ok(self.bus.broadcast(subject, &payload).await?)
    }
}

#[async_trait]
impl NotificationPublisher for BusNotificationPublisher {
    async fn publish_to_operator(
        &self,
        operator_id: &OperatorId,
        message: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        self.send(&operator_subject(operator_id), message).await
    }

    async fn publish_to_org_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        message: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        self.send(&member_subject(organization_id, org_user_id), message)
            .await
    }

    async fn publish_to_tenant_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        message: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        self.send(&tenant_user_subject(tenant_id, user_id), message)
            .await
    }

    async fn publish_dashboard(
        &self,
        subject: &str,
        message: &RealtimeMessage,
    ) -> Result<(), DomainError> {
        self.send(&dashboard_subject(subject)?, message).await
    }
}

/// Live updates heard on a bus, each checked against its publisher's
/// seal.
pub struct BusNotificationSubscriber {
    bus: Arc<dyn Bus>,
    check: BroadcastCheck,
}

impl BusNotificationSubscriber {
    /// A subscriber listening on `bus`, handing on only the updates
    /// `check` finds sealed by a publisher that may send them.
    #[must_use]
    pub fn new(bus: Arc<dyn Bus>, check: BroadcastCheck) -> Self {
        Self { bus, check }
    }

    async fn open(&self, subject: &str) -> Result<Box<dyn NotificationReceiver>, DomainError> {
        let listener = self.bus.listen(subject).await?;
        Ok(Box::new(BusNotificationReceiver {
            listener,
            subject: subject.to_owned(),
            check: self.check.clone(),
        }))
    }
}

#[async_trait]
impl NotificationSubscriber for BusNotificationSubscriber {
    async fn subscribe_operator(
        &self,
        operator_id: &OperatorId,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
        self.open(&operator_subject(operator_id)).await
    }

    async fn subscribe_org_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
        self.open(&member_subject(organization_id, org_user_id))
            .await
    }

    async fn subscribe_tenant_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
        self.open(&tenant_user_subject(tenant_id, user_id)).await
    }

    async fn subscribe_dashboard(
        &self,
        subject: &str,
    ) -> Result<Box<dyn NotificationReceiver>, DomainError> {
        self.open(&dashboard_subject(subject)?).await
    }
}

/// The live updates on one subject, checked against their seals.
struct BusNotificationReceiver {
    listener: Box<dyn Listener>,
    subject: String,
    check: BroadcastCheck,
}

impl BusNotificationReceiver {
    /// The update `payload` carries, when its seal holds for this subject
    /// under a publisher that may send it, and it reads back.
    fn vouched_update(&self, payload: &[u8]) -> Option<RealtimeMessage> {
        let (seal, update) = unsealed(payload)?;
        let vouched = self.check.vouched(&self.subject, update, seal);
        if vouched == Vouched::Nobody {
            return None;
        }
        let message = update_in(update)?;
        may_send(vouched, &message).then_some(message)
    }
}

/// The update `payload` writes, or `None` when it does not read back.
fn update_in(payload: &[u8]) -> Option<RealtimeMessage> {
    serde_json::from_slice::<Wire>(payload).ok()?.read()
}

/// Whether the publisher `vouched` names may send `message`: the control
/// plane any update, the data plane only a request the gateway decided.
fn may_send(vouched: Vouched, message: &RealtimeMessage) -> bool {
    match (vouched, message) {
        (Vouched::ControlPlane, _) | (Vouched::DataPlane, RealtimeMessage::ProxyAudit(_)) => true,
        (
            Vouched::DataPlane,
            RealtimeMessage::Notification(_)
            | RealtimeMessage::SetupProgress(_)
            | RealtimeMessage::BrokerMessage(_)
            | RealtimeMessage::RunMoment(_)
            | RealtimeMessage::DraftChanged(_),
        )
        | (Vouched::Nobody, _) => false,
    }
}

#[async_trait]
impl NotificationReceiver for BusNotificationReceiver {
    async fn recv(&mut self) -> Option<RealtimeMessage> {
        loop {
            let payload = self.listener.next().await?;
            let Some(message) = self.vouched_update(&payload) else {
                tracing::warn!("a live update with no seal that holds, or unreadable, was dropped");
                continue;
            };
            return Some(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::provisioning::{SetupProgress, StepOutcome};
    use ianua_app::ports::realtime::{
        BrokerDelivery, NotificationUpdate, ProxyAuditEntry, ProxyDecision,
    };
    use ianua_domain::domains::messaging::topic_name::TopicName;
    use ianua_domain::domains::notifications::category::NotificationCategory;
    use ianua_domain::domains::notifications::notification::{
        AboutResource, ReadState, title_label,
    };
    use ianua_domain::domains::notifications::reach::NotificationReach;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::domains::proxy::observation::ObservedPrincipal;
    use ianua_domain::domains::proxy::request::context::ConsumerCredential;
    use ianua_domain::domains::tenant::setup::SetupStep;
    use ianua_domain::shared::model::steps::RunOutcome;
    use ianua_domain::types::{
        AgentId, ConsumerId, CorrelationId, DelegationId, EventType, Fact, NotificationId,
        PrincipalRef, Text, UntrustedText,
    };
    use uuid::Uuid;

    use super::*;
    use crate::bus::MemoryBus;
    use crate::crypto::RootSecret;
    use crate::crypto::keys::tests::test_root;

    fn check() -> BroadcastCheck {
        BroadcastCheck::new(
            BroadcastSeal::control_plane(&test_root()),
            BroadcastSeal::data_plane(&test_root()),
        )
    }

    fn pair() -> (
        Arc<MemoryBus>,
        BusNotificationPublisher,
        BusNotificationSubscriber,
    ) {
        let bus = Arc::new(MemoryBus::new(16));
        (
            Arc::clone(&bus),
            BusNotificationPublisher::new(
                Arc::clone(&bus) as Arc<dyn Bus>,
                BroadcastSeal::control_plane(&test_root()),
            ),
            BusNotificationSubscriber::new(bus, check()),
        )
    }

    /// A publisher on `bus` sealing as `seal` does.
    fn publishing_as(bus: &Arc<MemoryBus>, seal: BroadcastSeal) -> BusNotificationPublisher {
        BusNotificationPublisher::new(Arc::clone(bus) as Arc<dyn Bus>, seal)
    }

    fn notification() -> RealtimeMessage {
        RealtimeMessage::Notification(NotificationUpdate {
            id: NotificationId::from_uuid(Uuid::now_v7()),
            event_type: EventType::all().next().unwrap(),
            category: NotificationCategory::parse("identity").unwrap(),
            severity: NotificationSeverity::parse("warning").unwrap(),
            title: title_label("New sign-in").unwrap(),
            body: Some(Text::new("body", "From a new device").unwrap()),
            resource_id: AboutResource::Resource(Uuid::now_v7()),
            reach: NotificationReach::OwnAccount,
            read: ReadState::Unread,
        })
    }

    fn proxy_audit(principal: ObservedPrincipal) -> RealtimeMessage {
        RealtimeMessage::ProxyAudit(ProxyAuditEntry {
            correlation_id: CorrelationId::from_uuid(Uuid::now_v7()),
            method: UntrustedText::record("GET"),
            path: UntrustedText::record("/orders"),
            tenant_id: Fact::from_option(Some(TenantId::from_uuid(Uuid::now_v7()))),
            principal,
            decision: ProxyDecision::Denied,
            status: 403,
            latency: time::Duration::milliseconds(12),
        })
    }

    fn the_same(sent: &RealtimeMessage, heard: &RealtimeMessage) -> bool {
        format!("{sent:?}") == format!("{heard:?}")
    }

    async fn heard_by_operator(message: RealtimeMessage) -> RealtimeMessage {
        let (_, publisher, subscriber) = pair();
        let operator = OperatorId::from_uuid(Uuid::now_v7());
        let mut receiver = subscriber.subscribe_operator(&operator).await.unwrap();

        publisher
            .publish_to_operator(&operator, &message)
            .await
            .unwrap();

        receiver.recv().await.unwrap()
    }

    /// A notification arrives whole on the operator it was sent to.
    #[tokio::test]
    async fn a_notification_arrives_whole() {
        let sent = notification();

        let heard = heard_by_operator(sent.clone()).await;

        assert!(the_same(&sent, &heard));
    }

    /// A failed step of a tenant's setup arrives whole, with its reason.
    #[tokio::test]
    async fn setup_progress_arrives_whole() {
        let sent = RealtimeMessage::SetupProgress(SetupProgress {
            tenant_id: TenantId::from_uuid(Uuid::now_v7()),
            organization_id: OrganizationId::from_uuid(Uuid::now_v7()),
            step: SetupStep::Database,
            step_outcome: StepOutcome::Failed,
            done_steps: 1,
            total_steps: 4,
            setup: RunOutcome::Failed,
            failure_reason: Some(UntrustedText::record("the database did not answer")),
        });

        let heard = heard_by_operator(sent.clone()).await;

        assert!(the_same(&sent, &heard));
    }

    /// A message from the agent message plane arrives whole, its bytes
    /// untouched.
    #[tokio::test]
    async fn a_broker_message_arrives_whole() {
        let sent = RealtimeMessage::BrokerMessage(BrokerDelivery {
            topic: TopicName::new("orders.created").unwrap(),
            payload: vec![0, 159, 146, 150],
        });

        let heard = heard_by_operator(sent.clone()).await;

        assert!(the_same(&sent, &heard));
    }

    /// A decided request arrives whole for every kind of caller.
    #[tokio::test]
    async fn a_proxy_decision_arrives_whole_for_every_caller() {
        let callers = [
            ObservedPrincipal::Anonymous,
            ObservedPrincipal::User(UserId::from_uuid(Uuid::now_v7())),
            ObservedPrincipal::Agent {
                agent_id: AgentId::from_uuid(Uuid::now_v7()),
                delegation_id: DelegationId::from_uuid(Uuid::now_v7()),
                on_behalf_of: PrincipalRef::from(UserId::from_uuid(Uuid::now_v7())),
            },
            ObservedPrincipal::Consumer {
                consumer_id: ConsumerId::from_uuid(Uuid::now_v7()),
                credential: ConsumerCredential::Certificate,
            },
        ];

        for caller in callers {
            let sent = proxy_audit(caller);

            let heard = heard_by_operator(sent.clone()).await;

            assert!(the_same(&sent, &heard));
        }
    }

    /// One member's updates never reach another member of the same
    /// organization.
    #[tokio::test]
    async fn an_update_reaches_only_its_member() {
        let (_, publisher, subscriber) = pair();
        let organization = OrganizationId::from_uuid(Uuid::now_v7());
        let alice = OrgUserId::from_uuid(Uuid::now_v7());
        let bob = OrgUserId::from_uuid(Uuid::now_v7());
        let mut bobs = subscriber
            .subscribe_org_user(&organization, &bob)
            .await
            .unwrap();

        publisher
            .publish_to_org_user(&organization, &alice, &notification())
            .await
            .unwrap();
        let for_bob = notification();
        publisher
            .publish_to_org_user(&organization, &bob, &for_bob)
            .await
            .unwrap();

        assert!(the_same(&for_bob, &bobs.recv().await.unwrap()));
    }

    /// Dashboard subscriptions reject wildcards, spaces and empty subject segments.
    #[tokio::test]
    async fn a_dashboard_subject_naming_more_than_one_is_refused() {
        let (_, _, subscriber) = pair();

        for subject in ["ianua.dashboard.org.*", "ianua.>", "a..b", "a b", ""] {
            assert!(subscriber.subscribe_dashboard(subject).await.is_err());
        }
    }

    /// A dashboard update arrives on the dashboard subject it was sent to.
    #[tokio::test]
    async fn a_dashboard_update_arrives() {
        let (_, publisher, subscriber) = pair();
        let mut receiver = subscriber
            .subscribe_dashboard("ianua.dashboard.platform")
            .await
            .unwrap();
        let sent = notification();

        publisher
            .publish_dashboard("ianua.dashboard.platform", &sent)
            .await
            .unwrap();

        assert!(the_same(&sent, &receiver.recv().await.unwrap()));
    }

    /// An update that does not read back is dropped, and the next one
    /// still arrives.
    #[tokio::test]
    async fn an_unreadable_update_is_dropped() {
        let (bus, publisher, subscriber) = pair();
        let operator = OperatorId::from_uuid(Uuid::now_v7());
        let subject = operator_subject(&operator);
        let mut receiver = subscriber.subscribe_operator(&operator).await.unwrap();
        let sent = notification();
        let unreadable = sealed(
            &BroadcastSeal::control_plane(&test_root()),
            &subject,
            b"{\"kind\":\"nothing\"}",
        );

        bus.broadcast(&subject, &unreadable).await.unwrap();
        publisher
            .publish_to_operator(&operator, &sent)
            .await
            .unwrap();

        assert!(the_same(&sent, &receiver.recv().await.unwrap()));
    }

    /// Updates with missing, forged, wrong-root or wrong-subject seals are
    /// dropped; the next genuine operator update still arrives.
    #[tokio::test]
    async fn an_update_without_a_seal_that_holds_is_dropped() {
        let (bus, publisher, subscriber) = pair();
        let operator = OperatorId::from_uuid(Uuid::now_v7());
        let subject = operator_subject(&operator);
        let mut receiver = subscriber.subscribe_operator(&operator).await.unwrap();
        let fake = serde_json::to_vec(&Wire::from(&notification())).unwrap();
        let other_root = RootSecret::parse(&"cd".repeat(32)).unwrap();
        let other_subject = operator_subject(&OperatorId::from_uuid(Uuid::now_v7()));
        let forged = [
            fake.clone(),
            [b"forged.".as_slice(), &fake].concat(),
            sealed(&BroadcastSeal::control_plane(&other_root), &subject, &fake),
            sealed(
                &BroadcastSeal::control_plane(&test_root()),
                &other_subject,
                &fake,
            ),
        ];
        let sent = notification();

        for payload in &forged {
            bus.broadcast(&subject, payload).await.unwrap();
        }
        publisher
            .publish_to_operator(&operator, &sent)
            .await
            .unwrap();

        assert!(the_same(&sent, &receiver.recv().await.unwrap()));
    }

    /// A notification sealed by the data plane is dropped while its subsequent
    /// proxy decision reaches the operator.
    #[tokio::test]
    async fn the_data_plane_vouches_only_for_decided_requests() {
        let (bus, _, subscriber) = pair();
        let gateway = publishing_as(&bus, BroadcastSeal::data_plane(&test_root()));
        let operator = OperatorId::from_uuid(Uuid::now_v7());
        let mut receiver = subscriber.subscribe_operator(&operator).await.unwrap();
        let decided = proxy_audit(ObservedPrincipal::Anonymous);

        gateway
            .publish_to_operator(&operator, &notification())
            .await
            .unwrap();
        gateway
            .publish_to_operator(&operator, &decided)
            .await
            .unwrap();

        assert!(the_same(&decided, &receiver.recv().await.unwrap()));
    }
}
