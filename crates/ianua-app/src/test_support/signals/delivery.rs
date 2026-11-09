//! Fakes that push, hold and throttle Security Event Tokens.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::signals::stream::EndpointChallenge;
use ianua_domain::domains::signals::verification::VERIFICATION_EVENT_TYPE;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    AgentId, DeliveryOutcome, PublicHttpsUrl, SignalId, SignalStreamId, TenantId,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::signals::{
    Backlog, PollBatch, PolledEvents, QueuedEvent, ReceiverCredential, SecurityEventToken, SetPush,
    SignalDeliverer, SignalDeliveryOutcome, SignalPollQueue, SuspendedAgents, VerificationThrottle,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::scheduling::FakeJobQueue;
use crate::use_cases::signals::delivery::SignalJobs;

/// One push the fake deliverer was asked to make.
#[derive(Debug, Clone)]
pub struct RecordedPush {
    /// Where it went.
    pub endpoint: PublicHttpsUrl,
    /// The token it carried.
    pub token: SecurityEventToken,
    /// The `Authorization` header it carried.
    pub credential: ReceiverCredential,
}

impl RecordedPush {
    /// Whether it carried a verification event rather than a signal.
    #[must_use]
    pub fn is_verification(&self) -> bool {
        claims_of(&self.token)
            .get("events")
            .and_then(|events| events.get(VERIFICATION_EVENT_TYPE))
            .is_some()
    }

    /// The `state` its verification event carried, if it carried one.
    #[must_use]
    pub fn verification_state(&self) -> Option<String> {
        claims_of(&self.token)
            .get("events")?
            .get(VERIFICATION_EVENT_TYPE)?
            .get("state")?
            .as_str()
            .map(str::to_owned)
    }

    /// The header value it carried, if any, as the receiver reads it.
    #[must_use]
    pub fn header(&self) -> Option<String> {
        match &self.credential {
            ReceiverCredential::Omitted => None,
            ReceiverCredential::Header(value) => Some(value.expose().to_owned()),
        }
    }
}

/// The claims inside a token the fake JWT signer made, which writes
/// `header.{claims}.sig_{kid}`.
///
/// # Panics
///
/// Panics if the token was not made by the fake signer.
#[must_use]
pub fn claims_of(token: &SecurityEventToken) -> serde_json::Value {
    let body = token
        .as_str()
        .strip_prefix("header.")
        .and_then(|rest| rest.rsplit_once(".sig_"))
        .map(|(claims, _)| claims)
        .expect("a token the fake signer made");
    serde_json::from_str(body).expect("the fake signer's claims are JSON")
}

/// Signal deliverer for tests that ends every push the same way and keeps
/// every push it was asked to make.
pub struct FakeSignalDeliverer {
    outcome: DeliveryOutcome,
    /// Every push, in order.
    pub pushes: Mutex<Vec<RecordedPush>>,
}

impl Default for FakeSignalDeliverer {
    fn default() -> Self {
        Self::always(DeliveryOutcome::Answered { code: 200 })
    }
}

impl FakeSignalDeliverer {
    /// A deliverer whose every push is answered with `200`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A deliverer whose every push ends in `outcome`.
    #[must_use]
    pub fn always(outcome: DeliveryOutcome) -> Self {
        Self {
            outcome,
            pushes: Mutex::new(Vec::new()),
        }
    }

    /// How many signals, not verification events, were pushed.
    #[must_use]
    pub fn signal_pushes(&self) -> usize {
        self.pushes
            .lock()
            .unwrap()
            .iter()
            .filter(|push| !push.is_verification())
            .count()
    }

    /// The verification events pushed, in order.
    #[must_use]
    pub fn verifications(&self) -> Vec<RecordedPush> {
        self.pushes
            .lock()
            .unwrap()
            .iter()
            .filter(|push| push.is_verification())
            .cloned()
            .collect()
    }

    /// Every endpoint challenge pushed, with the endpoint it went to.
    #[must_use]
    pub fn challenges(&self) -> Vec<(PublicHttpsUrl, EndpointChallenge)> {
        self.verifications()
            .into_iter()
            .filter_map(|push| {
                let challenge = EndpointChallenge::new(push.verification_state()?).ok()?;
                Some((push.endpoint, challenge))
            })
            .collect()
    }

    /// The last challenge pushed, as the endpoint would echo it.
    ///
    /// # Panics
    ///
    /// Panics if no challenge was pushed.
    #[must_use]
    pub fn last_challenge(&self) -> EndpointChallenge {
        self.challenges()
            .pop()
            .map(|(_, challenge)| challenge)
            .expect("a challenge was pushed")
    }
}

#[async_trait]
impl SignalDeliverer for FakeSignalDeliverer {
    async fn deliver(&self, push: SetPush<'_>) -> Result<SignalDeliveryOutcome, DomainError> {
        self.pushes.lock().unwrap().push(RecordedPush {
            endpoint: push.endpoint.clone(),
            token: push.token.clone(),
            credential: push.credential.clone(),
        });
        Ok(SignalDeliveryOutcome {
            outcome: self.outcome,
            duration_ms: 0,
        })
    }
}

/// One event the fake queue holds.
#[derive(Debug, Clone)]
struct HeldEvent {
    tenant_id: TenantId,
    stream_id: SignalStreamId,
    event: QueuedEvent,
}

/// In-memory poll queue for tests, holding each event under the tenant and
/// stream it was queued for.
#[derive(Default)]
pub struct FakeSignalPollQueue {
    held: Mutex<Vec<HeldEvent>>,
}

impl TenantScoped for FakeSignalPollQueue {}

impl FakeSignalPollQueue {
    /// A queue holding nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The events the test tenant's stream `stream_id` holds, oldest first.
    #[must_use]
    pub fn held_for(&self, stream_id: &SignalStreamId) -> Vec<QueuedEvent> {
        let tenant = crate::test_support::test_ctx().tenant_id();
        self.held
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.tenant_id == tenant && held.stream_id == *stream_id)
            .map(|held| held.event.clone())
            .collect()
    }
}

#[async_trait]
impl SignalPollQueue for FakeSignalPollQueue {
    async fn enqueue(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        event: &QueuedEvent,
    ) -> Result<(), DomainError> {
        self.held.lock().unwrap().push(HeldEvent {
            tenant_id: **tenant_id,
            stream_id: *stream_id,
            event: event.clone(),
        });
        Ok(())
    }

    async fn acknowledge(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        jtis: &[SignalId],
    ) -> Result<(), DomainError> {
        self.held.lock().unwrap().retain(|held| {
            held.tenant_id != **tenant_id
                || held.stream_id != *stream_id
                || !jtis.contains(&held.event.jti)
        });
        Ok(())
    }

    async fn next(
        &self,
        tenant_id: &ScopedTenant,
        stream_id: &SignalStreamId,
        batch: PollBatch,
    ) -> Result<PolledEvents, DomainError> {
        let waiting: Vec<QueuedEvent> = self
            .held
            .lock()
            .unwrap()
            .iter()
            .filter(|held| held.tenant_id == **tenant_id && held.stream_id == *stream_id)
            .map(|held| held.event.clone())
            .collect();
        let backlog = if waiting.len() > usize::from(batch.get()) {
            Backlog::MoreWaiting
        } else {
            Backlog::Drained
        };
        let events = waiting.into_iter().take(usize::from(batch.get())).collect();
        Ok(PolledEvents { events, backlog })
    }
}

/// Verification throttle that lets every request through.
pub struct OpenVerificationThrottle;

impl TenantScoped for OpenVerificationThrottle {}

#[async_trait]
impl VerificationThrottle for OpenVerificationThrottle {
    async fn admit(&self, _: &ScopedTenant, _: &SignalStreamId) -> Result<bool, DomainError> {
        Ok(true)
    }
}

/// Verification throttle that holds every request back, as for a stream
/// that asked a moment ago.
pub struct ShutVerificationThrottle;

impl TenantScoped for ShutVerificationThrottle {}

#[async_trait]
impl VerificationThrottle for ShutVerificationThrottle {
    async fn admit(&self, _: &ScopedTenant, _: &SignalStreamId) -> Result<bool, DomainError> {
        Ok(false)
    }
}

impl Fake for Arc<dyn SignalDeliverer> {
    fn fake() -> Self {
        Arc::new(FakeSignalDeliverer::new())
    }
}

impl Fake for Arc<dyn SignalPollQueue> {
    fn fake() -> Self {
        Arc::new(FakeSignalPollQueue::empty())
    }
}

impl Fake for Arc<dyn VerificationThrottle> {
    fn fake() -> Self {
        Arc::new(OpenVerificationThrottle)
    }
}

/// The agents a tenant-wide stop suspended, as a test lays them out, and
/// the times they were asked for since.
#[derive(Default)]
pub struct FakeSuspendedAgents {
    agents: Vec<(TenantId, AgentId)>,
    asked_since: Mutex<Vec<OffsetDateTime>>,
}

impl FakeSuspendedAgents {
    /// The agents `agents` of `tenant`, all suspended.
    #[must_use]
    pub fn of(tenant: TenantId, agents: &[AgentId]) -> Self {
        Self {
            agents: agents.iter().map(|agent| (tenant, *agent)).collect(),
            ..Self::default()
        }
    }

    /// The times asked for since, in order.
    #[must_use]
    pub fn asked_since(&self) -> Vec<OffsetDateTime> {
        self.asked_since.lock().unwrap().clone()
    }
}

impl TenantScoped for FakeSuspendedAgents {}

#[async_trait]
impl SuspendedAgents for FakeSuspendedAgents {
    async fn suspended_since(
        &self,
        tenant_id: &ScopedTenant,
        since: OffsetDateTime,
        limit: NonZeroU32,
    ) -> Result<Vec<AgentId>, DomainError> {
        self.asked_since.lock().unwrap().push(since);
        Ok(self
            .agents
            .iter()
            .filter(|(tenant, _)| tenant == &**tenant_id)
            .map(|(_, agent)| *agent)
            .take(limit.get() as usize)
            .collect())
    }
}

impl Fake for Arc<dyn SuspendedAgents> {
    fn fake() -> Self {
        Arc::new(FakeSuspendedAgents::default())
    }
}

impl Fake for SignalJobs {
    fn fake() -> Self {
        SignalJobs {
            queue: Arc::new(FakeJobQueue::new()),
            attempts: NonZeroU32::MIN,
        }
    }
}
