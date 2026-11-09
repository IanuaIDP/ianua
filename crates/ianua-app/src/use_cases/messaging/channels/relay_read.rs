//! Relay read, an agent takes the next messages off a topic through ianua.
//!
//! The checks, and what each refusal means, are set out in
//! [`agent_relay`](crate::use_cases::messaging::channels::agent_relay).

use ianua_domain::domains::agents::authority::capability::PubSub;
use ianua_domain::domains::agents::authority::provenance::SealedProvenance;
use ianua_domain::domains::agents::channels::area::AgentArea;
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::AgentId;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::broker::AgentPrincipal;
use crate::ports::messaging::{Acknowledgement, ConsumerRead, ConsumerSpec, ReceivedMessage};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::messaging::channels::agent_relay::{
    AgentRelayPorts, MAX_READ_BATCH, PROVENANCE_HEADER, RelayedMessage, TopicAccess,
    admitted_topic, authenticated_principal, ensure_exposure_admitted, record_by_agent,
    record_decision, refusal,
};

/// An agent's request to read from a topic.
pub struct RelayReadRequest {
    /// The agent's task token.
    pub credential: Secret,
    /// The topic to read from.
    pub topic: TopicName,
    /// How many messages to return at most; capped at `MAX_READ_BATCH`.
    pub max_messages: usize,
}

/// Decides, verifies and records one agent's read of a topic.
pub struct RelayReadUseCase {
    ports: AgentRelayPorts,
}

impl RelayReadUseCase {
    /// Creates the use case over the relay's ports.
    #[must_use]
    pub fn new(ports: AgentRelayPorts) -> Self {
        Self { ports }
    }

    /// The topic, once the reader may subscribe to it, reads it through an
    /// open channel (or owns the area), and has taken on its data class.
    ///
    /// # Errors
    ///
    /// As [`execute`](Command::execute), less authentication.
    async fn admitted_reader_topic(
        &self,
        tenant: &ScopedTenant,
        principal: &AgentPrincipal,
        topic_name: &TopicName,
    ) -> Result<Topic<ResolvedTenant>, AppError> {
        let access = TopicAccess {
            topic: topic_name,
            action: PubSub::Subscribe,
        };
        let topic = admitted_topic(&self.ports, tenant, principal, access).await?;
        self.ensure_open_channel(tenant, principal, &topic).await?;
        ensure_exposure_admitted(&self.ports, tenant, principal, &topic).await?;
        Ok(topic)
    }

    /// Refuses a read of another agent's area unless a channel a person
    /// opened carries this topic to this reader now.
    ///
    /// # Errors
    ///
    /// `AppError::Forbidden` when the topic is outside every agent area, or
    /// no open channel carries it.
    async fn ensure_open_channel(
        &self,
        tenant: &ScopedTenant,
        principal: &AgentPrincipal,
        topic: &Topic<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let Some(owner) = AgentArea::owner_of(topic.topic_name()) else {
            return Err(AppError::Forbidden(message!(
                "messaging-an-agent-reads-only-from-agent",
                "an agent reads only from agent areas"
            )));
        };
        if owner == principal.agent_id {
            return Ok(());
        }
        if self
            .channel_carries(tenant, &owner, principal, topic)
            .await?
        {
            return Ok(());
        }
        Err(AppError::Forbidden(message!(
            "messaging-no-open-channel-lets-this-agent",
            "no open channel lets this agent read that area"
        )))
    }

    /// Whether a channel `owner` has open with the reader carries `topic` to
    /// them now.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the channels cannot be read.
    async fn channel_carries(
        &self,
        tenant: &ScopedTenant,
        owner: &AgentId,
        principal: &AgentPrincipal,
        topic: &Topic<ResolvedTenant>,
    ) -> Result<bool, AppError> {
        let now = clock::now();
        let channels = self
            .ports
            .channels
            .unclosed_between(tenant, owner, &principal.agent_id)
            .await
            .map_err(AppError::from_domain)?;
        Ok(channels
            .iter()
            .any(|channel| channel.carries(&principal.agent_id, topic, now)))
    }

    /// The next messages on the topic, read through the reader's own cursor.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the bus refuses.
    async fn pulled(
        &self,
        principal: &AgentPrincipal,
        topic: &Topic<ResolvedTenant>,
        max_messages: usize,
    ) -> Result<Vec<ReceivedMessage>, AppError> {
        let consumer = consumer_name(principal, topic);
        self.ports
            .consumer
            .ensure_consumer(
                &principal.tenant_id,
                topic.topic_name(),
                &ConsumerSpec {
                    name: &consumer,
                    filter: None,
                    acknowledgement: Acknowledgement::OnFetch,
                },
            )
            .await
            .map_err(AppError::from_domain)?;
        self.ports
            .consumer
            .pull_messages(
                &principal.tenant_id,
                ConsumerRead {
                    topic_name: topic.topic_name(),
                    consumer_name: &consumer,
                    retention: topic.retention(),
                },
                max_messages.clamp(1, MAX_READ_BATCH),
            )
            .await
            .map_err(AppError::from_domain)
    }

    /// The messages whose provenance verifies, recording every one dropped.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when a dropped message cannot be recorded.
    async fn verified(
        &self,
        auditor: &RequestAuditor,
        principal: &AgentPrincipal,
        topic: &TopicName,
        received: Vec<ReceivedMessage>,
    ) -> Result<Vec<RelayedMessage>, AppError> {
        let mut delivered = Vec::with_capacity(received.len());
        let mut dropped = Vec::new();
        for message in received {
            match self.opened(principal, topic, message).await {
                Ok(relayed) => delivered.push(relayed),
                Err(reason) => dropped.push(refusal(
                    principal,
                    TopicAccess {
                        topic,
                        action: PubSub::Subscribe,
                    },
                    &reason,
                )),
            }
        }
        if !dropped.is_empty() {
            record_by_agent(auditor, principal, dropped).await?;
        }
        Ok(delivered)
    }

    /// The message with the authorship its provenance proves, or why it is
    /// dropped: no provenance, a signature that does not verify, or a sender
    /// other than the area's owner.
    async fn opened(
        &self,
        principal: &AgentPrincipal,
        topic: &TopicName,
        message: ReceivedMessage,
    ) -> Result<RelayedMessage, String> {
        let Some(token) = provenance_of(&message) else {
            return Err("message dropped: it carries no provenance".to_owned());
        };
        let token = SealedProvenance::new(token)
            .map_err(|_| "message dropped: its provenance is not a sealed token".to_owned())?;
        let provenance = self
            .ports
            .provenance
            .open(
                &ScopedTenant::from_verified_credential(principal.tenant_id),
                &token,
                &message.payload,
            )
            .await
            .map_err(|_| "message dropped: its provenance does not verify".to_owned())?;
        if AgentArea::owner_of(topic) != Some(*provenance.sender()) {
            return Err("message dropped: its sender does not own the area".to_owned());
        }
        Ok(RelayedMessage {
            payload: message.payload,
            provenance,
        })
    }
}

impl Command for RelayReadUseCase {
    type Caller = ScopedTenant;
    type Input = RelayReadRequest;
    type Output = Result<Vec<RelayedMessage>, AppError>;

    /// Reads the next messages on a topic for an agent, from the tenant the
    /// request was addressed to.
    ///
    /// Records `agents.message_authorized`, or `agents.message_denied` for a
    /// refusal the agent caused, before anything is read; a message with no
    /// provenance, a provenance that does not verify, or a sender other than
    /// the area's owner is dropped, recorded as
    /// `agents.message_denied`, and never delivered. A token that does not
    /// authenticate records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the token does not verify, its
    ///   delegation is revoked, or it was issued for another tenant.
    /// - `AppError::Forbidden` when any check refuses the read.
    /// - `AppError::NotFound` when the topic does not exist.
    /// - `AppError::Internal` when a check cannot be made, a decision cannot
    ///   be recorded, or the bus refuses.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RelayReadRequest,
    ) -> Result<Vec<RelayedMessage>, AppError> {
        let principal = authenticated_principal(&self.ports, tenant, &req.credential).await?;
        let admitted = self
            .admitted_reader_topic(tenant, &principal, &req.topic)
            .await;
        let access = TopicAccess {
            topic: &req.topic,
            action: PubSub::Subscribe,
        };
        record_decision(auditor, &principal, access, &admitted).await?;
        let topic = admitted?;
        let received = self.pulled(&principal, &topic, req.max_messages).await?;
        self.verified(auditor, &principal, &req.topic, received)
            .await
    }
}

/// The durable consumer one agent reads one topic through. Both ids are
/// globally unique, so no two agents, in any tenant, ever share a cursor.
fn consumer_name(principal: &AgentPrincipal, topic: &Topic<ResolvedTenant>) -> String {
    format!(
        "agent-{}-{}",
        principal.agent_id.as_uuid().as_simple(),
        topic.id().as_uuid().as_simple()
    )
}

fn provenance_of(message: &ReceivedMessage) -> Option<&str> {
    message
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(PROVENANCE_HEADER))
        .map(|(_, value)| value.as_str())
}
