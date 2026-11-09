//! Relay publish, an agent hands ianua one message for its own area.
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
use ianua_domain::shared::security::secret::Secret;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::ports::broker::AgentPrincipal;
use crate::ports::messaging::OutgoingMessage;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::messaging::channels::agent_relay::{
    AgentRelayPorts, MAX_MESSAGE_BYTES, PROVENANCE_HEADER, TopicAccess, admitted_topic,
    authenticated_principal, ensure_exposure_admitted, record_decision,
};

/// An agent's request to publish one message.
pub struct RelayPublishRequest {
    /// The agent's task token.
    pub credential: Secret,
    /// The topic to publish to.
    pub topic: TopicName,
    /// The message, as the agent sent it.
    pub payload: Vec<u8>,
}

/// A published message after every check, ready for the bus.
struct SealedMessage {
    payload: Vec<u8>,
    provenance: SealedProvenance,
}

/// Decides, signs, forwards and records one agent's message.
pub struct RelayPublishUseCase {
    ports: AgentRelayPorts,
}

impl RelayPublishUseCase {
    /// Creates the use case over the relay's ports.
    #[must_use]
    pub fn new(ports: AgentRelayPorts) -> Self {
        Self { ports }
    }

    /// The message in canonical form with its signed provenance, once every
    /// check has passed. The data mark is raised last, so a refused message
    /// never raises it.
    ///
    /// # Errors
    ///
    /// As [`execute`](Command::execute), less authentication.
    async fn sealed(
        &self,
        tenant: &ScopedTenant,
        principal: &AgentPrincipal,
        topic_name: &TopicName,
        payload: &[u8],
    ) -> Result<SealedMessage, AppError> {
        ensure_publishable(principal, topic_name, payload)?;
        let access = TopicAccess {
            topic: topic_name,
            action: PubSub::Publish,
        };
        let topic = admitted_topic(&self.ports, tenant, principal, access).await?;
        let canonical = self.conformed(&topic, payload)?;
        ensure_exposure_admitted(&self.ports, tenant, principal, &topic).await?;
        let provenance = self
            .ports
            .provenance
            .seal(principal, &canonical)
            .await
            .map_err(AppError::from_domain)?;
        Ok(SealedMessage {
            payload: canonical,
            provenance,
        })
    }

    /// `payload` rewritten to the canonical form of the topic's schema.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the topic declares no schema.
    /// - `AppError::Domain(Validation)` when the payload does not match it.
    fn conformed(
        &self,
        topic: &Topic<ResolvedTenant>,
        payload: &[u8],
    ) -> Result<Vec<u8>, AppError> {
        let Some(schema) = topic.schema() else {
            return Err(AppError::Forbidden(message!(
                "messaging-the-topic-declares-no-message-schema",
                "the topic declares no message schema"
            )));
        };
        self.ports
            .shape
            .conform(schema, payload)
            .map_err(AppError::from_domain)
    }
}

impl Command for RelayPublishUseCase {
    type Caller = ScopedTenant;
    type Input = RelayPublishRequest;
    type Output = Result<(), AppError>;

    /// Publishes one message for an agent to the tenant the request was
    /// addressed to.
    ///
    /// Records `agents.message_authorized`, or `agents.message_denied` for a
    /// refusal the agent caused, before anything reaches the bus. A token
    /// that does not authenticate records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the token does not verify, its
    ///   delegation is revoked, or it was issued for another tenant.
    /// - `AppError::Forbidden` when any check refuses the message.
    /// - `AppError::NotFound` when the delegation covers a topic that does not
    ///   exist.
    /// - `AppError::Domain(Validation)` when the message does not match the
    ///   topic's schema.
    /// - `AppError::Internal` when a check cannot be made, the decision cannot
    ///   be recorded, or the bus refuses the message.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RelayPublishRequest,
    ) -> Result<(), AppError> {
        let principal = authenticated_principal(&self.ports, tenant, &req.credential).await?;
        let sealed = self
            .sealed(tenant, &principal, &req.topic, &req.payload)
            .await;
        let access = TopicAccess {
            topic: &req.topic,
            action: PubSub::Publish,
        };
        record_decision(auditor, &principal, access, &sealed).await?;
        let sealed = sealed?;
        let headers = [(
            PROVENANCE_HEADER.to_owned(),
            sealed.provenance.as_str().to_owned(),
        )];
        let message = OutgoingMessage {
            payload: &sealed.payload,
            headers: &headers,
            message_type: None,
        };
        self.ports
            .publisher
            .publish(&principal.tenant_id, &req.topic, &message)
            .await
            .map_err(AppError::from_domain)
    }
}

/// Refuses a message over [`MAX_MESSAGE_BYTES`], or one outside the
/// publishing agent's own area.
///
/// # Errors
///
/// `AppError::Forbidden` naming the rule broken.
fn ensure_publishable(
    principal: &AgentPrincipal,
    topic_name: &TopicName,
    payload: &[u8],
) -> Result<(), AppError> {
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err(AppError::Forbidden(message!(
            "messaging-a-message-may-be-at-most",
            format!("a message may be at most {MAX_MESSAGE_BYTES} bytes")
        )));
    }
    if !AgentArea::of(principal.agent_id).contains(topic_name) {
        return Err(AppError::Forbidden(message!(
            "messaging-an-agent-publishes-only-in-its",
            "an agent publishes only in its own area"
        )));
    }
    Ok(())
}
