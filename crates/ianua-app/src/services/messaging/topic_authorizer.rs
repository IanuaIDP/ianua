//! Topic authorizer: layer A of the message plane (transport authorization).
//!
//! The message-plane sibling of the proxy's `policy` stage: it reads the
//! same delegated [`CapabilitySet`](ianua_domain::domains::agents::authority::capability::CapabilitySet)
//! and lets it answer "may this principal publish or subscribe this topic?",
//! denying by default.
//!
//! Topics are **tenant-relative** (`agents.a2.tasks`, not the wire subject
//! `ianua.msg.{tenant}.agents.a2.tasks`). The message relay only ever resolves
//! topics in the tenant the task token was issued for, so tenant isolation is
//! structural and cap patterns stay broker-portable.

use async_trait::async_trait;
use ianua_domain::domains::agents::authority::capability::{PubSub, TopicCapability, TopicPattern};
use ianua_domain::domains::messaging::topic_name::TopicName;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;

use crate::ports::broker::{AgentPrincipal, TopicAuthorizer};

/// Authorizes pub/sub by asking the principal's delegated capabilities
/// whether they cover the request.
#[derive(Debug, Default, Clone, Copy)]
pub struct DelegationTopicAuthorizer;

impl DelegationTopicAuthorizer {
    /// Creates the authorizer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TopicAuthorizer for DelegationTopicAuthorizer {
    async fn authorize(
        &self,
        principal: &AgentPrincipal,
        topic: &TopicName,
        action: PubSub,
    ) -> Result<(), DomainError> {
        let requested = TopicCapability::new(TopicPattern::new(topic.as_str())?, action);
        if principal.caps.permits_topic(&requested) {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "messaging-topic-not-permitted-for-this-principal",
            "topic not permitted for this principal"
        )))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::CapabilitySet;
    use ianua_domain::types::{AgentId, DelegationId, PrincipalRef, TenantId, UserId};

    use super::*;
    use crate::test_support::block_on;

    fn principal(caps: CapabilitySet) -> AgentPrincipal {
        AgentPrincipal {
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            subject: PrincipalRef::User(UserId::new()),
            caps,
        }
    }

    fn caps(pattern: &str, rights: PubSub) -> CapabilitySet {
        CapabilitySet::new(
            vec![],
            vec![TopicCapability::new(
                TopicPattern::new(pattern).unwrap(),
                rights,
            )],
        )
    }

    fn tasks_topic() -> TopicName {
        TopicName::new("agents.a2.tasks").unwrap()
    }

    /// Ann's agent was delegated every `agents.` topic, so it may publish to
    /// `agents.a2.tasks`.
    #[test]
    fn allows_topic_within_a_granted_pattern() {
        let principal = principal(caps("agents.>", PubSub::Both));

        let result = block_on(DelegationTopicAuthorizer::new().authorize(
            &principal,
            &tasks_topic(),
            PubSub::Publish,
        ));

        assert!(result.is_ok());
    }

    /// An agent delegated `agents.a1.` topics is refused publication to `agents.a2.tasks`.
    #[test]
    fn denies_topic_outside_granted_pattern() {
        let principal = principal(caps("agents.a1.>", PubSub::Both));

        let result = block_on(DelegationTopicAuthorizer::new().authorize(
            &principal,
            &tasks_topic(),
            PubSub::Publish,
        ));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A matching topic pattern grants no publishing rights when it permits only subscribing.
    #[test]
    fn denies_publish_when_only_subscribe_is_granted() {
        let principal = principal(caps("agents.>", PubSub::Subscribe));

        let result = block_on(DelegationTopicAuthorizer::new().authorize(
            &principal,
            &tasks_topic(),
            PubSub::Publish,
        ));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An agent with no delegated topic capabilities is refused a subscription.
    #[test]
    fn denies_by_default_with_no_capabilities() {
        let principal = principal(CapabilitySet::empty());

        let result = block_on(DelegationTopicAuthorizer::new().authorize(
            &principal,
            &tasks_topic(),
            PubSub::Subscribe,
        ));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }
}
