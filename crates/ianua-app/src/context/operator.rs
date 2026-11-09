//! An operator acting on the platform with their own key.

use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::types::{ActorRef, Fact, IpAddress, KeyPrefix, OperatorId, UserAgent};

/// An operator acting on the platform with their own key. What they may do
/// is worked out by [`acting`](crate::acting).
#[derive(Debug, Clone)]
pub struct OperatorCaller {
    operator: OperatorId,
    key: KeyPrefix,
    ip_address: Option<IpAddress>,
    user_agent: Option<UserAgent>,
}

impl OperatorCaller {
    /// `operator` acting through the key `key`.
    #[must_use]
    pub fn new(operator: OperatorId, key: KeyPrefix) -> Self {
        Self {
            operator,
            key,
            ip_address: None,
            user_agent: None,
        }
    }

    /// Attaches the client's IP address and User-Agent.
    #[must_use]
    pub fn with_request_metadata(
        mut self,
        ip_address: Option<IpAddress>,
        user_agent: Option<UserAgent>,
    ) -> Self {
        self.ip_address = ip_address;
        self.user_agent = user_agent;
        self
    }

    /// The operator acting.
    #[must_use]
    pub fn operator(&self) -> &OperatorId {
        &self.operator
    }

    /// The key they came with.
    #[must_use]
    pub fn key(&self) -> &KeyPrefix {
        &self.key
    }

    /// The audit context for the request: the operator, on the platform.
    #[must_use]
    pub fn audit_context(&self) -> AuditContext {
        AuditContext::for_platform_caller(ActorRef::Operator(self.operator)).with_request(
            Fact::from_option(self.ip_address.clone()),
            Fact::from_option(self.user_agent.clone()),
        )
    }
}
