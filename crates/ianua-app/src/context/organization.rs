//! A caller on the organization plane: a member and their credential.

use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::types::{
    ActorRef, Fact, IpAddress, OrgApiKeyId, OrgUserId, OrganizationId, SessionId, UserAgent,
};

/// The credential an organization member came with, on the organization
/// plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgCredential {
    /// Their own signed-in session.
    Session(SessionId),
    /// An organization API key they made.
    ApiKey(OrgApiKeyId),
}

/// A member acting on their organization: who they are, the organization,
/// and the credential they came with. It claims no permission; what they
/// may do is worked out by [`acting`](crate::acting).
#[derive(Debug, Clone)]
pub struct OrgCaller {
    member: OrgUserId,
    credential: OrgCredential,
    organization_id: OrganizationId,
    ip_address: Option<IpAddress>,
    user_agent: Option<UserAgent>,
}

impl OrgCaller {
    /// `member` acting on `organization_id` through `credential`.
    #[must_use]
    pub fn new(
        member: OrgUserId,
        credential: OrgCredential,
        organization_id: OrganizationId,
    ) -> Self {
        Self {
            member,
            credential,
            organization_id,
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

    /// Where the request came from, as failed passwords are counted.
    #[must_use]
    pub fn origin(&self) -> AttemptOrigin {
        AttemptOrigin::of(Fact::from_option(self.ip_address.as_ref()))
    }

    /// The member acting.
    #[must_use]
    pub fn member(&self) -> &OrgUserId {
        &self.member
    }

    /// The credential they came with.
    #[must_use]
    pub fn credential(&self) -> &OrgCredential {
        &self.credential
    }

    /// The organization they act on.
    #[must_use]
    pub fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }

    /// The audit context for the request: the member, the organization and
    /// the request's address and client.
    #[must_use]
    pub fn audit_context(&self) -> AuditContext {
        AuditContext::for_caller(self.organization_id, ActorRef::OrgUser(self.member)).with_request(
            Fact::from_option(self.ip_address.clone()),
            Fact::from_option(self.user_agent.clone()),
        )
    }
}
