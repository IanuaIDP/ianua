//! The identity assertion the gateway hands an upstream as
//! `X-Ianua-Assertion`: who made the request, for whom, and what they may
//! do, signed with the tenant's assertion keys.
//!
//! An upstream decides on what the assertion says instead of keeping its
//! own copy of who may do what, so what it says comes from the request's
//! verified caller and nothing the client sent. It is made only for a
//! request the policy let through, names the tenant's issuer and the one
//! service it is forwarded to, and lasts seconds, so one copied off the
//! wire is worth little and to one service only.
//!
//! An agent's assertion names the agent as the actor and, typed, whom it
//! acts for: a person, or another agent one hop up a chain, never widened
//! into a person. The delegation it acts under is named too, so an
//! upstream can follow the chain back to the person at its root.

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::domains::proxy::request::context::{
    Authentication, Authorization, Caller, PipelineContext,
};
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{
    AgentId, ConsumerId, CorrelationId, DelegationId, Issuer, Label, PermissionName, PrincipalRef,
    ServiceId, TenantId, UserId,
};

/// How long an assertion is accepted after it is signed. It travels one
/// hop, to the service the request is forwarded to, so a few seconds of
/// clock drift and the forward are all it needs.
pub const ASSERTION_LIFETIME: Duration = Duration::seconds(30);

/// Who an assertion says made the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertedCaller {
    /// A person, through their tenant account.
    User {
        /// The account.
        user_id: UserId,
    },
    /// An agent, acting under a delegation.
    Agent {
        /// The agent, the actor.
        agent_id: AgentId,
        /// Whom it acts for, by kind: a person, or another agent.
        acting_for: PrincipalRef,
        /// The delegation its authority came from.
        delegation_id: DelegationId,
    },
    /// A consumer outside the platform.
    Consumer {
        /// The external client authenticated before its identity is asserted upstream.
        consumer_id: ConsumerId,
    },
}

impl AssertedCaller {
    /// What the assertion, or an exchanged token, says of the verified
    /// `caller`.
    pub(crate) fn of(caller: &Caller) -> Self {
        match caller {
            Caller::User { user_id, .. } => Self::User { user_id: *user_id },
            Caller::Agent {
                agent_id,
                delegation_id,
                acting_for,
                ..
            } => Self::Agent {
                agent_id: *agent_id,
                acting_for: *acting_for,
                delegation_id: *delegation_id,
            },
            Caller::Consumer { consumer_id, .. } => Self::Consumer {
                consumer_id: *consumer_id,
            },
        }
    }

    /// The raw id of whom the request is made for: the person, whom an
    /// agent acts for, or the consumer. It is the assertion's `sub`.
    #[must_use]
    pub fn subject(&self) -> Uuid {
        match self {
            Self::User { user_id } => *user_id.as_uuid(),
            Self::Agent { acting_for, .. } => acting_for.id(),
            Self::Consumer { consumer_id } => *consumer_id.as_uuid(),
        }
    }
}

/// What a signed `X-Ianua-Assertion` says.
#[derive(Debug, Clone)]
pub struct UpstreamAssertion {
    issuer: Issuer,
    audience: ServiceId,
    tenant_id: TenantId,
    correlation_id: CorrelationId,
    caller: AssertedCaller,
    roles: Vec<Label>,
    permissions: Vec<PermissionName>,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl UpstreamAssertion {
    /// The assertion for the request `context` holds, forwarded to the
    /// service `audience`, signed at `now`.
    ///
    /// `None` for an anonymous request: there is nobody to assert, and the
    /// upstream gets no identity at all rather than an empty one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the request's caller is known but
    ///   the policy has not let it through: an identity is never vouched
    ///   for on a request that was not allowed.
    /// - [`DomainError::Infrastructure`] when the tenant's issuer is not
    ///   known, so an upstream could not hold the assertion to it.
    pub fn for_request(
        context: &PipelineContext,
        audience: ServiceId,
        now: OffsetDateTime,
    ) -> Result<Option<Self>, DomainError> {
        let Authentication::Authenticated(verified) = context.authentication() else {
            return Ok(None);
        };
        if context.authorization() != Authorization::Granted {
            return Err(DomainError::forbidden(message!(
                "proxy-an-identity-is-asserted-only-for",
                "an identity is asserted only for a request the policy let through"
            )));
        }
        let Some(issuer) = context.route.expected_issuer.known() else {
            return Err(DomainError::infra_msg(
                "the tenant's issuer is not known, so no assertion can name it",
            ));
        };
        Ok(Some(Self {
            issuer: issuer.clone(),
            audience,
            tenant_id: context.tenant_id,
            correlation_id: context.correlation_id,
            caller: AssertedCaller::of(&verified.caller),
            roles: context.claims.role_names.clone(),
            permissions: context.claims.permissions.clone(),
            issued_at: now,
            expires_at: now.saturating_add(ASSERTION_LIFETIME),
        }))
    }

    /// The tenant's issuer, the assertion's `iss`.
    #[must_use]
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// The one service the request is forwarded to, the assertion's `aud`.
    #[must_use]
    pub fn audience(&self) -> ServiceId {
        self.audience
    }

    /// The tenant the request was made in.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// The request's correlation id, so the upstream's logs and the
    /// gateway's record of the request can be tied together.
    #[must_use]
    pub fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }

    /// Who made the request.
    #[must_use]
    pub fn caller(&self) -> &AssertedCaller {
        &self.caller
    }

    /// The names of the roles the caller holds.
    #[must_use]
    pub fn roles(&self) -> &[Label] {
        &self.roles
    }

    /// What the caller may do: a person's from the roles they hold now, an
    /// agent's from its task token.
    #[must_use]
    pub fn permissions(&self) -> &[PermissionName] {
        &self.permissions
    }

    /// When it was signed: its `iat` and `nbf`.
    #[must_use]
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    /// When an upstream stops accepting it: its `exp`.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::{ActionApproval, McpGrant};
    use crate::domains::proxy::request::context::{
        AgentLimits, KeyBinding, Metering, UserSignIn, Verified,
    };
    use crate::shared::model::restriction::Restriction;
    use crate::types::{Expiry, Fact, PipelineId};

    fn unlimited() -> AgentLimits {
        AgentLimits {
            intent_envelope: Restriction::Unrestricted,
            mcp: McpGrant::default(),
            resource_scope: Restriction::Unrestricted,
            max_data_class: Restriction::Unrestricted,
            key_binding: KeyBinding::Bearer,
            approval: ActionApproval::NotRequired,
            metering: Metering::Unmetered,
        }
    }

    fn issuer() -> Issuer {
        Issuer::new("https://id.example.com/acme").unwrap()
    }

    fn context_of(caller: Caller) -> PipelineContext {
        let mut context =
            PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new());
        context.route.expected_issuer = Fact::Known(issuer());
        context.claims.role_names = vec![Label::new("role_name", "Support").unwrap()];
        context.claims.permissions = vec![PermissionName::new("tickets:read").unwrap()];
        context
            .authenticate(Verified {
                caller,
                expiry: Expiry::Never,
            })
            .unwrap();
        context
    }

    fn person(user_id: UserId) -> Caller {
        Caller::User {
            user_id,
            sign_in: UserSignIn::Token,
        }
    }

    /// Ann's request was let through to the orders service. The assertion
    /// names her, the tenant's issuer, that one service, her roles and
    /// permissions, and lasts thirty seconds.
    #[test]
    fn a_persons_assertion_names_her_and_what_she_may_do() {
        let ann = UserId::new();
        let orders = ServiceId::new();
        let now = crate::shared::clock::now();
        let mut context = context_of(person(ann));
        context.authorize();

        let assertion = UpstreamAssertion::for_request(&context, orders, now)
            .unwrap()
            .unwrap();

        assert_eq!(assertion.caller(), &AssertedCaller::User { user_id: ann });
        assert_eq!(assertion.caller().subject(), *ann.as_uuid());
        assert_eq!(assertion.issuer(), &issuer());
        assert_eq!(assertion.audience(), orders);
        assert_eq!(assertion.roles()[0].as_str(), "Support");
        assert_eq!(assertion.permissions()[0].as_str(), "tickets:read");
        assert_eq!(
            assertion.expires_at() - assertion.issued_at(),
            ASSERTION_LIFETIME
        );
    }

    /// An agent acting for another agent is asserted as the actor, with
    /// whom it acts for kept typed, so an upstream never reads a machine as
    /// a person.
    #[test]
    fn an_agents_assertion_keeps_whom_it_acts_for_typed() {
        let planner = AgentId::new();
        let fetcher = AgentId::new();
        let delegation = DelegationId::new();
        let mut context = context_of(Caller::Agent {
            agent_id: fetcher,
            delegation_id: delegation,
            acting_for: PrincipalRef::Agent(planner),
            limits: Box::new(unlimited()),
        });
        context.authorize();

        let assertion =
            UpstreamAssertion::for_request(&context, ServiceId::new(), crate::shared::clock::now())
                .unwrap()
                .unwrap();

        assert_eq!(
            assertion.caller(),
            &AssertedCaller::Agent {
                agent_id: fetcher,
                acting_for: PrincipalRef::Agent(planner),
                delegation_id: delegation,
            }
        );
        assert_eq!(assertion.caller().subject(), *planner.as_uuid());
    }

    /// An anonymous request on a public route gets no assertion at all.
    #[test]
    fn an_anonymous_request_gets_no_assertion() {
        let mut context =
            PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new());
        context.authorize();

        let assertion =
            UpstreamAssertion::for_request(&context, ServiceId::new(), crate::shared::clock::now())
                .unwrap();

        assert!(assertion.is_none());
    }

    /// An authenticated request without authorization cannot produce an
    /// upstream identity assertion. Building it is forbidden.
    #[test]
    fn a_request_not_let_through_gets_no_assertion() {
        let context = context_of(person(UserId::new()));

        let assertion =
            UpstreamAssertion::for_request(&context, ServiceId::new(), crate::shared::clock::now());

        assert!(matches!(assertion, Err(DomainError::Forbidden(_))));
    }

    /// An authorized request with an unknown tenant issuer cannot produce an
    /// assertion. The missing issuer is reported as an infrastructure error.
    #[test]
    fn an_assertion_without_the_tenants_issuer_is_refused() {
        let mut context = context_of(person(UserId::new()));
        context.route.expected_issuer = Fact::Unknown;
        context.authorize();

        let assertion =
            UpstreamAssertion::for_request(&context, ServiceId::new(), crate::shared::clock::now());

        assert!(matches!(assertion, Err(DomainError::Infrastructure(_))));
    }
}
