//! The pipeline context: the typed data a request carries between stages.
//!
//! Stages read from and write to this context. Each stage sees only what
//! earlier stages have filled in. Each field says which stage sets it.

use crate::domains::agents::authority::capability::{ActionApproval, BudgetKey, RequestBudget};
use crate::domains::agents::authority::intent::IntentEnvelope;
use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authorization::policy::claims::Claim;
use crate::domains::data_classification::level::DataClassLevel;
use crate::domains::proxy::access::decision::TenantRuling;
use crate::domains::proxy::access::question::{Circumstances, DpopBinding, PostureFinding};
use crate::domains::proxy::observation::DecidingRule;
use crate::domains::proxy::request::device::RequestDevice;
use crate::domains::proxy::request::graphql::GraphQlOperation;
use crate::domains::proxy::request::identification::Identification;
use crate::domains::proxy::request::transform::RequestMutation;
use crate::domains::proxy::stages::decision::HeaderEntry;
use crate::domains::routing::backend::upstream::{RouteIdentity, TokenAudience};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::model::restriction::Restriction;
use crate::types::{
    ActionCallId, AgentId, CertificateFingerprint, ConsumerId, CorrelationId, CountryCode,
    DelegationId, Fact, IpAddress, Issuer, Label, PermissionName, PipelineId, PrincipalRef, RoleId,
    RouteId, Scope, SessionId, StreamRouteId, TenantId, TrustedDeviceId, UserAgent, UserId,
};

/// Whether a request's caller has been identified.
///
/// Separate from [`Authorization`], since a public route lets an anonymous
/// caller through.
#[derive(Debug, Clone, Default)]
pub enum Authentication {
    /// Nobody proved who they are.
    #[default]
    Anonymous,
    /// The Identity stage verified the caller's credential.
    Authenticated(Verified),
}

/// A credential the Identity stage verified.
#[derive(Debug, Clone)]
pub struct Verified {
    /// Who it names.
    pub caller: Caller,
    /// When it stops being valid, such as a token's `exp`, or that it never
    /// does. A tunnel opened with it closes then.
    pub expiry: crate::types::Expiry,
}

impl Authentication {
    /// Who the caller is, when the Identity stage proved it.
    #[must_use]
    pub fn caller(&self) -> Option<&Caller> {
        let Self::Authenticated(verified) = self else {
            return None;
        };
        Some(&verified.caller)
    }
}

/// Who a request's verified credential names. It is exactly one kind of
/// caller, with everything that kind always has.
///
/// One value instead of an optional field per kind. So a request can never
/// read as an agent with no delegation, or as a person and a consumer at once.
#[derive(Debug, Clone)]
pub enum Caller {
    /// A person, through one of their tenant accounts.
    User {
        /// The account.
        user_id: UserId,
        /// How they signed in.
        sign_in: UserSignIn,
    },
    /// An agent, under one delegation.
    Agent {
        /// The executing identity proven by the presented task token.
        agent_id: AgentId,
        /// The delegation its task token was minted from. It is the token's
        /// `jti`.
        delegation_id: DelegationId,
        /// Whom it acts for, by kind, from the token's `obo` claim. That is a
        /// person, or another agent one hop down a chain. It stays typed. An
        /// agent widened into a user id would tell an upstream a machine is a
        /// person.
        acting_for: PrincipalRef,
        /// Everything its task token confines it to.
        limits: Box<AgentLimits>,
    },
    /// A consumer outside the platform.
    ///
    /// What it may reach is not kept here. The access decision reads what
    /// its roles give it from the tenant's records, as it does for a
    /// person, and the scopes its credential carries from `claims.scopes`.
    Consumer {
        /// The external machine identity whose current roles determine request access.
        consumer_id: ConsumerId,
        /// Which of its credentials it presented.
        credential: ConsumerCredential,
    },
}

impl Caller {
    /// Who the caller is in the tenant's records.
    #[must_use]
    pub fn principal(&self) -> PrincipalRef {
        match self {
            Self::User { user_id, .. } => PrincipalRef::User(*user_id),
            Self::Agent { agent_id, .. } => PrincipalRef::Agent(*agent_id),
            Self::Consumer { consumer_id, .. } => PrincipalRef::Consumer(*consumer_id),
        }
    }

    /// The budget the caller's requests count against, and every key they
    /// count against, when the caller is an agent whose task token is
    /// metered. Nobody else is counted.
    #[must_use]
    pub fn metered(&self) -> Option<MeteredRequest> {
        let Self::Agent {
            agent_id,
            delegation_id,
            acting_for,
            limits,
        } = self
        else {
            return None;
        };
        let Metering::Metered(budget) = limits.metering else {
            return None;
        };
        Some(MeteredRequest {
            budget,
            keys: BudgetKey::counted_for(*agent_id, *delegation_id, *acting_for),
        })
    }
}

/// What a metered agent's request is counted against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeteredRequest {
    /// The budget its task token states.
    pub budget: RequestBudget,
    /// Every key the request counts against. It is refused once any of them
    /// is spent.
    pub keys: Vec<BudgetKey>,
}

/// How a person's request was signed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSignIn {
    /// Through this session.
    Session(SessionId),
    /// Through a token no session backs.
    Token,
    /// Through a workflow run acting for them, with a pass made for this one
    /// call of a Protected apps step. The person is not there, so they
    /// proved nothing more than signing in at all.
    WorkflowRun(ActionCallId),
}

/// Which of a consumer's credentials a request presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerCredential {
    /// A shared bearer secret authenticated the external client.
    ApiKey,
    /// A client certificate.
    Certificate,
    /// A token the consumer was issued.
    Token,
}

/// Whether the Policy stage let a request through.
///
/// Who the caller is and whether they are let through are separate
/// questions. A public route lets an anonymous caller through, and a
/// signed-in caller can still be refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Authorization {
    /// The Policy stage has not allowed the request, or has not run yet.
    #[default]
    NotGranted,
    /// The Policy stage allowed the request.
    Granted,
}

/// Data gathered as the request passes through pipeline stages.
///
/// The Identity stage fills in `authentication`, and the Policy stage
/// `authorization`. The GeoFence stage fills in `country_code`. The DataClassify stage fills in `classification_levels`.
/// Each stage can read what earlier stages wrote.
#[derive(Debug, Clone)]
pub struct PipelineContext {
    /// The tenant this request targets.
    pub tenant_id: TenantId,
    /// Which pipeline runs, taken from the matched route.
    ///
    /// Carried on the context instead of looked up per tenant, because a
    /// tenant holds several and only the route knows which one applies.
    pub pipeline_id: PipelineId,
    /// Correlation ID given when the request arrives, and carried through all
    /// stages.
    pub correlation_id: CorrelationId,
    /// The client's IP address, as the edge saw it.
    pub ip_address: Fact<IpAddress>,
    /// The client's `User-Agent` header.
    pub user_agent: Fact<UserAgent>,
    /// The client's country. The GeoFence stage sets it.
    pub country_code: Fact<CountryCode>,
    /// Data classification levels found on the request. The DataClassify
    /// stage sets them.
    pub classification_levels: Vec<DataClassLevel>,
    /// What the pipeline changes about the forwarded request: headers and
    /// query parameters added, overwritten or dropped. Every stage that
    /// returns [`StageDecision::Transform`](crate::domains::proxy::stages::decision::StageDecision::Transform)
    /// adds to it.
    pub request_mutation: RequestMutation,
    /// Headers to add to the response sent back to the client.
    ///
    /// Response-side stages such as `Cors` and `SecurityHeaders` set them.
    /// They go out on every answer the pipeline ends in: a forwarded
    /// response, a ready one, and a refusal or challenge too. So a stage
    /// that refuses with a 429 puts `Retry-After` and `RateLimit-*` here
    /// before it returns its denial, and the client learns when to come
    /// back; a browser reading a refusal still gets its CORS headers.
    pub response_headers: Vec<HeaderEntry>,
    /// The client certificate fingerprint from the mTLS handshake. The
    /// server layer sets it.
    pub client_cert_fingerprint: Fact<CertificateFingerprint>,
    /// What the matched route asks of the request. The proxy sets it after
    /// route matching.
    pub route: RouteRequirements,
    /// What the caller's credential carries. The Identity stage sets it.
    pub claims: CallerClaims,
    /// Whether the Identity stage proved who the caller is.
    ///
    /// Private, so it is written only through
    /// [`authenticate`](Self::authenticate), and only once.
    authentication: Authentication,
    /// Whether the Policy stage let the request through.
    ///
    /// Private, so it is written only through
    /// [`authorize`](Self::authorize). Nothing takes it back. A later stage
    /// refuses the request through its own decision instead.
    authorization: Authorization,
    /// Where the response comes from: the upstream, or a stage that
    /// produced one without it.
    ///
    /// When a stage has one ready, the proxy serves it directly instead of
    /// forwarding. The `Cache` stage sets it on a hit, and `Terminate` sets
    /// it whenever it runs. Later stages still run, and `response_headers`
    /// still applies on top, as for a forwarded response.
    pub response: ResponseSource,
    /// Who the Identity stage proved the caller is, whole: with what the
    /// records give them, when that was read, and whether the request
    /// proved its credential's key. The Policy stage decides on this rather
    /// than reading the records again.
    ///
    /// Private, so it is written only through
    /// [`identify`](Self::identify), with `authentication` and `claims`, so
    /// the three never tell two stories.
    identification: Identification,
    /// The device the request comes from, as a posture check reads it. The
    /// Identity stage sets it.
    pub device: RequestDevice,
    /// What a device posture check found. The DevicePosture stage sets it.
    pub posture: PostureFinding,
    /// What the tenant's own policy had to do with the access decision. The
    /// Policy stage sets it, and the request record names the version that
    /// ruled.
    pub tenant_ruling: TenantRuling,
    /// The tenant policy rule that refused the request, when a named rule
    /// did. The Policy stage sets it, and the request record names it.
    pub refusing_rule: DecidingRule,
    /// The GraphQL operation the GraphQl stage read from the request. The
    /// Cache stage keys on its fingerprint, and keeps only a query's answer.
    pub graphql_operation: Fact<GraphQlOperation>,
}

/// Where a request's response comes from.
#[derive(Debug, Clone, Default)]
pub enum ResponseSource {
    /// Forward the request and serve what the upstream answers.
    #[default]
    Upstream,
    /// Serve this response a stage produced. Nothing is forwarded.
    Ready(ReadyResponse),
}

impl ResponseSource {
    /// The response a stage produced, when one did.
    #[must_use]
    pub fn ready(&self) -> Option<&ReadyResponse> {
        match self {
            Self::Ready(response) => Some(response),
            Self::Upstream => None,
        }
    }
}

/// What the matched route asks of a request.
#[derive(Debug, Clone, Default)]
pub struct RouteRequirements {
    /// The issuer a presented token's `iss` must name. Unknown until the
    /// proxy sets it from the tenant. While unknown, no token is accepted. A
    /// token is never let through unchecked for want of an issuer to check
    /// it against.
    pub expected_issuer: Fact<Issuer>,
    /// Which tokens the matched route accepts as identity, by audience.
    /// A token's `aud` claim is checked against it.
    pub token_audience: TokenAudience,
    /// What identity the matched route takes: a token or a client
    /// certificate. On a certificate route a bearer token does not satisfy
    /// the Identity stage, even a fully valid one.
    pub identity: RouteIdentity,
    /// The route policy resolved after route matching. Unknown until the
    /// proxy sets it, and a request whose policy is unknown is refused.
    pub policy: Fact<crate::domains::routing::policy::RoutePolicy>,
    /// The kind of action the matched route declares it takes. Set with
    /// `policy`.
    pub action_class: crate::types::DeclaredAction,
    /// The matched route, which a workflow run's pass must name. Unknown
    /// until the proxy sets it, and while unknown no pass is taken.
    pub route_id: Fact<RouteId>,
    /// The stream route a connection reached, which a Protected data run's
    /// pass must name. Unknown on every request to a route, so no pass made
    /// for a stream route is taken there.
    pub stream_route_id: Fact<StreamRouteId>,
    /// Whether workflows may call the matched route, or reach the stream
    /// route. A run's pass is taken only where they may.
    pub workflow_use: crate::domains::routing::route::WorkflowUse,
}

/// Everything an agent's task token confines it to, each one stated. A
/// token that leaves one out is not read as one with no limit.
#[derive(Debug, Clone)]
pub struct AgentLimits {
    /// The action classes the token is confined to, from the `ienv` claim.
    ///
    /// The Policy stage denies actions outside it, so each request is held
    /// to the task's stated purpose.
    pub intent_envelope: Restriction<IntentEnvelope>,
    /// What the token reaches on an MCP server, from the `mcp` claim.
    ///
    /// A token naming none reaches nothing, not everything.
    pub mcp: crate::domains::agents::authority::capability::McpGrant,
    /// The URL path prefixes the token is confined to, from the `rsc` claim.
    ///
    /// The Policy stage denies any request whose path is not under one of
    /// them.
    pub resource_scope: Restriction<crate::domains::agents::authority::capability::ResourceScope>,
    /// The most sensitive data the agent may reach, from the `dcl` claim.
    pub max_data_class: Restriction<DataClassLevel>,
    /// What the token must be presented with, from the `cnf.jwk` claim.
    ///
    /// That is a proof of possession of this key on every request, or
    /// nothing more.
    pub key_binding: KeyBinding,
    /// Whether a person approves each action, from the `apr` claim.
    ///
    /// When they do, the proxy forwards nothing a person has not approved.
    pub approval: ActionApproval,
    /// Whether the token's requests are counted against a budget. A tunnel
    /// carries uses nothing can count, so a metered token may not open one.
    pub metering: Metering,
}

/// What a task token must be presented with.
#[derive(Debug, Clone)]
pub enum KeyBinding {
    /// Nothing more. Whoever holds the token may use it.
    Bearer,
    /// A `DPoP` proof of possession of this agent credential key.
    Key(crate::domains::crypto::jwk::JwkComponents),
}

/// Whether an agent's requests are counted against a budget, and which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metering {
    /// No budget counts them.
    Unmetered,
    /// Each request is counted against this budget, from the `bmax` and
    /// `bwin` claims: the agent's, and the delegation's too when a person
    /// granted it.
    Metered(crate::domains::agents::authority::capability::RequestBudget),
}

/// What the caller's credential carries.
#[derive(Debug, Clone, Default)]
pub struct CallerClaims {
    /// Scopes the verified token carries, from its `scope` or `scp` claim.
    ///
    /// The Identity stage sets them. Empty for credentials without scopes.
    pub scopes: Vec<Scope>,
    /// What the caller may do, written out.
    ///
    /// It comes from the roles they hold, or from an agent token's
    /// `permissions` claim. The Identity stage sets it. Empty for credentials
    /// without any.
    pub permissions: Vec<PermissionName>,
    /// The names of the roles the caller holds, directly or through groups.
    ///
    /// The Identity stage sets them. Empty for callers without roles.
    pub role_names: Vec<Label>,
    /// The ids of the roles the caller holds, directly or through groups.
    ///
    /// The Identity stage sets them. Policy conditions match on these, since
    /// a role's name can change.
    pub role_ids: Vec<RoleId>,
    /// The caller's authentication assurance level, from the verified
    /// token's `aal` claim. The Identity stage sets it.
    ///
    /// `Fact::Unknown` when the token carries no such claim, the request is
    /// unauthenticated, or the credential is not a person's, such as a
    /// service key or an agent task token. Unknown means *no assurance*, not
    /// `Aal1`. So a token without the claim never satisfies a route that
    /// asks for `StepUp`. The `StepUp` stage's evaluator explains why this
    /// matters.
    pub current_aal: Fact<AssuranceLevel>,
    /// The claims the verified credential asserts about the caller, such as
    /// a department, which a tenant's policy rules can compare. The
    /// Identity stage sets them.
    ///
    /// `Fact::Unknown` when the credential is of a kind that carries no
    /// such claims, such as an API key, a client certificate or an app
    /// session cookie. A known list that lacks a claim says the caller does
    /// not hold it.
    pub asserted: Fact<Vec<Claim>>,
    /// The trusted device the person's session was signed in from, from
    /// the session token's `did` claim. The Identity stage sets it, and the
    /// DevicePosture stage reads it when no device certificate names the
    /// device.
    ///
    /// `Fact::Unknown` for a session signed in from no remembered device,
    /// for a credential no session backs, such as an OAuth grant's access
    /// token held by an app's server, and for every caller who is not a
    /// person.
    pub signed_in_from: Fact<TrustedDeviceId>,
}

/// A response the proxy can serve without asking an upstream.
///
/// Two stages produce one, for opposite reasons. `Cache` already has the
/// upstream's answer. `Terminate` runs because the tenant does not want the
/// upstream asked. The proxy does not need to tell them apart, since either
/// way there is nothing left to forward.
///
/// `Debug` shows the status, the header names and the body's length. It
/// never shows header values or the body. An upstream's answer may carry
/// tokens, cookies or personal data, and a debug print of the context would
/// log it.
#[derive(Clone)]
pub struct ReadyResponse {
    /// The stored HTTP status code.
    pub status: u16,
    /// The stored response headers.
    pub headers: Vec<HeaderEntry>,
    /// The stored response body.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for ReadyResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|h| h.name().as_str()).collect();
        f.debug_struct("ReadyResponse")
            .field("status", &self.status)
            .field("headers", &names)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl PipelineContext {
    /// An empty context for the start of a pipeline run.
    ///
    /// The proxy gives `correlation_id` when the request arrives. It is
    /// carried through every later stage, so logs and traces can be tied
    /// together.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        pipeline_id: PipelineId,
        correlation_id: CorrelationId,
    ) -> Self {
        Self {
            tenant_id,
            pipeline_id,
            correlation_id,
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            country_code: Fact::Unknown,
            classification_levels: Vec::new(),
            request_mutation: RequestMutation::default(),
            response_headers: Vec::new(),
            client_cert_fingerprint: Fact::Unknown,
            route: RouteRequirements::default(),
            claims: CallerClaims::default(),
            authentication: Authentication::Anonymous,
            authorization: Authorization::NotGranted,
            response: ResponseSource::Upstream,
            identification: Identification::Anonymous,
            device: RequestDevice::Unknown,
            posture: PostureFinding::NotAsked,
            tenant_ruling: TenantRuling::NotReached,
            refusing_rule: DecidingRule::Unnamed,
            graphql_operation: Fact::Unknown,
        }
    }

    /// Records who the Identity stage proved the caller is.
    ///
    /// A proven caller becomes the request's authenticated caller, as
    /// [`authenticate`](Self::authenticate) records it, and what their
    /// credential carries becomes `claims`; the whole proof is kept for the
    /// Policy stage. Nobody leaves the request anonymous. Works once, like
    /// `authenticate`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the request is already
    ///   authenticated. What it holds stays.
    pub fn identify(&mut self, identification: Identification) -> Result<(), DomainError> {
        if let Authentication::Authenticated(_) = self.authentication {
            return Err(DomainError::invalid_transition(message!(
                "proxy-the-request-s-caller-was-already",
                "the request's caller was already authenticated"
            )));
        }
        if let Identification::Proven(proven) = &identification {
            self.authenticate(proven.verified.clone())?;
            self.claims = proven.claims.clone();
        }
        self.identification = identification;
        Ok(())
    }

    /// Who the Identity stage proved the caller is, whole.
    #[must_use]
    pub fn identification(&self) -> &Identification {
        &self.identification
    }

    /// Whether the request proved possession of the key its credential is
    /// bound to.
    #[must_use]
    pub fn binding(&self) -> DpopBinding {
        self.identification.binding()
    }

    /// What is known around the request, for the access decision: what the
    /// stages before Policy wrote here. Whatever none found is unknown,
    /// which the decision never reads as harmless.
    #[must_use]
    pub fn circumstances(&self) -> Circumstances {
        Circumstances {
            country: self.country_code.clone(),
            source_ip: Fact::from_option(
                self.ip_address
                    .known()
                    .and_then(|address| address.as_str().parse().ok()),
            ),
            device: Fact::Unknown,
            risk: Fact::Unknown,
            sensitivity: Fact::Unknown,
            binding: self.binding(),
            posture: self.posture,
        }
    }

    /// Whether the Identity stage proved who the caller is.
    #[must_use]
    pub fn authentication(&self) -> &Authentication {
        &self.authentication
    }

    /// Records the credential the Identity stage verified.
    ///
    /// Only the Identity stage calls this, with what it checked. It is the
    /// only way a request becomes authenticated, and it works once. A later
    /// stage that calls it again is refused, so no stage can swap the caller
    /// the Identity stage proved for one of its own.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the request is already
    ///   authenticated. The caller it holds stays.
    pub fn authenticate(&mut self, verified: Verified) -> Result<(), DomainError> {
        if let Authentication::Authenticated(_) = self.authentication {
            return Err(DomainError::invalid_transition(message!(
                "proxy-the-request-s-caller-was-already",
                "the request's caller was already authenticated"
            )));
        }
        self.authentication = Authentication::Authenticated(verified);
        Ok(())
    }

    /// Whether the Policy stage let the request through.
    ///
    /// A request is not let through until the Policy stage says so. One it
    /// never reached, or one that errored before it, reads as not granted.
    #[must_use]
    pub fn authorization(&self) -> Authorization {
        self.authorization
    }

    /// Records that the Policy stage allowed the request.
    ///
    /// Only the Policy stage calls this, once its policy allowed the request.
    /// Calling it again changes nothing. Nothing takes it back: a later stage
    /// that refuses the request does so through its own decision.
    pub fn authorize(&mut self) {
        self.authorization = Authorization::Granted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::agents::authority::capability::McpGrant;
    use crate::types::{Expiry, HeaderName, HeaderValue, Seconds};

    fn context() -> PipelineContext {
        PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new())
    }

    fn verified(user_id: UserId) -> Verified {
        Verified {
            caller: Caller::User {
                user_id,
                sign_in: UserSignIn::Token,
            },
            expiry: Expiry::Never,
        }
    }

    fn caller_id(ctx: &PipelineContext) -> Option<UserId> {
        match ctx.authentication().caller()? {
            Caller::User { user_id, .. } => Some(*user_id),
            Caller::Agent { .. } | Caller::Consumer { .. } => None,
        }
    }

    /// A request arrives. Until the Identity stage records what it verified,
    /// nobody is named as its caller.
    #[test]
    fn a_new_request_is_anonymous_until_authenticated() {
        let mut ctx = context();
        let ann = UserId::new();
        assert!(ctx.authentication().caller().is_none());

        ctx.authenticate(verified(ann)).unwrap();

        assert_eq!(caller_id(&ctx), Some(ann));
    }

    /// Authenticating a second caller after Ann returns an invalid
    /// transition and retains Ann as the request's caller.
    #[test]
    fn a_second_authentication_cannot_swap_the_caller() {
        let mut ctx = context();
        let ann = UserId::new();
        ctx.authenticate(verified(ann)).unwrap();

        let result = ctx.authenticate(verified(UserId::new()));

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert_eq!(caller_id(&ctx), Some(ann));
    }

    /// A newly created request context starts with authorization not
    /// granted.
    #[test]
    fn a_new_request_is_not_let_through() {
        let ctx = context();

        assert_eq!(ctx.authorization(), Authorization::NotGranted);
    }

    /// Ann's request passes the Policy stage, which records that it let her
    /// through.
    #[test]
    fn the_policy_stage_lets_a_request_through() {
        let mut ctx = context();
        ctx.authenticate(verified(UserId::new())).unwrap();

        ctx.authorize();

        assert_eq!(ctx.authorization(), Authorization::Granted);
    }

    /// Ann's request is let through, and the record is written a second
    /// time. It still reads as let through, once.
    #[test]
    fn letting_a_request_through_twice_changes_nothing() {
        let mut ctx = context();
        ctx.authorize();

        ctx.authorize();

        assert_eq!(ctx.authorization(), Authorization::Granted);
    }

    /// Authenticating a caller leaves the request's authorization not
    /// granted.
    #[test]
    fn being_authenticated_does_not_let_a_request_through() {
        let mut ctx = context();

        ctx.authenticate(verified(UserId::new())).unwrap();

        assert_eq!(ctx.authorization(), Authorization::NotGranted);
    }

    fn proof_of(user_id: UserId, binding: DpopBinding) -> Identification {
        Identification::Proven(Box::new(
            crate::domains::proxy::request::identification::Proven {
                verified: verified(user_id),
                claims: CallerClaims {
                    current_aal: Fact::Known(AssuranceLevel::Aal2),
                    ..CallerClaims::default()
                },
                held: crate::domains::authorization::held::Held::default(),
                established_at: crate::shared::clock::now(),
                binding,
            },
        ))
    }

    /// The Identity stage proves Ann with a key-bound token. The request
    /// names her as its caller, carries her claims, and reads as bound.
    #[test]
    fn identifying_a_caller_authenticates_the_request_with_their_claims() {
        let mut ctx = context();
        let ann = UserId::new();

        ctx.identify(proof_of(ann, DpopBinding::Bound)).unwrap();

        assert_eq!(caller_id(&ctx), Some(ann));
        assert_eq!(ctx.claims.current_aal, Fact::Known(AssuranceLevel::Aal2));
        assert_eq!(ctx.binding(), DpopBinding::Bound);
        assert!(matches!(ctx.identification(), Identification::Proven(_)));
    }

    /// Attempts to replace Ann's identification with anonymous or another
    /// user both return an invalid transition, retaining Ann and her unbound
    /// status.
    #[test]
    fn an_identified_request_cannot_be_identified_again() {
        let mut ctx = context();
        let ann = UserId::new();
        ctx.identify(proof_of(ann, DpopBinding::Unbound)).unwrap();

        let anonymous = ctx.identify(Identification::Anonymous);
        let mallory = ctx.identify(proof_of(UserId::new(), DpopBinding::Bound));

        assert!(matches!(anonymous, Err(DomainError::InvalidTransition(_))));
        assert!(matches!(mallory, Err(DomainError::InvalidTransition(_))));
        assert_eq!(caller_id(&ctx), Some(ann));
        assert_eq!(ctx.binding(), DpopBinding::Unbound);
    }

    /// Nobody proven leaves the request anonymous and unbound.
    #[test]
    fn identifying_nobody_leaves_the_request_anonymous() {
        let mut ctx = context();

        ctx.identify(Identification::Anonymous).unwrap();

        assert!(ctx.authentication().caller().is_none());
        assert_eq!(ctx.binding(), DpopBinding::Unbound);
    }

    /// A new request has no posture finding, no ruling and no device, and
    /// what the access decision is told around it says so.
    #[test]
    fn a_new_request_knows_nothing_around_it() {
        let ctx = context();

        let around = ctx.circumstances();

        assert_eq!(around.posture, PostureFinding::NotAsked);
        assert_eq!(around.binding, DpopBinding::Unbound);
        assert_eq!(around.source_ip, Fact::Unknown);
        assert_eq!(ctx.tenant_ruling, TenantRuling::NotReached);
        assert_eq!(ctx.device, RequestDevice::Unknown);
    }

    /// An agent on a budget a person granted counts against itself and the
    /// delegation; a person is never metered.
    #[test]
    fn only_a_metered_agent_counts_against_a_budget() {
        let budget = RequestBudget::new(100, Seconds::new(60)).unwrap();
        let (agent_id, delegation_id) = (AgentId::new(), DelegationId::new());
        let agent = Caller::Agent {
            agent_id,
            delegation_id,
            acting_for: PrincipalRef::User(UserId::new()),
            limits: Box::new(metered_limits(budget)),
        };
        let ann = Caller::User {
            user_id: UserId::new(),
            sign_in: UserSignIn::Token,
        };

        assert_eq!(
            agent.metered(),
            Some(MeteredRequest {
                budget,
                keys: vec![
                    BudgetKey::Agent(agent_id),
                    BudgetKey::Delegation(delegation_id)
                ],
            })
        );
        assert_eq!(ann.metered(), None);
    }

    /// A bearer agent token carrying a request budget and no MCP grant.
    fn metered_limits(budget: RequestBudget) -> AgentLimits {
        AgentLimits {
            intent_envelope: Restriction::Unrestricted,
            mcp: McpGrant::default(),
            resource_scope: Restriction::Unrestricted,
            max_data_class: Restriction::Unrestricted,
            key_binding: KeyBinding::Bearer,
            approval: ActionApproval::NotRequired,
            metering: Metering::Metered(budget),
        }
    }

    /// A cached answer holds `set-cookie: session=s3cret` and a social
    /// security number. Its `Debug` shows the header name but neither the
    /// cookie nor the body.
    #[test]
    fn a_ready_response_never_prints_its_body_or_header_values() {
        let ready = ReadyResponse {
            status: 200,
            headers: vec![HeaderEntry::new(
                HeaderName::new("set-cookie").unwrap(),
                HeaderValue::new("session=s3cret").unwrap(),
            )],
            body: b"{\"ssn\":\"123-45-6789\"}".to_vec(),
        };

        let printed = format!("{ready:?}");

        assert!(printed.contains("set-cookie"));
        assert!(!printed.contains("s3cret"));
        assert!(!printed.contains("123-45"));
    }
}
