//! The narrowed token the TokenExchange stage hands an upstream in place of
//! the caller's own credential.
//!
//! An upstream that should not hold Ann's session or her OAuth token gets a
//! token of its own: for that one service's audience, carrying only the
//! scopes the route asks for that Ann holds, lasting minutes at most and
//! never past her credential. It names whom the request is for and, for an
//! agent, the agent acting, so the upstream can tell the two apart.
//!
//! It is signed with the tenant's assertion keys, which the gateway holds,
//! and typed `ianua-exchanged+jwt`, so neither the gateway nor the API ever
//! takes it as an access token; an upstream checks it against the published
//! assertion key set. Deny by default: an anonymous request, one the policy
//! did not let through, an unknown issuer, a credential that has run out or
//! a caller holding none of what the route asks for gets no token, and the
//! request is not forwarded.

use time::OffsetDateTime;

use crate::domains::proxy::assertion::AssertedCaller;
use crate::domains::proxy::request::context::{Authentication, Authorization, PipelineContext};
use crate::domains::proxy::stages::stage::TokenExchangeConfig;
use crate::types::{Audience, Expiry, Issuer, PermissionName, Scope, Seconds, TenantId, TokenId};

/// The longest an exchanged token lives. It is made for one forward to one
/// service, so a copy taken off the wire is worth minutes at most; a route
/// cannot be configured for longer.
pub(crate) const EXCHANGED_TOKEN_LIFETIME: Seconds = Seconds::new(300);

/// Why no exchanged token is made for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExchangeRefused {
    /// Nobody proved who they are, so there is nobody to narrow a token for.
    #[error("an anonymous request gets no exchanged token")]
    Anonymous,
    /// The policy has not let the request through.
    #[error("a token is exchanged only for a request the policy let through")]
    NotLetThrough,
    /// The tenant's issuer is not known, so an upstream could not check the
    /// token's `iss`.
    #[error("the tenant's issuer is not known")]
    IssuerUnknown,
    /// The caller's credential has run out.
    #[error("the caller's credential has run out")]
    CredentialExpired,
    /// The caller holds none of the scopes the route asks for.
    #[error("the caller holds none of the scopes the route asks for")]
    NothingHeld,
}

/// What a request proved, read once from its context: whom an exchanged
/// token may speak for, what they hold and until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeGrounds {
    issuer: Issuer,
    tenant_id: TenantId,
    caller: AssertedCaller,
    scopes: Vec<Scope>,
    permissions: Vec<PermissionName>,
    holds_until: Expiry,
}

impl ExchangeGrounds {
    /// What the request `context` holds proved, once the policy let it
    /// through.
    ///
    /// # Errors
    ///
    /// - [`ExchangeRefused::Anonymous`] when nobody proved who they are.
    /// - [`ExchangeRefused::NotLetThrough`] when the policy has not let the
    ///   request through.
    /// - [`ExchangeRefused::IssuerUnknown`] when the tenant's issuer is not
    ///   known.
    pub fn of_request(context: &PipelineContext) -> Result<Self, ExchangeRefused> {
        let Authentication::Authenticated(verified) = context.authentication() else {
            return Err(ExchangeRefused::Anonymous);
        };
        if context.authorization() != Authorization::Granted {
            return Err(ExchangeRefused::NotLetThrough);
        }
        let Some(issuer) = context.route.expected_issuer.known() else {
            return Err(ExchangeRefused::IssuerUnknown);
        };
        Ok(Self {
            issuer: issuer.clone(),
            tenant_id: context.tenant_id,
            caller: AssertedCaller::of(&verified.caller),
            scopes: context.claims.scopes.clone(),
            permissions: context.claims.permissions.clone(),
            holds_until: verified.expiry,
        })
    }

    /// The tenant the request was made in.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Whether the caller holds `scope`: their credential carries it, or
    /// it names a permission they hold.
    fn holds(&self, scope: &Scope) -> bool {
        self.scopes.contains(scope)
            || self
                .permissions
                .iter()
                .any(|permission| permission.as_str() == scope.as_str())
    }
}

/// What a signed exchanged token says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangedToken {
    issuer: Issuer,
    audience: Audience,
    tenant_id: TenantId,
    caller: AssertedCaller,
    scopes: Vec<Scope>,
    token_id: TokenId,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl ExchangedToken {
    /// The token `config` asks for, narrowed to what `grounds` proved, made
    /// at `now` under the fresh id `token_id`.
    ///
    /// It names `config`'s one audience and carries the scopes `config`
    /// asks for that the caller holds, never one more. It lasts `config`'s
    /// lifetime, never past `EXCHANGED_TOKEN_LIFETIME` nor past the
    /// caller's credential.
    ///
    /// # Errors
    ///
    /// - [`ExchangeRefused::CredentialExpired`] when the caller's credential
    ///   has run out by `now`.
    /// - [`ExchangeRefused::NothingHeld`] when the caller holds none of the
    ///   scopes `config` asks for: a token carrying nothing would still say
    ///   who they are to a service that asked for more.
    pub fn narrowed(
        grounds: &ExchangeGrounds,
        config: &TokenExchangeConfig,
        token_id: TokenId,
        now: OffsetDateTime,
    ) -> Result<Self, ExchangeRefused> {
        if grounds.holds_until.has_passed(now) {
            return Err(ExchangeRefused::CredentialExpired);
        }
        let scopes: Vec<Scope> = config
            .scopes
            .iter()
            .filter(|scope| grounds.holds(scope))
            .cloned()
            .collect();
        if scopes.is_empty() {
            return Err(ExchangeRefused::NothingHeld);
        }
        Ok(Self {
            issuer: grounds.issuer.clone(),
            audience: config.target_audience.clone(),
            tenant_id: grounds.tenant_id,
            caller: grounds.caller.clone(),
            scopes,
            token_id,
            issued_at: now,
            expires_at: expiry_of(grounds.holds_until, config.ttl_seconds, now),
        })
    }

    /// The tenant's issuer, the token's `iss`.
    #[must_use]
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// The one upstream audience it is for, its `aud`.
    #[must_use]
    pub fn audience(&self) -> &Audience {
        &self.audience
    }

    /// The tenant the request was made in.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Whom the request is for and, for an agent, the agent acting.
    #[must_use]
    pub fn caller(&self) -> &AssertedCaller {
        &self.caller
    }

    /// The scopes it carries: those the route asks for that the caller
    /// holds.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Its own id, the token's `jti`, by which an upstream spots a replay.
    #[must_use]
    pub fn token_id(&self) -> &TokenId {
        &self.token_id
    }

    /// When it was made: its `iat` and `nbf`.
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

/// When a token made at `now` for `ttl` ends: at the shortest of `ttl`,
/// `EXCHANGED_TOKEN_LIFETIME` and the caller's credential.
fn expiry_of(credential: Expiry, ttl: Seconds, now: OffsetDateTime) -> OffsetDateTime {
    let lifetime = ttl.min(EXCHANGED_TOKEN_LIFETIME).duration();
    let own = now.saturating_add(lifetime);
    credential.instant().map_or(own, |until| own.min(until))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use time::Duration;

    use super::*;
    use crate::domains::agents::authority::capability::{ActionApproval, McpGrant};
    use crate::domains::proxy::request::context::{
        AgentLimits, Caller, KeyBinding, Metering, UserSignIn, Verified,
    };
    use crate::shared::model::restriction::Restriction;
    use crate::types::{
        AgentId, CorrelationId, DelegationId, Fact, PipelineId, PrincipalRef, UserId,
    };

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn scope(name: &str) -> Scope {
        Scope::new(name).unwrap()
    }

    /// A route asking a token for the billing service with `scopes`, for
    /// `ttl` seconds.
    fn billing(scopes: &[&str], ttl: u32) -> TokenExchangeConfig {
        TokenExchangeConfig {
            target_audience: Audience::new("billing-service").unwrap(),
            scopes: scopes.iter().map(|name| scope(name)).collect(),
            ttl_seconds: Seconds::new(ttl),
        }
    }

    fn ann() -> Caller {
        Caller::User {
            user_id: UserId::new(),
            sign_in: UserSignIn::Token,
        }
    }

    /// `caller`'s request, proven until `expiry`, carrying `scopes` and
    /// holding `permissions`, before the policy ran.
    fn proven(
        caller: Caller,
        expiry: Expiry,
        scopes: &[&str],
        permissions: &[&str],
    ) -> PipelineContext {
        let mut context =
            PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new());
        context.route.expected_issuer =
            Fact::Known(Issuer::new("https://id.example.com/acme").unwrap());
        context.claims.scopes = scopes.iter().map(|name| scope(name)).collect();
        context.claims.permissions = permissions
            .iter()
            .map(|name| PermissionName::new(*name).unwrap())
            .collect();
        context.authenticate(Verified { caller, expiry }).unwrap();
        context
    }

    /// `caller`'s request as [`proven`] makes it, let through.
    fn let_through(
        caller: Caller,
        expiry: Expiry,
        scopes: &[&str],
        permissions: &[&str],
    ) -> PipelineContext {
        let mut context = proven(caller, expiry, scopes, permissions);
        context.authorize();
        context
    }

    fn exchanged(
        context: &PipelineContext,
        config: &TokenExchangeConfig,
    ) -> Result<ExchangedToken, ExchangeRefused> {
        let grounds = ExchangeGrounds::of_request(context)?;
        let token_id = TokenId::new("019f0000-0000-7000-8000-0000000000e1").unwrap();
        ExchangedToken::narrowed(&grounds, config, token_id, now())
    }

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

    /// Ann's token carries `invoices:read` and she holds `invoices:pay`
    /// through her roles. The route asks for both and for `invoices:void`.
    /// Her exchanged token is for the billing service alone and carries
    /// the two she holds.
    #[test]
    fn the_token_carries_what_the_route_asks_and_the_caller_holds() {
        let context = let_through(ann(), Expiry::Never, &["invoices:read"], &["invoices:pay"]);
        let config = billing(&["invoices:read", "invoices:pay", "invoices:void"], 60);

        let token = exchanged(&context, &config).unwrap();

        assert_eq!(token.audience().as_str(), "billing-service");
        assert_eq!(
            token.scopes(),
            [scope("invoices:read"), scope("invoices:pay")]
        );
        assert_eq!(token.issuer().as_str(), "https://id.example.com/acme");
        assert_eq!(token.tenant_id(), context.tenant_id);
    }

    /// A route asking a token for a day is held to five minutes, and a
    /// credential running out sooner ends the token with it.
    #[test]
    fn the_token_lives_minutes_and_never_past_the_credential() {
        let config = billing(&["invoices:read"], 86_400);
        let lasting = let_through(ann(), Expiry::Never, &["invoices:read"], &[]);
        let soon = now() + Duration::seconds(40);
        let ending = let_through(ann(), Expiry::At(soon), &["invoices:read"], &[]);

        let long = exchanged(&lasting, &config).unwrap();
        let short = exchanged(&ending, &config).unwrap();

        assert_eq!(long.expires_at() - long.issued_at(), Duration::minutes(5));
        assert_eq!(short.expires_at(), soon);
    }

    /// An agent's token names whom it acts for as the subject and the
    /// agent as the actor, with the delegation it acts under.
    #[test]
    fn an_agents_token_names_whom_it_acts_for_and_the_agent() {
        let (agent, delegation, ann) = (AgentId::new(), DelegationId::new(), UserId::new());
        let caller = Caller::Agent {
            agent_id: agent,
            delegation_id: delegation,
            acting_for: PrincipalRef::User(ann),
            limits: Box::new(unlimited()),
        };
        let context = let_through(caller, Expiry::Never, &[], &["invoices:read"]);

        let token = exchanged(&context, &billing(&["invoices:read"], 60)).unwrap();

        assert_eq!(
            token.caller(),
            &AssertedCaller::Agent {
                agent_id: agent,
                acting_for: PrincipalRef::User(ann),
                delegation_id: delegation,
            }
        );
        assert_eq!(token.caller().subject(), *ann.as_uuid());
    }

    /// An authorized context without an authenticated caller returns
    /// `Anonymous` when asked for an exchanged token.
    #[test]
    fn an_anonymous_request_gets_no_token() {
        let mut context =
            PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new());
        context.authorize();

        let refused = exchanged(&context, &billing(&["invoices:read"], 60));

        assert_eq!(refused, Err(ExchangeRefused::Anonymous));
    }

    /// Ann's authenticated request returns `NotLetThrough` when token
    /// exchange is attempted before authorization.
    #[test]
    fn a_request_the_policy_did_not_let_through_gets_no_token() {
        let context = proven(ann(), Expiry::Never, &["invoices:read"], &[]);

        let refused = exchanged(&context, &billing(&["invoices:read"], 60));

        assert_eq!(refused, Err(ExchangeRefused::NotLetThrough));
    }

    /// An otherwise authorized request with an unknown tenant issuer
    /// returns `IssuerUnknown` instead of an exchanged token.
    #[test]
    fn a_request_without_the_tenants_issuer_gets_no_token() {
        let mut context = let_through(ann(), Expiry::Never, &["invoices:read"], &[]);
        context.route.expected_issuer = Fact::Unknown;

        let refused = exchanged(&context, &billing(&["invoices:read"], 60));

        assert_eq!(refused, Err(ExchangeRefused::IssuerUnknown));
    }

    /// A credential that expired one second earlier returns
    /// `CredentialExpired` instead of an exchanged token.
    #[test]
    fn an_expired_credential_gets_no_token() {
        let context = let_through(
            ann(),
            Expiry::At(now() - Duration::seconds(1)),
            &["invoices:read"],
            &[],
        );

        let refused = exchanged(&context, &billing(&["invoices:read"], 60));

        assert_eq!(refused, Err(ExchangeRefused::CredentialExpired));
    }

    /// Ann's unrelated scope and permission do not satisfy the billing
    /// route's requested scope, so exchange returns `NothingHeld`.
    #[test]
    fn a_caller_holding_nothing_asked_gets_no_token() {
        let context = let_through(ann(), Expiry::Never, &["profile:read"], &["tickets:read"]);

        let refused = exchanged(&context, &billing(&["invoices:read"], 60));

        assert_eq!(refused, Err(ExchangeRefused::NothingHeld));
    }

    fn names() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec("[a-c]:[a-c]", 0..6)
    }

    proptest! {
        /// Whatever the route asks for and the caller holds, the exchanged
        /// token carries only scopes both name: never one the caller does
        /// not hold, never one the route did not ask for.
        #[test]
        fn the_token_is_never_wider_than_the_caller_or_the_route(
            asked in names(),
            carried in names(),
            held in names(),
            ttl in 1u32..=86_400,
        ) {
            let carried: Vec<&str> = carried.iter().map(String::as_str).collect();
            let held: Vec<&str> = held.iter().map(String::as_str).collect();
            let asked: Vec<&str> = asked.iter().map(String::as_str).collect();
            let context = let_through(ann(), Expiry::Never, &carried, &held);

            let Ok(token) = exchanged(&context, &billing(&asked, ttl)) else {
                return Ok(());
            };

            for scope in token.scopes() {
                let name = scope.as_str();
                prop_assert!(asked.contains(&name));
                prop_assert!(carried.contains(&name) || held.contains(&name));
            }
            prop_assert!(token.expires_at() - token.issued_at() <= EXCHANGED_TOKEN_LIFETIME.duration());
        }
    }
}
