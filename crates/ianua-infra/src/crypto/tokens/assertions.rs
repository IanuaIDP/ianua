//! The identity assertion the gateway hands an upstream as
//! `X-Ianua-Assertion`, written out as a JWT and signed with the tenant's
//! assertion key.
//!
//! It is typed `ianua-assertion+jwt`, so no check of access tokens takes
//! it, and signed with a key of its own, published apart from the tenant's
//! JWKS, so a relying party holding the JWKS never believes one either.
//! The claims are what the domain's [`UpstreamAssertion`] says, written in
//! the names upstreams read: `iss`, `aud` (the service's id), `sub`, `tid`,
//! `cid`, `kind`, and for an agent `act`, `obo` and `jti` (the delegation),
//! with `roles`, `permissions`, `iat`, `nbf` and `exp`.
//!
//! The same key signs the narrowed token a TokenExchange stage hands an
//! upstream, typed `ianua-exchanged+jwt`: what the domain's
//! [`ExchangedToken`] says, as `iss`, `aud` (the upstream's audience),
//! `sub`, `tid`, `kind`, `scope`, `jti` (its own id), `iat`, `nbf`, `exp`,
//! and for an agent `act` as RFC 8693 writes it (`{"sub": <agent>}`),
//! `obo` and `dlg` (the delegation). An upstream checks it against the
//! assertion key set the tenant publishes.
//!
//! The egress gateway reads one back with [`Pkcs8AssertionVerifier`], to
//! hold an outbound call against the agent whose request caused it.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::crypto::{AssertionKeyStore, AssertionSigner, AssertionVerifier};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::crypto::assertion_key::AssertionSigningKey;
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::domains::crypto::key_status::KeyStatus;
use ianua_domain::domains::proxy::assertion::{AssertedCaller, UpstreamAssertion};
use ianua_domain::domains::proxy::exchange::ExchangedToken;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    AgentId, ConsumerId, DelegationId, Label, PermissionName, PrincipalRef, Scope, UserId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::jws::{Compact, PrivateKey, PublicKey, TokenHeader, signed};
use crate::crypto::tokens::claims::{Times, refused};

/// The caller kind and optional delegation fields shared by both token shapes.
struct CallerClaims {
    kind: &'static str,
    actor: Option<Uuid>,
    acting_for: Option<String>,
    delegation: Option<Uuid>,
}

impl CallerClaims {
    /// Maps the asserted caller without granting fields to a different caller kind.
    fn of(caller: &AssertedCaller) -> Self {
        let (kind, actor, acting_for, delegation) = match caller {
            AssertedCaller::User { .. } => ("user", None, None, None),
            AssertedCaller::Agent {
                agent_id,
                acting_for,
                delegation_id,
            } => (
                "agent",
                Some(*agent_id.as_uuid()),
                Some(acting_for.label()),
                Some(*delegation_id.as_uuid()),
            ),
            AssertedCaller::Consumer { .. } => ("consumer", None, None, None),
        };
        Self {
            kind,
            actor,
            acting_for,
            delegation,
        }
    }
}

/// What an assertion says, as written in the token.
#[derive(Debug, Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    aud: Uuid,
    sub: Uuid,
    tid: Uuid,
    cid: Uuid,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    act: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    obo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<Uuid>,
    roles: Vec<&'a str>,
    permissions: Vec<&'a str>,
    #[serde(flatten)]
    times: Times,
}

impl<'a> AssertionClaims<'a> {
    /// The claims `assertion` is written as.
    fn of(assertion: &'a UpstreamAssertion) -> Self {
        let caller = assertion.caller();
        let identity = CallerClaims::of(caller);
        let issued_at = assertion.issued_at().unix_timestamp();
        Self {
            iss: assertion.issuer().as_str(),
            aud: *assertion.audience().as_uuid(),
            sub: caller.subject(),
            tid: *assertion.tenant_id().as_uuid(),
            cid: *assertion.correlation_id().as_uuid(),
            kind: identity.kind,
            act: identity.actor,
            obo: identity.acting_for,
            jti: identity.delegation,
            roles: assertion.roles().iter().map(Label::as_str).collect(),
            permissions: assertion
                .permissions()
                .iter()
                .map(PermissionName::as_str)
                .collect(),
            times: Times {
                exp: Some(assertion.expires_at().unix_timestamp()),
                nbf: Some(issued_at),
                iat: Some(issued_at),
            },
        }
    }
}

/// Who acts in an exchanged token, written as RFC 8693 4.1 has it.
#[derive(Debug, Serialize)]
struct Actor {
    sub: Uuid,
}

/// What an exchanged token says, as written in the token.
#[derive(Debug, Serialize)]
struct ExchangedClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: Uuid,
    tid: Uuid,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    act: Option<Actor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    obo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dlg: Option<Uuid>,
    scope: String,
    jti: &'a str,
    #[serde(flatten)]
    times: Times,
}

impl<'a> ExchangedClaims<'a> {
    /// The claims `token` is written as.
    fn of(token: &'a ExchangedToken) -> Self {
        let caller = token.caller();
        let identity = CallerClaims::of(caller);
        let scope: Vec<&str> = token.scopes().iter().map(Scope::as_str).collect();
        let issued_at = token.issued_at().unix_timestamp();
        Self {
            iss: token.issuer().as_str(),
            aud: token.audience().as_str(),
            sub: caller.subject(),
            tid: *token.tenant_id().as_uuid(),
            kind: identity.kind,
            act: identity.actor.map(|sub| Actor { sub }),
            obo: identity.acting_for,
            dlg: identity.delegation,
            scope: scope.join(" "),
            jti: token.token_id().as_str(),
            times: Times {
                exp: Some(token.expires_at().unix_timestamp()),
                nbf: Some(issued_at),
                iat: Some(issued_at),
            },
        }
    }
}

/// The signer of upstream identity assertions and exchanged tokens with
/// the tenant's assertion key.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pkcs8AssertionSigner;

impl Pkcs8AssertionSigner {
    /// `claims` signed with `key` as a JWT of `typ`.
    fn signed_as<C: Serialize>(
        claims: &C,
        typ: JwtType,
        key: &AssertionSigningKey,
    ) -> Result<Secret, DomainError> {
        let claims = serde_json::to_string(claims).map_err(DomainError::infra)?;
        let private = PrivateKey::from_pem(key.algorithm(), key.private_key().expose())
            .map_err(DomainError::infra)?;
        signed(
            &claims,
            TokenHeader::new(typ, key.kid().as_str(), key.algorithm()),
            &private,
        )
        .map(Secret::new)
        .map_err(DomainError::infra)
    }
}

#[async_trait]
impl AssertionSigner for Pkcs8AssertionSigner {
    async fn sign(
        &self,
        assertion: &UpstreamAssertion,
        key: &AssertionSigningKey,
    ) -> Result<Secret, DomainError> {
        Self::signed_as(
            &AssertionClaims::of(assertion),
            JwtType::UpstreamAssertion,
            key,
        )
    }

    async fn sign_exchanged(
        &self,
        token: &ExchangedToken,
        key: &AssertionSigningKey,
    ) -> Result<Secret, DomainError> {
        Self::signed_as(&ExchangedClaims::of(token), JwtType::ExchangedToken, key)
    }
}

/// Signs the gateway's message signatures, over the claims the response
/// stages wrote, with the tenant's assertion key: the key the gateway owns,
/// never the tenant's token signing key. Typed `ianua-signature+jwt`, so
/// neither an access token check nor an assertion check takes one.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Pkcs8MessageSigner;

impl Pkcs8MessageSigner {
    /// `claims_json` signed with `key`, in compact form.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the key does not read or
    /// the signing fails.
    pub(crate) fn sign(
        &self,
        claims_json: &str,
        key: &AssertionSigningKey,
    ) -> Result<String, DomainError> {
        let private = PrivateKey::from_pem(key.algorithm(), key.private_key().expose())
            .map_err(DomainError::infra)?;
        signed(
            claims_json,
            TokenHeader::new(
                JwtType::MessageSignature,
                key.kid().as_str(),
                key.algorithm(),
            ),
            &private,
        )
        .map_err(DomainError::infra)
    }
}

/// What an assertion says, as the egress gateway reads it back: the tenant,
/// the kind of caller and who that is, and the times.
#[derive(Debug, Deserialize)]
struct ReadClaims {
    sub: Uuid,
    tid: Uuid,
    kind: String,
    #[serde(default)]
    act: Option<Uuid>,
    #[serde(default)]
    obo: Option<String>,
    #[serde(default)]
    jti: Option<Uuid>,
    #[serde(flatten)]
    times: Times,
}

impl ReadClaims {
    /// The caller the claims name, refused when its kind is unknown or an
    /// agent's claims lack the agent, whom it acts for, or its delegation.
    fn caller(self) -> Result<AssertedCaller, DomainError> {
        match self.kind.as_str() {
            "user" => Ok(AssertedCaller::User {
                user_id: UserId::from_uuid(self.sub),
            }),
            "consumer" => Ok(AssertedCaller::Consumer {
                consumer_id: ConsumerId::from_uuid(self.sub),
            }),
            "agent" => self.agent(),
            _ => Err(refused("the assertion names a caller of no known kind")),
        }
    }

    /// The agent the claims name, with whom it acts for and its delegation.
    fn agent(self) -> Result<AssertedCaller, DomainError> {
        let incomplete = || refused("the assertion names an agent without its delegation");
        let (Some(act), Some(obo), Some(jti)) = (self.act, self.obo, self.jti) else {
            return Err(incomplete());
        };
        Ok(AssertedCaller::Agent {
            agent_id: AgentId::from_uuid(act),
            acting_for: PrincipalRef::from_label(&obo).map_err(|_| incomplete())?,
            delegation_id: DelegationId::from_uuid(jti),
        })
    }
}

/// The check of upstream identity assertions against the tenant's own
/// assertion keys, for the egress gateway.
///
/// The key is the one the header names among the tenant's keys that are
/// not revoked: a rotated key no longer signs, so it checks only what it
/// signed before, and the assertion's own short life bounds that.
pub struct Pkcs8AssertionVerifier {
    keys: Arc<dyn AssertionKeyStore>,
}

impl TenantScoped for Pkcs8AssertionVerifier {}

impl Pkcs8AssertionVerifier {
    /// A verifier reading the tenant's assertion keys from `keys`.
    #[must_use]
    pub fn new(keys: Arc<dyn AssertionKeyStore>) -> Self {
        Self { keys }
    }

    /// The public key of `tenant_id` that `token` names, while it is not
    /// revoked.
    async fn checking_key(
        &self,
        tenant_id: &ScopedTenant,
        token: &Compact,
    ) -> Result<PublicKey, DomainError> {
        let kid = token
            .header()
            .kid
            .as_deref()
            .ok_or_else(|| refused("the assertion names no key"))?;
        let set = self
            .keys
            .find(tenant_id)
            .await?
            .ok_or_else(|| refused("the tenant has no assertion keys"))?;
        let key = set
            .keys()
            .iter()
            .filter(|key| key.status() != KeyStatus::Revoked)
            .find(|key| key.kid().as_str() == kid)
            .ok_or_else(|| refused("the assertion names no key of the tenant"))?;
        PublicKey::from_pem(key.algorithm(), key.public_key().as_str()).map_err(DomainError::infra)
    }
}

#[async_trait]
impl AssertionVerifier for Pkcs8AssertionVerifier {
    async fn caller(
        &self,
        tenant_id: &ScopedTenant,
        assertion: &Secret,
    ) -> Result<AssertedCaller, DomainError> {
        let token =
            Compact::parse(assertion.expose()).map_err(|_| refused("the assertion is no JWT"))?;
        let key = self.checking_key(tenant_id, &token).await?;
        let claims: ReadClaims = token
            .verified(&key, JwtType::UpstreamAssertion)
            .map_err(|_| refused("the assertion does not check against the tenant's keys"))?;
        if &claims.tid != tenant_id.as_uuid() {
            return Err(refused("the assertion is another tenant's"));
        }
        claims.times.hold_at(clock::now())?;
        claims.caller()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::crypto::FakeAssertionKeyStore;
    use ianua_domain::domains::agents::authority::capability::{ActionApproval, McpGrant};
    use ianua_domain::domains::crypto::assertion_key::{
        AssertionKey, AssertionKeySet, NewAssertionKey,
    };
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::domains::proxy::exchange::ExchangeGrounds;
    use ianua_domain::domains::proxy::request::context::{
        AgentLimits, Caller, KeyBinding, Metering, PipelineContext, UserSignIn, Verified,
    };
    use ianua_domain::domains::proxy::stages::stage::TokenExchangeConfig;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::types::{
        AgentId, Audience, CorrelationId, DelegationId, Expiry, Fact, Issuer, KeyId, PipelineId,
        PrincipalRef, PublicKeyPem, Seconds, ServiceId, TenantId, TokenId, UserId,
    };
    use serde_json::Value;

    use super::*;
    use crate::crypto::jws::keys_for_tests::pair;
    use crate::crypto::jws::{Compact, JwsError, PublicKey};

    struct Signed {
        token: Compact,
        public: PublicKey,
        service: ServiceId,
    }

    /// Authenticates the fixture caller and permits the prepared request to proceed.
    fn authorize(context: &mut PipelineContext, caller: Caller) {
        context
            .authenticate(Verified {
                caller,
                expiry: Expiry::Never,
            })
            .unwrap();
        context.authorize();
    }

    /// Narrows a fixture token to reading invoices at the billing service for one minute.
    fn exchange_config() -> TokenExchangeConfig {
        TokenExchangeConfig {
            target_audience: Audience::new("billing-service").unwrap(),
            scopes: vec![Scope::new("invoices:read").unwrap()],
            ttl_seconds: Seconds::new(60),
        }
    }

    /// `caller`'s request in a new tenant, let through to a service, signed
    /// with a fresh ES256 assertion key `a1`.
    async fn signed_for(caller: Caller) -> Signed {
        let (private, public) = pair(SigningAlgorithm::Es256);
        let key = AssertionKey::create(NewAssertionKey {
            kid: KeyId::new("a1").unwrap(),
            public_key: PublicKeyPem::new(public.clone()).unwrap(),
            private_key: Secret::new(private.clone()),
        });
        let set = AssertionKeySet::<ResolvedTenant>::new(key);
        let signing = AssertionSigningKey::of(&set, Secret::new(private)).unwrap();
        let mut context =
            PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new());
        context.route.expected_issuer =
            Fact::Known(Issuer::new("https://id.example.com/acme").unwrap());
        context.claims.role_names = vec![Label::new("role_name", "Support").unwrap()];
        context.claims.permissions = vec![PermissionName::new("tickets:read").unwrap()];
        authorize(&mut context, caller);
        let service = ServiceId::new();
        let assertion = UpstreamAssertion::for_request(&context, service, clock::now())
            .unwrap()
            .unwrap();
        let signed = Pkcs8AssertionSigner
            .sign(&assertion, &signing)
            .await
            .unwrap();
        Signed {
            token: Compact::parse(signed.expose()).unwrap(),
            public: PublicKey::from_pem(SigningAlgorithm::Es256, &public).unwrap(),
            service,
        }
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

    /// Ann's assertion verifies with the published public half as an
    /// assertion, names the tenant's issuer, the one service and Ann, and
    /// lasts thirty seconds.
    #[tokio::test]
    async fn a_persons_assertion_verifies_and_names_her() {
        let ann = UserId::new();

        let signed = signed_for(Caller::User {
            user_id: ann,
            sign_in: UserSignIn::Token,
        })
        .await;

        let claims: Value = signed
            .token
            .verified(&signed.public, JwtType::UpstreamAssertion)
            .unwrap();
        assert_eq!(signed.token.header().kid.as_deref(), Some("a1"));
        assert_eq!(claims["iss"], "https://id.example.com/acme");
        assert_eq!(claims["aud"], signed.service.as_uuid().to_string());
        assert_eq!(claims["sub"], ann.as_uuid().to_string());
        assert_eq!(claims["kind"], "user");
        assert_eq!(claims["roles"][0], "Support");
        assert_eq!(claims["permissions"][0], "tickets:read");
        assert!(claims.get("act").is_none());
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            30
        );
    }

    /// An agent's assertion names it as the actor, whom it acts for typed,
    /// and the delegation as `jti`.
    #[tokio::test]
    async fn an_agents_assertion_names_the_actor_and_whom_it_acts_for() {
        let (fetcher, planner, delegation) = (AgentId::new(), AgentId::new(), DelegationId::new());

        let signed = signed_for(Caller::Agent {
            agent_id: fetcher,
            delegation_id: delegation,
            acting_for: PrincipalRef::Agent(planner),
            limits: Box::new(unlimited()),
        })
        .await;

        let claims: Value = signed
            .token
            .verified(&signed.public, JwtType::UpstreamAssertion)
            .unwrap();
        assert_eq!(claims["kind"], "agent");
        assert_eq!(claims["act"], fetcher.as_uuid().to_string());
        assert_eq!(claims["obo"], format!("agent:{}", planner.as_uuid()));
        assert_eq!(claims["jti"], delegation.as_uuid().to_string());
        assert_eq!(claims["sub"], planner.as_uuid().to_string());
    }

    /// An upstream assertion fails the access-token type check and is not accepted as a credential.
    #[tokio::test]
    async fn an_assertion_is_never_taken_for_an_access_token() {
        let signed = signed_for(Caller::User {
            user_id: UserId::new(),
            sign_in: UserSignIn::Token,
        })
        .await;

        let as_access = signed
            .token
            .verified::<Value>(&signed.public, JwtType::Access);

        assert!(matches!(as_access, Err(JwsError::WrongType)));
        assert!(!JwtType::accepted_as_credential(
            signed.token.header().typ.as_deref()
        ));
    }

    /// A message signature verifies under the assertion key's public half,
    /// typed as a signature, so it is taken for neither an access token nor
    /// an assertion.
    #[test]
    fn a_message_signature_is_typed_apart_and_verifies() {
        let (private, public) = pair(SigningAlgorithm::Es256);
        let key = AssertionKey::create(NewAssertionKey {
            kid: KeyId::new("a1").unwrap(),
            public_key: PublicKeyPem::new(public.clone()).unwrap(),
            private_key: Secret::new(private.clone()),
        });
        let set = AssertionKeySet::<ResolvedTenant>::new(key);
        let signing = AssertionSigningKey::of(&set, Secret::new(private)).unwrap();
        let public = PublicKey::from_pem(SigningAlgorithm::Es256, &public).unwrap();

        let signed = Pkcs8MessageSigner
            .sign(r#"{"sub":"request"}"#, &signing)
            .unwrap();

        let token = Compact::parse(&signed).unwrap();
        assert!(
            token
                .verified::<Value>(&public, JwtType::MessageSignature)
                .is_ok()
        );
        assert!(matches!(
            token.verified::<Value>(&public, JwtType::UpstreamAssertion),
            Err(JwsError::WrongType)
        ));
    }

    /// `caller`'s request in a new tenant, carrying `invoices:read`, let
    /// through and exchanged for a token for the billing service, signed
    /// with a fresh ES256 assertion key `a1`.
    async fn exchanged_for(caller: Caller) -> (Compact, PublicKey) {
        let (private, public) = pair(SigningAlgorithm::Es256);
        let key = AssertionKey::create(NewAssertionKey {
            kid: KeyId::new("a1").unwrap(),
            public_key: PublicKeyPem::new(public.clone()).unwrap(),
            private_key: Secret::new(private.clone()),
        });
        let set = AssertionKeySet::<ResolvedTenant>::new(key);
        let signing = AssertionSigningKey::of(&set, Secret::new(private)).unwrap();
        let mut context =
            PipelineContext::new(TenantId::new(), PipelineId::new(), CorrelationId::new());
        context.route.expected_issuer =
            Fact::Known(Issuer::new("https://id.example.com/acme").unwrap());
        context.claims.scopes = vec![Scope::new("invoices:read").unwrap()];
        authorize(&mut context, caller);
        let config = exchange_config();
        let grounds = ExchangeGrounds::of_request(&context).unwrap();
        let token_id = TokenId::new("019f0000-0000-7000-8000-0000000000e2").unwrap();
        let token = ExchangedToken::narrowed(&grounds, &config, token_id, clock::now()).unwrap();
        let signed = Pkcs8AssertionSigner
            .sign_exchanged(&token, &signing)
            .await
            .unwrap();
        (
            Compact::parse(signed.expose()).unwrap(),
            PublicKey::from_pem(SigningAlgorithm::Es256, &public).unwrap(),
        )
    }

    /// Ann's exchanged token checks out under the public half the tenant
    /// publishes, typed as an exchanged token, and names the issuer, the
    /// billing service, Ann, the scope and its own id, for a minute.
    #[tokio::test]
    async fn an_exchanged_token_verifies_against_the_published_key() {
        let ann = UserId::new();

        let (token, public) = exchanged_for(Caller::User {
            user_id: ann,
            sign_in: UserSignIn::Token,
        })
        .await;

        let claims: Value = token.verified(&public, JwtType::ExchangedToken).unwrap();
        assert_eq!(token.header().kid.as_deref(), Some("a1"));
        assert_eq!(claims["iss"], "https://id.example.com/acme");
        assert_eq!(claims["aud"], "billing-service");
        assert_eq!(claims["sub"], ann.as_uuid().to_string());
        assert_eq!(claims["kind"], "user");
        assert_eq!(claims["scope"], "invoices:read");
        assert_eq!(claims["jti"], "019f0000-0000-7000-8000-0000000000e2");
        assert!(claims.get("act").is_none());
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            60
        );
    }

    /// An agent's exchanged token names whom it acts for as `sub`, the
    /// agent as the actor as RFC 8693 writes it, and the delegation.
    #[tokio::test]
    async fn an_agents_exchanged_token_names_the_actor() {
        let (fetcher, ann, delegation) = (AgentId::new(), UserId::new(), DelegationId::new());

        let (token, public) = exchanged_for(Caller::Agent {
            agent_id: fetcher,
            delegation_id: delegation,
            acting_for: PrincipalRef::User(ann),
            limits: Box::new(unlimited()),
        })
        .await;

        let claims: Value = token.verified(&public, JwtType::ExchangedToken).unwrap();
        assert_eq!(claims["kind"], "agent");
        assert_eq!(claims["sub"], ann.as_uuid().to_string());
        assert_eq!(claims["act"]["sub"], fetcher.as_uuid().to_string());
        assert_eq!(claims["obo"], PrincipalRef::User(ann).label());
        assert_eq!(claims["dlg"], delegation.as_uuid().to_string());
    }

    /// An exchanged token is neither an access token nor an upstream assertion;
    /// both type checks fail and it is not accepted as a credential.
    #[tokio::test]
    async fn an_exchanged_token_is_never_taken_back_as_a_credential() {
        let (token, public) = exchanged_for(Caller::User {
            user_id: UserId::new(),
            sign_in: UserSignIn::Token,
        })
        .await;

        let as_access = token.verified::<Value>(&public, JwtType::Access);
        let as_assertion = token.verified::<Value>(&public, JwtType::UpstreamAssertion);

        assert!(matches!(as_access, Err(JwsError::WrongType)));
        assert!(matches!(as_assertion, Err(JwsError::WrongType)));
        assert!(!JwtType::accepted_as_credential(
            token.header().typ.as_deref()
        ));
    }

    /// `caller`'s assertion, made in `signed_in`, read back by the egress
    /// gateway as one of `read_in`'s, whose keys are the ones it was
    /// signed with.
    async fn read_back(
        caller: Caller,
        signed_in: TenantId,
        read_in: TenantId,
    ) -> Result<AssertedCaller, DomainError> {
        let (private, public) = pair(SigningAlgorithm::Es256);
        let key = AssertionKey::create(NewAssertionKey {
            kid: KeyId::new("a1").unwrap(),
            public_key: PublicKeyPem::new(public).unwrap(),
            private_key: Secret::new(private.clone()),
        });
        let set = AssertionKeySet::<ResolvedTenant>::new(key);
        let signing = AssertionSigningKey::of(&set, Secret::new(private)).unwrap();
        let keys = Arc::new(FakeAssertionKeyStore::empty());
        keys.put(read_in, &set);
        let mut context = PipelineContext::new(signed_in, PipelineId::new(), CorrelationId::new());
        context.route.expected_issuer =
            Fact::Known(Issuer::new("https://id.example.com/acme").unwrap());
        authorize(&mut context, caller);
        let assertion = UpstreamAssertion::for_request(&context, ServiceId::new(), clock::now())
            .unwrap()
            .unwrap();
        let signed = Pkcs8AssertionSigner
            .sign(&assertion, &signing)
            .await
            .unwrap();
        Pkcs8AssertionVerifier::new(keys)
            .caller(&ScopedTenant::for_test(read_in), &signed)
            .await
    }

    /// The egress gateway reads back the agent an assertion names, whom it
    /// acts for and its delegation, so a refused way out is held against
    /// that agent.
    #[tokio::test]
    async fn the_egress_gateway_reads_the_agent_an_assertion_names() {
        let (fetcher, delegation, ann) = (AgentId::new(), DelegationId::new(), UserId::new());
        let tenant = TenantId::new();

        let read = read_back(
            Caller::Agent {
                agent_id: fetcher,
                delegation_id: delegation,
                acting_for: PrincipalRef::User(ann),
                limits: Box::new(unlimited()),
            },
            tenant,
            tenant,
        )
        .await
        .unwrap();

        assert_eq!(
            read,
            AssertedCaller::Agent {
                agent_id: fetcher,
                acting_for: PrincipalRef::User(ann),
                delegation_id: delegation,
            }
        );
    }

    /// A trusted signature cannot authorize an assertion naming a different tenant.
    #[tokio::test]
    async fn an_assertion_of_another_tenant_is_refused() {
        let caller = Caller::User {
            user_id: UserId::new(),
            sign_in: UserSignIn::Token,
        };

        let read = read_back(caller, TenantId::new(), TenantId::new()).await;

        assert!(matches!(read, Err(DomainError::Unauthorized(_))));
    }

    /// Malformed JWT text fails assertion verification as unauthorized.
    #[tokio::test]
    async fn a_forged_assertion_is_refused() {
        let keys = Arc::new(FakeAssertionKeyStore::empty());

        let read = Pkcs8AssertionVerifier::new(keys)
            .caller(
                &ScopedTenant::for_test(TenantId::new()),
                &Secret::new("forged.assertion.value"),
            )
            .await;

        assert!(matches!(read, Err(DomainError::Unauthorized(_))));
    }
}
