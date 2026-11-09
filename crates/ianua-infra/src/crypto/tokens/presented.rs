//! The tenant's own tokens as a request presents them at the gateway: a
//! bearer token, a person's or an agent's, an app's session cookie, and on
//! the workflow listener a run pass, which `passes` also makes.
//!
//! Each is checked against the public halves of the tenant's keys, the
//! only ones the gateway's role reads, with the algorithm the key pins and
//! never the one the header names. A bearer must be typed `at+jwt` and an
//! app session as one; both are held to their times with the allowed skew.
//! What a token says once it checks out is read in `people` and `agents`;
//! whether its session, grant or delegation still stands is the
//! application's to ask.
//!
//! A token that does not check is a refusal with its reason; only keys that
//! cannot be read are an error, so a check that failed is never read as a
//! refusal it did not make.

mod agents;
mod passes;
mod people;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::{
    AppSessionClaim, AppSessionToken, ClaimedPass, ClaimedToken, ExpectedSession, ExpectedToken,
    PresentedTokens, RunPassToken, TenantToken, TokenFault, TokenReading,
};
use ianua_app::ports::crypto::VerifyingKeyStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    Fact, FederatedSubject, Issuer, Lifetime, Scope, ServiceId, SessionId, UserId,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use time::OffsetDateTime;

pub use self::passes::Pkcs8RunPasses;
use crate::crypto::jws::{Compact, PublicKey};
use crate::crypto::tokens::app_sessions::{SessionClaims, device_named};
use crate::crypto::tokens::claims::{TimeFault, Times};

/// What a reading comes to before it is handed out: what the token says,
/// or why it is refused.
pub(super) type Read<T> = Result<T, TokenFault>;

/// The reading `read` comes to.
pub(super) fn reading<T>(read: Read<T>) -> TokenReading<T> {
    match read {
        Ok(value) => TokenReading::Read(value),
        Err(fault) => TokenReading::Refused(fault),
    }
}

/// The refusal of a token whose times do not hold at `now`, if they do not.
pub(super) fn times_hold(times: Times, now: OffsetDateTime) -> Read<()> {
    match times.fault_at(now) {
        None => Ok(()),
        Some(TimeFault::Expired) => Err(TokenFault::Expired),
        Some(TimeFault::NotYetValid | TimeFault::IssuedAhead) => Err(TokenFault::NotYetValid),
        Some(TimeFault::NoExpiry) => Err(TokenFault::Invalid),
    }
}

/// When a token stops being valid, from its `exp`.
pub(super) fn expiry_of(exp: Option<i64>) -> Read<OffsetDateTime> {
    exp.and_then(|exp| OffsetDateTime::from_unix_timestamp(exp).ok())
        .ok_or(TokenFault::Invalid)
}

/// Scopes as a token lists them: space-separated, or as a list.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Listed {
    Spaced(String),
    Each(Vec<String>),
}

impl Listed {
    /// Every scope named, in order.
    fn names(self) -> Vec<String> {
        match self {
            Self::Spaced(spaced) => spaced.split_whitespace().map(str::to_owned).collect(),
            Self::Each(each) => each,
        }
    }
}

/// The scopes a token carries, from `scope` or `scp`.
#[derive(Debug, Deserialize)]
pub(super) struct ScopeClaims {
    #[serde(default)]
    scope: Option<Listed>,
    #[serde(default)]
    scp: Option<Listed>,
}

impl ScopeClaims {
    /// The scopes named, from `scope`, else from `scp`; none when neither
    /// is there.
    ///
    /// # Errors
    ///
    /// [`TokenFault::Invalid`] when a scope named is not one.
    pub(super) fn scopes(self) -> Read<Vec<Scope>> {
        self.scope
            .or(self.scp)
            .map_or_else(Vec::new, Listed::names)
            .into_iter()
            .map(|name| Scope::new(name).map_err(|_| TokenFault::Invalid))
            .collect()
    }
}

/// The issuer and subject a token claims, as written.
#[derive(Debug, Deserialize)]
struct Claimed {
    iss: String,
    sub: String,
}

/// The public halves of a tenant's keys, read from their store.
struct VerifyingKeys {
    store: Arc<dyn VerifyingKeyStore>,
    grace: Lifetime,
}

impl VerifyingKeys {
    /// The key of `tenant_id` `token` names, when it is one a verifier may
    /// still accept now.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the keys cannot be read,
    /// or the key named does not read as a key.
    async fn checking(
        &self,
        tenant_id: &ScopedTenant,
        token: &Compact,
    ) -> Result<Option<PublicKey>, DomainError> {
        let Some(kid) = token.header().kid.as_deref() else {
            return Ok(None);
        };
        let now = clock::now();
        let keys = self.store.find(tenant_id).await?;
        let Some(key) = keys
            .iter()
            .find(|key| key.kid().as_str() == kid && key.is_in_jwks(self.grace, now))
        else {
            return Ok(None);
        };
        PublicKey::from_pem(key.algorithm(), key.public_key().as_str())
            .map(Some)
            .map_err(DomainError::infra)
    }

    /// The claims of `token`, once it checks out as a token of `typ` under
    /// a key of `tenant_id`, or the refusal of one that does not.
    async fn verified<C: serde::de::DeserializeOwned>(
        &self,
        tenant_id: &ScopedTenant,
        token: &Secret,
        typ: JwtType,
    ) -> Result<Read<C>, DomainError> {
        let Ok(token) = Compact::parse(token.expose()) else {
            return Ok(Err(TokenFault::Invalid));
        };
        let Some(key) = self.checking(tenant_id, &token).await? else {
            return Ok(Err(TokenFault::Invalid));
        };
        Ok(token.verified(&key, typ).map_err(|_| TokenFault::Invalid))
    }
}

/// The reader of the tenant's tokens presented at the gateway, with the
/// public halves of the tenant's keys.
pub struct Pkcs8PresentedTokens {
    keys: VerifyingKeys,
}

impl Pkcs8PresentedTokens {
    /// A reader checking against the keys `verifying_keys` holds, a rotated
    /// key still checking for `grace`.
    #[must_use]
    pub fn new(verifying_keys: Arc<dyn VerifyingKeyStore>, grace: Lifetime) -> Self {
        Self {
            keys: VerifyingKeys {
                store: verifying_keys,
                grace,
            },
        }
    }
}

/// What an app session's `claims`, checked out under the tenant's key,
/// say on the host `expected` names, at `now`.
fn app_session_of(
    tenant_id: &ScopedTenant,
    claims: &SessionClaims,
    expected: ExpectedSession<'_>,
    now: OffsetDateTime,
) -> Read<AppSessionToken> {
    let minted_here = &claims.tid == tenant_id.as_uuid()
        && claims.host.eq_ignore_ascii_case(expected.host.as_str())
        && &claims.svc == expected.owner.as_uuid();
    if !minted_here {
        return Err(TokenFault::WrongHost);
    }
    if claims.iss != expected.issuer.as_str() {
        return Err(TokenFault::WrongIssuer);
    }
    if claims.aud != expected.audience.as_str() {
        return Err(TokenFault::WrongAudience);
    }
    times_hold(claims.times, now)?;
    Ok(AppSessionToken {
        claim: AppSessionClaim {
            session_id: SessionId::from_uuid(claims.sid),
            user_id: UserId::from_uuid(claims.sub),
            service_id: ServiceId::from_uuid(claims.svc),
            idle_timeout: claims.idl.map(Duration::from_secs),
            signed_in_from: device_named(claims.did),
        },
        assurance: Fact::Known(claims.aal),
        expires_at: expiry_of(claims.times.exp)?,
    })
}

#[async_trait]
impl PresentedTokens for Pkcs8PresentedTokens {
    fn claimed(&self, token: &Secret) -> Option<ClaimedToken> {
        let claimed: Claimed = Compact::parse(token.expose())
            .ok()?
            .unchecked_claims()
            .ok()?;
        Some(ClaimedToken {
            issuer: Issuer::new(claimed.iss).ok()?,
            subject: FederatedSubject::new(claimed.sub).ok()?,
        })
    }

    async fn read_bearer(
        &self,
        tenant_id: &ScopedTenant,
        token: &Secret,
        expected: ExpectedToken<'_>,
    ) -> Result<TokenReading<TenantToken>, DomainError> {
        let claims: Read<Map<String, Value>> = self
            .keys
            .verified(tenant_id, token, JwtType::Access)
            .await?;
        let now = clock::now();
        Ok(reading(claims.and_then(|claims| {
            if claims.contains_key(agents::ACTING_FOR) {
                return agents::agent_token(tenant_id, claims, expected, now)
                    .map(|token| TenantToken::Agent(Box::new(token)));
            }
            people::person_token(tenant_id, claims, expected, now).map(TenantToken::Person)
        })))
    }

    async fn read_app_session(
        &self,
        tenant_id: &ScopedTenant,
        token: &Secret,
        expected: ExpectedSession<'_>,
    ) -> Result<TokenReading<AppSessionToken>, DomainError> {
        let claims: Read<SessionClaims> = self
            .keys
            .verified(tenant_id, token, JwtType::AppSession)
            .await?;
        let now = clock::now();
        Ok(reading(claims.and_then(|claims| {
            app_session_of(tenant_id, &claims, expected, now)
        })))
    }

    fn claimed_pass(&self, token: &Secret) -> Option<ClaimedPass> {
        passes::claimed(token)
    }

    async fn read_run_pass(
        &self,
        tenant_id: &ScopedTenant,
        token: &Secret,
        issuer: &Issuer,
    ) -> Result<TokenReading<RunPassToken>, DomainError> {
        let claims: Read<passes::PassClaims> = self
            .keys
            .verified(tenant_id, token, JwtType::RunPass)
            .await?;
        let now = clock::now();
        Ok(reading(claims.and_then(|claims| {
            passes::pass_of(tenant_id, &claims, issuer, now)
        })))
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::TenantScoped;
    use ianua_app::ports::agents::{TaskTokenIssuer, task_token_audience};
    use ianua_app::ports::authentication::{
        AppAccessGrant, AppSessionGrant, AppSessionTokens, IssuedUnder, PassReach, PersonToken,
    };
    use ianua_app::ports::workflows::{RunPassGrant, RunPasses};
    use ianua_app::test_support::agents::{FakeAgentCredentialStore, delegation_row};
    use ianua_app::test_support::crypto::FakeSigningKeyStore;
    use ianua_app::test_support::routing::FakeServiceStore;
    use ianua_domain::domains::agents::authority::delegation::Delegation;
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::crypto::key_status::KeyState;
    use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKeySet};
    use ianua_domain::domains::crypto::verifying_key::{VerifyingKey, VerifyingKeyRow};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{
        ActionCallId, AgentId, Audience, DomainName, Expiry, PrincipalRef, RouteId, StreamRouteId,
        TenantId, TrustedDeviceId,
    };
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::crypto::jws::{PrivateKey, TokenHeader, signed};
    use crate::crypto::tokens::app_sessions::Pkcs8AppSessionTokens;
    use crate::crypto::tokens::claims::tests::{grace, key_set};
    use crate::crypto::tokens::tasks::Pkcs8TaskTokenIssuer;

    /// The public halves of a tenant's keys, or none to be read at all.
    struct FakeVerifyingKeys(Option<Vec<VerifyingKey>>);

    impl TenantScoped for FakeVerifyingKeys {}

    #[async_trait]
    impl VerifyingKeyStore for FakeVerifyingKeys {
        async fn find(&self, _: &ScopedTenant) -> Result<Vec<VerifyingKey>, DomainError> {
            self.0
                .clone()
                .ok_or_else(|| DomainError::infra_msg("the keys could not be read"))
        }
    }

    struct Fixture {
        tenant: ScopedTenant,
        set: SigningKeySet<ResolvedTenant>,
        private: Secret,
        issuer: Issuer,
        audience: Audience,
    }

    fn fixture() -> Fixture {
        let (set, private) = key_set();
        Fixture {
            tenant: ScopedTenant::for_background(TenantId::new()),
            set,
            private,
            issuer: Issuer::new("https://acme.ianua.example").unwrap(),
            audience: Audience::new("ledger").unwrap(),
        }
    }

    impl Fixture {
        /// A task issuer using the tenant's active signing key and empty agent stores.
        fn task_issuer(&self) -> Pkcs8TaskTokenIssuer {
            let keys = Arc::new(FakeSigningKeyStore::empty());
            keys.put(*self.tenant, self.set.clone());
            Pkcs8TaskTokenIssuer::new(
                keys,
                grace(),
                Arc::new(FakeServiceStore::empty()),
                Arc::new(FakeAgentCredentialStore::empty()),
            )
        }

        /// Reads a bearer against this tenant's agent audience and expected issuer.
        async fn agent_bearer(&self, token: &Secret) -> TokenReading<TenantToken> {
            let agents = Audience::new(task_token_audience(&self.tenant)).unwrap();
            self.reader()
                .read_bearer(
                    &self.tenant,
                    token,
                    ExpectedToken {
                        issuer: &self.issuer,
                        audience: &agents,
                    },
                )
                .await
                .unwrap()
        }

        /// A session grant for this tenant's audience on the given app host.
        fn session_grant(&self, host: DomainName, owner: ServiceId) -> AppSessionGrant {
            AppSessionGrant {
                issuer: self.issuer.clone(),
                audience: self.audience.clone(),
                host,
                user_id: UserId::new(),
                session_id: SessionId::new(),
                service_id: owner,
                assurance: AssuranceLevel::Aal1,
                expires_at: clock::now() + time::Duration::minutes(30),
                idle_timeout: Some(Duration::from_secs(900)),
                signed_in_from: Fact::Known(TrustedDeviceId::new()),
            }
        }

        /// The public half of the tenant's key, standing at `state`.
        fn public_half(&self, state: KeyState, created_at: OffsetDateTime) -> VerifyingKey {
            let key = &self.set.keys()[0];
            VerifyingKey::reconstitute(VerifyingKeyRow {
                kid: key.kid().clone(),
                algorithm: key.algorithm(),
                public_key: key.public_key().clone(),
                state,
                created_at,
                expires_at: Expiry::Never,
            })
            .unwrap()
        }

        /// A reader over the tenant's active key.
        fn reader(&self) -> Pkcs8PresentedTokens {
            let active = self.public_half(KeyState::Active, clock::now());
            Pkcs8PresentedTokens::new(Arc::new(FakeVerifyingKeys(Some(vec![active]))), grace())
        }

        /// `claims` signed with the tenant's key as a token of `typ`.
        fn sign(&self, claims: &Value, typ: JwtType) -> Secret {
            let key = PrivateKey::from_pem(SigningAlgorithm::Es256, self.private.expose()).unwrap();
            let token = signed(
                &claims.to_string(),
                TokenHeader::new(typ, "k1", SigningAlgorithm::Es256),
                &key,
            );
            Secret::new(token.unwrap())
        }

        fn expected(&self) -> ExpectedToken<'_> {
            ExpectedToken {
                issuer: &self.issuer,
                audience: &self.audience,
            }
        }

        async fn bearer(&self, token: &Secret) -> TokenReading<TenantToken> {
            self.reader()
                .read_bearer(&self.tenant, token, self.expected())
                .await
                .unwrap()
        }

        /// What the session cookie `token` reads as on `host`, for the
        /// service `owner`.
        async fn session_on(
            &self,
            token: &Secret,
            host: &DomainName,
            owner: &ServiceId,
        ) -> TokenReading<AppSessionToken> {
            let expected = ExpectedSession {
                issuer: &self.issuer,
                audience: &self.audience,
                host,
                owner,
            };
            self.reader()
                .read_app_session(&self.tenant, token, expected)
                .await
                .unwrap()
        }
    }

    /// Claims of an access token the tenant issued `sub` under a grant,
    /// for the route's audience, valid for ten minutes.
    fn grant_claims(fx: &Fixture, sub: &str) -> Value {
        let now = clock::now().unix_timestamp();
        json!({
            "iss": fx.issuer.as_str(),
            "aud": fx.audience.as_str(),
            "sub": sub,
            "client_id": "ledger",
            "jti": "t-1",
            "scope": "openid ledger:read",
            "acr": AssuranceLevel::Aal2.acr(),
            "department": "finance",
            "iat": now,
            "exp": now + 600,
        })
    }

    fn person(reading: TokenReading<TenantToken>) -> PersonToken {
        match reading {
            TokenReading::Read(TenantToken::Person(person)) => person,
            other => panic!("not a person's token: {other:?}"),
        }
    }

    fn fault<T: std::fmt::Debug>(reading: TokenReading<T>) -> TokenFault {
        match reading {
            TokenReading::Refused(fault) => fault,
            TokenReading::Read(read) => panic!("read where a refusal was due: {read:?}"),
        }
    }

    /// An access token issued under a grant reads as its person, with its
    /// scopes, its assurance from `acr`, and the claims a rule compares,
    /// the registered ones left out.
    #[tokio::test]
    async fn a_grants_access_token_reads_as_its_person() {
        let fx = fixture();
        let user = UserId::new();
        let token = fx.sign(&grant_claims(&fx, &user.to_string()), JwtType::Access);

        let read = person(fx.bearer(&token).await);

        assert_eq!(read.user_id, user);
        let scopes: Vec<&str> = read.scopes.iter().map(Scope::as_str).collect();
        assert_eq!(scopes, ["openid", "ledger:read"]);
        assert_eq!(read.assurance, Fact::Known(AssuranceLevel::Aal2));
        assert_eq!(read.issued_under, IssuedUnder::Grant);
        let claims: Vec<(&str, &str)> = read
            .claims
            .iter()
            .map(|claim| (claim.name().as_str(), claim.value().as_str()))
            .collect();
        assert_eq!(claims, [("department", "finance")]);
    }

    /// The bearer token an app's page fetched names the app session it was
    /// fetched under, and the trusted device that session was signed in
    /// from.
    #[tokio::test]
    async fn an_apps_access_token_names_its_session() {
        let fx = fixture();
        let keys = Arc::new(FakeSigningKeyStore::empty());
        keys.put(*fx.tenant, fx.set.clone());
        let grant = AppAccessGrant {
            issuer: fx.issuer.clone(),
            audience: fx.audience.clone(),
            user_id: UserId::new(),
            session_id: SessionId::new(),
            owner: ServiceId::new(),
            assurance: AssuranceLevel::Aal2,
            expires_at: clock::now() + time::Duration::minutes(5),
            idle_timeout: None,
            signed_in_from: Fact::Known(TrustedDeviceId::new()),
        };
        let issued = Pkcs8AppSessionTokens::new(keys, grace())
            .issue_access(&fx.tenant, &grant)
            .await
            .unwrap();

        let read = person(fx.bearer(&issued.token).await);

        assert_eq!(read.user_id, grant.user_id);
        assert_eq!(read.assurance, Fact::Known(AssuranceLevel::Aal2));
        let IssuedUnder::AppSession(session) = read.issued_under else {
            panic!("issued under a grant");
        };
        assert_eq!(session.session_id, grant.session_id);
        assert_eq!(session.service_id, grant.owner);
        assert_eq!(session.signed_in_from, grant.signed_in_from);
    }

    /// Audience, issuer, expiry, not-before and tenant mismatches each retain
    /// their specific refusal reason.
    #[tokio::test]
    async fn a_misdirected_or_untimely_token_is_refused_for_its_reason() {
        let fx = fixture();
        let user = UserId::new().to_string();
        let now = clock::now().unix_timestamp();
        let with = |field: &str, value: Value| {
            let mut claims = grant_claims(&fx, &user);
            claims[field] = value;
            fx.sign(&claims, JwtType::Access)
        };
        let cases = [
            (with("aud", json!("billing")), TokenFault::WrongAudience),
            (
                with("iss", json!("https://evil.example")),
                TokenFault::WrongIssuer,
            ),
            (with("exp", json!(now - 3600)), TokenFault::Expired),
            (with("nbf", json!(now + 3600)), TokenFault::NotYetValid),
            (with("tid", json!(Uuid::now_v7())), TokenFault::WrongHost),
        ];

        for (token, wanted) in cases {
            assert_eq!(fault(fx.bearer(&token).await), wanted);
        }
    }

    /// An app session, a token signed by another key and an opaque string
    /// are all invalid when presented as access bearers.
    #[tokio::test]
    async fn what_is_no_bearer_of_the_tenant_is_invalid() {
        let fx = fixture();
        let other = fixture();
        let claims = grant_claims(&fx, &UserId::new().to_string());
        let session = fx.sign(&claims, JwtType::AppSession);
        let foreign = other.sign(&claims, JwtType::Access);
        let opaque = Secret::new("at_opaque_value");

        for token in [session, foreign, opaque] {
            assert_eq!(fault(fx.bearer(&token).await), TokenFault::Invalid);
        }
    }

    /// A token signed by a retired key is invalid after that key's grace period.
    #[tokio::test]
    async fn a_key_past_its_grace_checks_nothing() {
        let fx = fixture();
        let now = clock::now();
        let rotated = fx.public_half(
            KeyState::Rotated {
                at: now - time::Duration::days(5),
            },
            now - time::Duration::days(10),
        );
        let reader =
            Pkcs8PresentedTokens::new(Arc::new(FakeVerifyingKeys(Some(vec![rotated]))), grace());
        let token = fx.sign(
            &grant_claims(&fx, &UserId::new().to_string()),
            JwtType::Access,
        );

        let read = reader
            .read_bearer(&fx.tenant, &token, fx.expected())
            .await
            .unwrap();

        assert_eq!(fault(read), TokenFault::Invalid);
    }

    /// An unavailable key store produces an infrastructure error, preserving the lookup failure.
    #[tokio::test]
    async fn keys_that_cannot_be_read_are_an_error() {
        let fx = fixture();
        let reader = Pkcs8PresentedTokens::new(Arc::new(FakeVerifyingKeys(None)), grace());
        let token = fx.sign(
            &grant_claims(&fx, &UserId::new().to_string()),
            JwtType::Access,
        );

        let read = reader.read_bearer(&fx.tenant, &token, fx.expected()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// A task token minted for a delegation reads as its agent, acting for
    /// its delegator, read in the shape it was minted with; a route whose
    /// audience it does not name refuses it.
    #[tokio::test]
    async fn a_task_token_reads_as_its_delegations_agent() {
        let fx = fixture();
        let issuer = fx.task_issuer();
        let row = delegation_row(AgentId::new(), PrincipalRef::User(UserId::new()));
        let delegation = Delegation::reconstitute(row).unwrap();
        let minted = issuer
            .issue(&fx.tenant, &fx.issuer, &delegation)
            .await
            .unwrap();
        let token = Secret::new(minted.reveal());
        let read = fx.agent_bearer(&token).await;
        let elsewhere = fx.bearer(&token).await;

        let TokenReading::Read(TenantToken::Agent(agent)) = read else {
            panic!("not an agent's token");
        };
        assert_eq!(&agent.agent_id, delegation.delegate());
        assert_eq!(&agent.delegation_id, delegation.id());
        assert_eq!(agent.acting_for.label(), delegation.delegator().label());
        assert!(agent.bound_key.is_none());
        assert_eq!(fault(elsewhere), TokenFault::WrongAudience);
    }

    /// A task token naming an issuer other than the tenant's receives the wrong-issuer refusal.
    #[tokio::test]
    async fn a_task_token_of_another_issuer_is_refused() {
        let fx = fixture();
        let keys = Arc::new(FakeSigningKeyStore::empty());
        keys.put(*fx.tenant, fx.set.clone());
        let issuer = Pkcs8TaskTokenIssuer::new(
            keys,
            grace(),
            Arc::new(FakeServiceStore::empty()),
            Arc::new(FakeAgentCredentialStore::empty()),
        );
        let row = delegation_row(AgentId::new(), PrincipalRef::User(UserId::new()));
        let delegation = Delegation::reconstitute(row).unwrap();
        let other = Issuer::new("https://elsewhere.example").unwrap();
        let minted = issuer.issue(&fx.tenant, &other, &delegation).await.unwrap();
        let agents = Audience::new(task_token_audience(&fx.tenant)).unwrap();

        let read = fx
            .reader()
            .read_bearer(
                &fx.tenant,
                &Secret::new(minted.reveal()),
                ExpectedToken {
                    issuer: &fx.issuer,
                    audience: &agents,
                },
            )
            .await
            .unwrap();

        assert_eq!(fault(read), TokenFault::WrongIssuer);
    }

    /// An app session cookie reads back on the host it was minted for, for
    /// the service whose sign-in opened it; on another host, or for another
    /// service, it is refused.
    #[tokio::test]
    async fn an_app_session_reads_back_on_its_host_only() {
        let fx = fixture();
        let keys = Arc::new(FakeSigningKeyStore::empty());
        keys.put(*fx.tenant, fx.set.clone());
        let host = DomainName::new("ledger.acme.example").unwrap();
        let elsewhere = DomainName::new("evil.acme.example").unwrap();
        let owner = ServiceId::new();
        let grant = fx.session_grant(host.clone(), owner);
        let issued = Pkcs8AppSessionTokens::new(keys, grace())
            .issue(&fx.tenant, &grant)
            .await
            .unwrap();
        let stranger = ServiceId::new();

        let own = fx.session_on(&issued.token, &host, &owner).await;
        let moved = fx.session_on(&issued.token, &elsewhere, &owner).await;
        let other = fx.session_on(&issued.token, &host, &stranger).await;

        let TokenReading::Read(session) = own else {
            panic!("the session did not read back");
        };
        assert_eq!(session.claim.session_id, grant.session_id);
        assert_eq!(session.claim.idle_timeout, grant.idle_timeout);
        assert_eq!(session.claim.signed_in_from, grant.signed_in_from);
        assert_eq!(session.assurance, Fact::Known(AssuranceLevel::Aal1));
        assert_eq!(fault(moved), TokenFault::WrongHost);
        assert_eq!(fault(other), TokenFault::WrongHost);
    }

    /// The issuer and subject a token claims are read without checking it,
    /// to choose whose keys check it; what is no JWT claims nothing.
    #[test]
    fn a_tokens_issuer_and_subject_are_read_unchecked() {
        let fx = fixture();
        let claims = json!({"iss": "https://partner.example", "sub": "feed"});
        let token = fx.sign(&claims, JwtType::Access);

        let claimed = fx.reader().claimed(&token).unwrap();
        let nothing = fx.reader().claimed(&Secret::new("sk_live_partner_7f3kq2"));

        assert_eq!(claimed.issuer.as_str(), "https://partner.example");
        assert_eq!(claimed.subject.as_str(), "feed");
        assert!(nothing.is_none());
    }

    /// A pass the worker made for one call of Ann's run, on the orders
    /// route, signed with the tenant's active key.
    async fn made_pass(fx: &Fixture, grant: &RunPassGrant) -> Secret {
        let keys = Arc::new(FakeSigningKeyStore::empty());
        keys.put(*fx.tenant, fx.set.clone());
        Pkcs8RunPasses::new(keys, grace())
            .issue(&fx.tenant, &fx.issuer, grant)
            .await
            .unwrap()
    }

    /// What `token` reads as when presented as a pass under `issuer`.
    async fn pass_read(
        fx: &Fixture,
        token: &Secret,
        issuer: &Issuer,
    ) -> TokenReading<RunPassToken> {
        fx.reader()
            .read_run_pass(&fx.tenant, token, issuer)
            .await
            .unwrap()
    }

    fn orders_grant() -> RunPassGrant {
        RunPassGrant {
            call_id: ActionCallId::new(),
            user_id: UserId::new(),
            reaches: PassReach::Route(RouteId::new()),
        }
    }

    /// The pass reads back as made: Ann, the orders route and the call,
    /// lapsing within a minute, and its tenant and route are read before
    /// it is checked.
    #[tokio::test]
    async fn a_run_pass_reads_back_as_it_was_made() {
        let fx = fixture();
        let grant = orders_grant();
        let pass = made_pass(&fx, &grant).await;

        let reading = pass_read(&fx, &pass, &fx.issuer).await;
        let claimed = fx.reader().claimed_pass(&pass).unwrap();

        let TokenReading::Read(read) = reading else {
            panic!("the pass did not read back");
        };
        assert_eq!(
            (read.call_id, read.user_id, read.reaches),
            (grant.call_id, grant.user_id, grant.reaches)
        );
        assert!(read.expires_at <= clock::now() + time::Duration::seconds(60));
        assert_eq!(claimed.reaches, grant.reaches);
        assert_eq!(claimed.tenant_id, *fx.tenant);
    }

    /// A pass made for Ann's run on the orders database reads back naming
    /// that stream route, and no route.
    #[tokio::test]
    async fn a_run_pass_for_a_stream_route_reads_back_naming_it() {
        let fx = fixture();
        let grant = RunPassGrant {
            reaches: PassReach::StreamRoute(StreamRouteId::new()),
            ..orders_grant()
        };
        let pass = made_pass(&fx, &grant).await;

        let reading = pass_read(&fx, &pass, &fx.issuer).await;
        let claimed = fx.reader().claimed_pass(&pass).unwrap();

        let TokenReading::Read(read) = reading else {
            panic!("the pass did not read back");
        };
        assert_eq!(read.reaches, grant.reaches);
        assert_eq!(claimed.reaches, grant.reaches);
    }

    /// A valid run pass is invalid when presented as an access bearer.
    #[tokio::test]
    async fn a_run_pass_is_no_bearer_token() {
        let fx = fixture();
        let pass = made_pass(&fx, &orders_grant()).await;

        let reading = fx.bearer(&pass).await;

        assert_eq!(fault(reading), TokenFault::Invalid);
    }

    /// An access token cannot be verified as a run pass.
    #[tokio::test]
    async fn an_access_token_is_no_run_pass() {
        let fx = fixture();
        let token = fx.sign(
            &grant_claims(&fx, &UserId::new().to_string()),
            JwtType::Access,
        );

        let reading = pass_read(&fx, &token, &fx.issuer).await;

        assert_eq!(fault(reading), TokenFault::Invalid);
    }

    /// Tenant and issuer mismatches invalidate a run pass, while a lapsed pass
    /// receives the expiry refusal.
    #[tokio::test]
    async fn a_run_pass_for_another_tenant_issuer_or_time_is_refused() {
        let fx = fixture();
        let now = clock::now().unix_timestamp();
        let claims = |tid: Uuid, exp: i64| {
            json!({
                "iss": fx.issuer.as_str(),
                "sub": Uuid::new_v4(),
                "tid": tid,
                "rte": Uuid::new_v4(),
                "jti": Uuid::new_v4(),
                "iat": now,
                "exp": exp,
            })
        };
        let elsewhere = fx.sign(&claims(Uuid::new_v4(), now + 60), JwtType::RunPass);
        let stale = fx.sign(&claims(*fx.tenant.as_uuid(), now - 300), JwtType::RunPass);
        let own = fx.sign(&claims(*fx.tenant.as_uuid(), now + 60), JwtType::RunPass);
        let other_issuer = Issuer::new("https://other.ianua.example").unwrap();

        let moved = pass_read(&fx, &elsewhere, &fx.issuer).await;
        let expired = pass_read(&fx, &stale, &fx.issuer).await;
        let misissued = pass_read(&fx, &own, &other_issuer).await;

        assert_eq!(fault(moved), TokenFault::Invalid);
        assert_eq!(fault(expired), TokenFault::Expired);
        assert_eq!(fault(misissued), TokenFault::WrongIssuer);
    }
}
