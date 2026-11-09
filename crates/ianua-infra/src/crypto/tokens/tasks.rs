//! Task tokens: the credential an agent presents for a delegation, signed
//! with the tenant's key as an access token, and read back on the message
//! plane.
//!
//! [`TaskTokenClaims`] is the one shape both sides read: the issuer writes
//! it, and the broker and the gateway read it back, so they cannot drift
//! apart. The token names the tenant's own issuer (`iss`), the delegator
//! (`sub`, `obo`), the agent (`act`), the tenant (`tid`) and the delegation
//! (`jti`), what the delegation grants, and every limit the gateway holds a
//! request to.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::agents::{
    AgentCredentialStore, TaskToken, TaskTokenIssuer, task_token_audience,
};
use ianua_app::ports::broker::{AgentPrincipal, TaskTokenVerifier, VerifiedTaskToken};
use ianua_app::ports::crypto::SigningKeyStore;
use ianua_app::ports::routing::ServiceStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::authority::capability::{AppAccess, CapabilitySet, McpGrant};
use ianua_domain::domains::agents::authority::delegation::{Delegation, TokenKey};
use ianua_domain::domains::agents::authority::intent::{DriftPolicy, IntentBinding};
use ianua_domain::domains::crypto::jwk::JwkComponents;
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ActionClass, AgentId, DelegationId, Issuer, Lifetime, PrincipalRef, TenantId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::crypto::jws::{Compact, PublicKey, TokenHeader, components, signed};
use crate::crypto::tokens::claims::{Audiences, TenantKeys, Times, refused};

/// What a task token says.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TaskTokenClaims {
    /// The tenant's own token issuer.
    pub iss: String,
    /// The delegator's id.
    pub sub: String,
    /// The delegator, as a principal label.
    pub obo: String,
    /// The agent acting.
    pub act: Uuid,
    /// The tenant.
    pub tid: Uuid,
    /// The tenant's agent surfaces, and each app the delegation reaches.
    pub aud: Vec<String>,
    /// The delegation.
    pub jti: Uuid,
    /// The HTTP permissions granted, as their names.
    pub permissions: Vec<String>,
    /// Everything the delegation grants.
    pub scope: CapabilitySet,
    /// When it was issued and when it lapses.
    #[serde(flatten)]
    pub times: TokenTimes,
    /// The actions an enforced intent allows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ienv: Option<Vec<ActionClass>>,
    /// The digest of that intent, in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idg: Option<String>,
    /// The most requests per window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bmax: Option<u32>,
    /// The window those requests are counted over, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bwin: Option<u32>,
    /// The URL path prefixes the agent is held to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsc: Option<Vec<String>>,
    /// The most sensitive data class the agent may reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcl: Option<String>,
    /// Whether every action waits for a person's approval.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub apr: bool,
    /// The MCP tools and resources granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpGrant>,
    /// The key the token is bound to, as `{"jwk": …}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Value>,
}

/// When a task token was issued and when it lapses, in seconds since the
/// epoch.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct TokenTimes {
    /// When it was issued.
    pub iat: i64,
    /// When it lapses.
    pub exp: i64,
}

impl TokenTimes {
    /// Records issuance now while retaining the delegation's expiry.
    fn of(delegation: &Delegation<ResolvedTenant>) -> Self {
        Self {
            iat: clock::now().unix_timestamp(),
            exp: delegation.expires_at().unix_timestamp(),
        }
    }
}

/// Lists the HTTP grants in the token's permission-name representation.
fn permissions(delegation: &Delegation<ResolvedTenant>) -> Vec<String> {
    delegation
        .granted()
        .http()
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// Lists the constrained path prefixes without changing an absent constraint.
fn resource_scope(delegation: &Delegation<ResolvedTenant>) -> Option<Vec<String>> {
    delegation
        .constraints()
        .resource_scope()
        .limit()
        .map(|scope| {
            scope
                .prefixes()
                .iter()
                .map(|prefix| prefix.as_str().to_owned())
                .collect()
        })
}

/// The intent binding the gateway enforces, if the delegation has one.
fn enforced(delegation: &Delegation<ResolvedTenant>) -> Option<&IntentBinding> {
    let intent = delegation.constraints().intent().limit()?;
    matches!(intent.drift_policy(), DriftPolicy::Enforce(_)).then_some(intent)
}

/// The JWK of `components`, without its `kid`, as `cnf` carries it.
fn bound_jwk(components: JwkComponents) -> Value {
    match components {
        JwkComponents::Ec { crv, x, y, .. } => json!({"kty": "EC", "crv": crv, "x": x, "y": y}),
        JwkComponents::Okp { crv, x, .. } => json!({"kty": "OKP", "crv": crv, "x": x}),
        JwkComponents::Rsa { n, e, .. } => json!({"kty": "RSA", "n": n, "e": e}),
    }
}

/// The issuer of task tokens, signing with the tenant's active key.
pub struct Pkcs8TaskTokenIssuer {
    keys: TenantKeys,
    services: Arc<dyn ServiceStore>,
    credentials: Arc<dyn AgentCredentialStore>,
}

impl Pkcs8TaskTokenIssuer {
    /// An issuer signing with the tenant keys `signing_keys` holds, a
    /// rotated key still checking for `grace`, naming the apps `services`
    /// holds and binding tokens to the keys `credentials` holds.
    #[must_use]
    pub fn new(
        signing_keys: Arc<dyn SigningKeyStore>,
        grace: Lifetime,
        services: Arc<dyn ServiceStore>,
        credentials: Arc<dyn AgentCredentialStore>,
    ) -> Self {
        Self {
            keys: TenantKeys::new(signing_keys, grace),
            services,
            credentials,
        }
    }

    /// The audiences the token names: the tenant's agent surfaces, and the
    /// audience each active app it reaches pins.
    async fn audiences(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<Vec<String>, DomainError> {
        let ours = task_token_audience(tenant_id);
        let AppAccess::Listed(apps) = delegation.constraints().apps() else {
            return Ok(vec![ours]);
        };
        let services = self
            .services
            .find_by_ids(tenant_id, apps.services())
            .await?;
        Ok(std::iter::once(ours)
            .chain(
                services
                    .iter()
                    .filter(|service| service.is_active())
                    .filter_map(|service| service.upstream().expected_audience())
                    .map(|audience| audience.as_str().to_owned()),
            )
            .collect())
    }

    /// The key the token is bound to, when the delegation asks for one: the
    /// key that signed the agent in to mint it, or for a delegation a
    /// person granted, the agent's one active key, as
    /// [`TokenKey::bound_credential`] picks it.
    async fn binding(
        &self,
        tenant_id: &ScopedTenant,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<Option<Value>, DomainError> {
        let token_key = delegation.token_key();
        if token_key == TokenKey::Bearer {
            return Ok(None);
        }
        let credentials = self
            .credentials
            .list_for_agent(tenant_id, delegation.delegate())
            .await?;
        let Some(credential) = token_key.bound_credential(&credentials, clock::now())? else {
            return Ok(None);
        };
        let key = PublicKey::from_pem(credential.algorithm(), credential.public_key().as_str())
            .map_err(DomainError::infra)?;
        Ok(Some(json!({"jwk": bound_jwk(components(&key, ""))})))
    }

    /// Collects the delegation's claims with its audiences and credential binding.
    async fn claims(
        &self,
        tenant_id: &ScopedTenant,
        issuer: &Issuer,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<TaskTokenClaims, DomainError> {
        let constraints = delegation.constraints();
        let intent = enforced(delegation);
        let budget = constraints.budget().limit();
        Ok(TaskTokenClaims {
            iss: issuer.as_str().to_owned(),
            sub: delegation.delegator().id().to_string(),
            obo: delegation.delegator().label(),
            act: *delegation.delegate().as_uuid(),
            tid: *tenant_id.as_uuid(),
            aud: self.audiences(tenant_id, delegation).await?,
            jti: *delegation.id().as_uuid(),
            permissions: permissions(delegation),
            scope: delegation.granted().clone(),
            times: TokenTimes::of(delegation),
            ienv: intent.map(|intent| intent.envelope().allowed().to_vec()),
            idg: intent.map(|intent| data_encoding::HEXLOWER.encode(intent.digest().as_bytes())),
            bmax: budget.and_then(|budget| budget.max_requests().limit().copied()),
            bwin: budget.map(|budget| budget.window_seconds().get()),
            rsc: resource_scope(delegation),
            dcl: constraints
                .max_data_class()
                .limit()
                .map(|class| class.as_str().to_owned()),
            apr: constraints.requires_approval(),
            mcp: (!delegation.granted().mcp().is_empty())
                .then(|| delegation.granted().mcp().clone()),
            cnf: self.binding(tenant_id, delegation).await?,
        })
    }
}

#[async_trait]
impl TaskTokenIssuer for Pkcs8TaskTokenIssuer {
    async fn issue(
        &self,
        tenant_id: &ScopedTenant,
        issuer: &Issuer,
        delegation: &Delegation<ResolvedTenant>,
    ) -> Result<TaskToken, DomainError> {
        let claims = serde_json::to_string(&self.claims(tenant_id, issuer, delegation).await?)
            .map_err(DomainError::infra)?;
        let active = self.keys.active(tenant_id).await?;
        let token = signed(
            &claims,
            TokenHeader::new(
                JwtType::Access,
                active.key.kid().as_str(),
                active.key.algorithm(),
            ),
            &active.private,
        )
        .map_err(DomainError::infra)?;
        Ok(TaskToken::new(token))
    }
}

/// The tenant a task token names, read before its signature is checked,
/// only to choose whose keys check it.
#[derive(Debug, Deserialize)]
struct NamedTenant {
    tid: Uuid,
}

/// The check of a task token on the message plane, against the keys of the
/// tenant it names.
pub struct Pkcs8TaskTokenVerifier {
    keys: TenantKeys,
}

impl Pkcs8TaskTokenVerifier {
    /// A check against the tenant keys `signing_keys` holds, a rotated key
    /// still checking for `grace`.
    #[must_use]
    pub fn new(signing_keys: Arc<dyn SigningKeyStore>, grace: Lifetime) -> Self {
        Self {
            keys: TenantKeys::new(signing_keys, grace),
        }
    }
}

#[async_trait]
impl TaskTokenVerifier for Pkcs8TaskTokenVerifier {
    async fn verify(&self, credential: &Secret) -> Result<VerifiedTaskToken, DomainError> {
        let token =
            Compact::parse(credential.expose()).map_err(|_| refused("the token is no JWT"))?;
        let named: NamedTenant = token
            .unchecked_claims()
            .map_err(|_| refused("the token names no tenant"))?;
        let tenant = ScopedTenant::from_verified_credential(TenantId::from_uuid(named.tid));
        let key = self.keys.checking(&tenant, &token).await?;
        let claims: TaskTokenClaims = token
            .verified(&key, JwtType::Access)
            .map_err(|_| refused("the token does not check against the tenant's key"))?;
        verified_claims(claims, &tenant)
    }
}

/// Checks signed claims for message-plane use before returning their principal.
fn verified_claims(
    claims: TaskTokenClaims,
    tenant: &ScopedTenant,
) -> Result<VerifiedTaskToken, DomainError> {
    if !Audiences::Many(claims.aud.clone()).names(&task_token_audience(tenant)) {
        return Err(refused("the token was not minted for this tenant's agents"));
    }
    Times {
        exp: Some(claims.times.exp),
        nbf: None,
        iat: Some(claims.times.iat),
    }
    .hold_at(clock::now())?;
    if claims.cnf.is_some() {
        return Err(refused(
            "a token bound to a key cannot be used on the message plane",
        ));
    }
    let issuer = Issuer::new(claims.iss).map_err(|_| refused("the token names no issuer"))?;
    let principal = AgentPrincipal {
        tenant_id: **tenant,
        agent_id: AgentId::from_uuid(claims.act),
        delegation_id: DelegationId::from_uuid(claims.jti),
        subject: PrincipalRef::from_label(&claims.obo)
            .map_err(|_| refused("the token names no delegator"))?,
        caps: claims.scope,
    };
    Ok(VerifiedTaskToken { principal, issuer })
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::agents::{FakeAgentCredentialStore, delegation_row, key_row};
    use ianua_app::test_support::crypto::FakeSigningKeyStore;
    use ianua_app::test_support::routing::FakeServiceStore;
    use ianua_domain::domains::agents::authority::delegation::{DelegationRow, Lineage};
    use ianua_domain::domains::agents::identity::credential::{
        AgentCredential, AgentCredentialRow,
    };
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::types::{PublicKeyPem, UserId};

    use super::*;
    use crate::crypto::jws::keys_for_tests::pair;
    use crate::crypto::tokens::claims::tests::{grace, key_set};

    struct Fixture {
        tenant: ScopedTenant,
        issuer: Pkcs8TaskTokenIssuer,
        verifier: Pkcs8TaskTokenVerifier,
    }

    fn fixture() -> Fixture {
        let tenant = ScopedTenant::for_background(TenantId::new());
        let keys = Arc::new(FakeSigningKeyStore::empty());
        keys.put(*tenant, key_set().0);
        Fixture {
            issuer: Pkcs8TaskTokenIssuer::new(
                keys.clone(),
                grace(),
                Arc::new(FakeServiceStore::empty()),
                Arc::new(FakeAgentCredentialStore::empty()),
            ),
            verifier: Pkcs8TaskTokenVerifier::new(keys, grace()),
            tenant,
        }
    }

    fn delegation(row: DelegationRow) -> Delegation<ResolvedTenant> {
        Delegation::reconstitute(row).unwrap()
    }

    /// The tenant's own token issuer.
    fn acme() -> Issuer {
        Issuer::new("https://acme.ianua.example").unwrap()
    }

    fn granted() -> DelegationRow {
        delegation_row(AgentId::new(), PrincipalRef::User(UserId::new()))
    }

    /// A task token minted for a delegation reads back on the message
    /// plane as that delegation's agent, acting for its delegator, with the
    /// issuer it names for the broker to hold to the tenant's own.
    #[tokio::test]
    async fn a_task_token_reads_back_as_its_delegation() {
        let fx = fixture();
        let delegation = delegation(granted());

        let token = fx
            .issuer
            .issue(&fx.tenant, &acme(), &delegation)
            .await
            .unwrap();
        let verified = fx
            .verifier
            .verify(&Secret::new(token.reveal()))
            .await
            .unwrap();

        let principal = verified.principal;
        assert_eq!(verified.issuer, acme());
        assert_eq!(principal.tenant_id, *fx.tenant);
        assert_eq!(&principal.agent_id, delegation.delegate());
        assert_eq!(&principal.delegation_id, delegation.id());
        assert_eq!(principal.subject.label(), delegation.delegator().label());
    }

    /// Issued task tokens carry the tenant's configured issuer claim.
    #[tokio::test]
    async fn a_task_token_names_the_tenants_issuer() {
        let fx = fixture();

        let token = fx
            .issuer
            .issue(&fx.tenant, &acme(), &delegation(granted()))
            .await
            .unwrap();

        let claims: TaskTokenClaims = Compact::parse(token.reveal())
            .unwrap()
            .unchecked_claims()
            .unwrap();
        assert_eq!(claims.iss, acme().as_str());
    }

    /// A token minted from an expired delegation fails verification as unauthorized.
    #[tokio::test]
    async fn a_token_of_a_lapsed_delegation_is_refused() {
        let fx = fixture();
        let now = clock::now();
        let lapsed = delegation(DelegationRow {
            issued_at: now - time::Duration::minutes(30),
            expires_at: now - time::Duration::minutes(20),
            updated_at: now - time::Duration::minutes(30),
            ..granted()
        });

        let token = fx.issuer.issue(&fx.tenant, &acme(), &lapsed).await.unwrap();
        let read = fx.verifier.verify(&Secret::new(token.reveal())).await;

        assert!(matches!(read, Err(DomainError::Unauthorized(_))));
    }

    /// Issuing a bound token without the agent's key returns a conflict instead of a bearer.
    #[tokio::test]
    async fn a_bound_token_needs_the_agents_key() {
        let fx = fixture();
        let row = granted();
        let bound = delegation(DelegationRow {
            constraints: row.constraints.clone().sender_constrained(),
            ..row
        });

        let minted = fx.issuer.issue(&fx.tenant, &acme(), &bound).await;

        assert!(matches!(minted, Err(DomainError::Conflict(_))));
    }

    /// One of `agent`'s Ed25519 keys, named `kid`, with its public PEM.
    fn agent_key(agent: AgentId, kid: &str) -> (AgentCredential<ResolvedTenant>, String) {
        let (_, public) = pair(SigningAlgorithm::EdDsa);
        let credential = AgentCredential::reconstitute(AgentCredentialRow {
            algorithm: SigningAlgorithm::EdDsa,
            public_key: PublicKeyPem::new(public.clone()).unwrap(),
            ..key_row(agent, kid)
        })
        .unwrap();
        (credential, public)
    }

    /// A sender-constrained delegation minted using this agent credential.
    fn minted_with(
        credential: &AgentCredential<ResolvedTenant>,
        agent: AgentId,
    ) -> Delegation<ResolvedTenant> {
        let row = delegation_row(agent, PrincipalRef::Agent(agent));
        delegation(DelegationRow {
            constraints: row.constraints.clone().sender_constrained(),
            lineage: Lineage::Minted {
                from: vec![DelegationId::new()],
                delegator: PrincipalRef::User(UserId::new()),
                signed_in_with: *credential.id(),
            },
            ..row
        })
    }

    /// With two active agent keys, the token's confirmation names the key
    /// used to authenticate rather than the newer key.
    #[tokio::test]
    async fn a_bound_token_names_the_key_that_signed_the_agent_in() {
        let tenant = ScopedTenant::for_background(TenantId::new());
        let signing = Arc::new(FakeSigningKeyStore::empty());
        signing.put(*tenant, key_set().0);
        let agent = AgentId::new();
        let (k3, k3_public) = agent_key(agent, "k3");
        let (k2, _) = agent_key(agent, "k2");
        let credentials = Arc::new(FakeAgentCredentialStore::empty());
        for enrolled in [&k3, &k2] {
            credentials.save(&tenant, enrolled).await.unwrap();
        }
        let issuer = Pkcs8TaskTokenIssuer::new(
            signing,
            grace(),
            Arc::new(FakeServiceStore::empty()),
            credentials,
        );
        let minted = minted_with(&k3, agent);

        let token = issuer.issue(&tenant, &acme(), &minted).await.unwrap();

        let claims: TaskTokenClaims = Compact::parse(token.reveal())
            .unwrap()
            .unchecked_claims()
            .unwrap();
        let k3_key = PublicKey::from_pem(SigningAlgorithm::EdDsa, &k3_public).unwrap();
        assert_eq!(
            claims.cnf,
            Some(json!({"jwk": bound_jwk(components(&k3_key, ""))}))
        );
    }

    /// Verification is unauthorized for a tenant with no stored signing keys.
    #[tokio::test]
    async fn a_token_of_an_unknown_tenant_is_refused() {
        let fx = fixture();
        let token = fx
            .issuer
            .issue(&fx.tenant, &acme(), &delegation(granted()))
            .await
            .unwrap();
        let elsewhere =
            Pkcs8TaskTokenVerifier::new(Arc::new(FakeSigningKeyStore::empty()), grace());

        let read = elsewhere.verify(&Secret::new(token.reveal())).await;

        assert!(matches!(read, Err(DomainError::Unauthorized(_))));
    }
}
