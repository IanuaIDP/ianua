//! Workload tokens: the JWTs a Kubernetes cluster, GitHub Actions or
//! another trusted OIDC issuer hands a workload, made for the binding of
//! one bootstrap's challenge and the key it enrols.
//!
//! The token's audience must be that binding, in lower-case hex, and
//! nothing else. A workload asks its platform for exactly that audience:
//!
//! - Kubernetes: a `TokenRequest` for its own service account,
//!   `POST /api/v1/namespaces/{namespace}/serviceaccounts/{name}/token` with
//!   `spec.audiences` the binding and `spec.expirationSeconds` 600, the
//!   least the API server takes, or `kubectl create token <name>
//!   --audience <binding> --duration 10m`. The service account needs
//!   `create` on `serviceaccounts/token`, which no default role grants a
//!   pod. A projected volume will not do: its audience is fixed when the
//!   pod starts. The token names `system:serviceaccount:<namespace>:<name>`
//!   and carries a `kubernetes.io` claim with the namespace and service
//!   account, which must agree with the subject. The API server signs
//!   with RS256 for an RSA key and ES256, ES384 or ES512 for an ECDSA key
//!   on P-256, P-384 or P-521, and always names the key (`kid`).
//!   <https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/>,
//!   <https://github.com/kubernetes/kubernetes/blob/master/pkg/serviceaccount/jwt.go>,
//!   <https://kubernetes.io/docs/concepts/storage/projected-volumes/>,
//!   <https://kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_token/>,
//!   <https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/>.
//! - GitHub Actions: a job with `permissions: id-token: write` calls
//!   `$ACTIONS_ID_TOKEN_REQUEST_URL&audience=<binding>` with
//!   `Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN`, or
//!   `core.getIDToken('<binding>')`, and presents the `value` it answers.
//!   GitHub signs with RS256 only, as its discovery document lists.
//!   <https://docs.github.com/en/actions/reference/security/oidc>,
//!   <https://docs.github.com/en/actions/concepts/security/openid-connect>.
//! - Another OIDC issuer: any whose discovery document and key set follow
//!   OpenID Connect Discovery 1.0 and that issues a token for an audience
//!   the workload names per request, such as through the `audience`
//!   parameter of a token exchange (RFC 8693, section 2.1). An issuer that
//!   cannot cannot attest. RS256, ES256, ES384 and ES512 are taken.
//!   <https://openid.net/specs/openid-connect-discovery-1_0.html>,
//!   <https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1>.
//!
//! Azure managed identities are not here: an identity's token is only for
//! an audience registered in Entra ID, so it cannot carry the binding.
//!
//! The token's `iss` is read before anything is trusted, only to refuse an
//! issuer the policy does not trust: no keys are fetched for one. The keys
//! of a trusted issuer are read through [`IssuerKeys`], and asked for again
//! once when the token names a key they lack. The algorithm is pinned for
//! each kind and must be the one the named key signs with, never the
//! header's choice, never `none`. The token must hold at its times, with
//! one allowed skew, and may not have been made to live longer than
//! [`LONGEST_LIFETIME`] seconds.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::agents::{
    PresentedWorkloadToken, VerifiedWorkloadClaims, WorkloadTokenVerifier,
};
use ianua_domain::domains::agents::identity::attestation::{
    WorkloadIssuer, WorkloadKind, WorkloadSubject,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::crypto::jws::{Compact, JwsAlgorithm};
use crate::crypto::{Audiences, Times};
use crate::proofs::attestation::published::{IssuerKeys, named_key};
use crate::proofs::attestation::{AttestationBinding, MOST_MATERIAL, refused};

/// The longest a workload token may have been made to live, in seconds.
///
/// A Kubernetes `TokenRequest` lives an hour unless it asks for less, and
/// at least ten minutes; GitHub's documented token lives five minutes. A
/// token made for one bootstrap needs no more. Longer ones, such as the
/// year-long tokens a cluster writes for its own API server, are refused.
const LONGEST_LIFETIME: i64 = 3600;

/// What every Kubernetes service account subject starts with.
const SERVICE_ACCOUNT_PREFIX: &str = "system:serviceaccount:";

/// The algorithms the tokens of `kind` are taken signed with: GitHub's
/// one, and for a cluster or an issuer the RSA and ECDSA ones a cluster
/// signs with, chosen by its key (RS256 for RSA, ES256, ES384 or ES512 for
/// ECDSA on P-256, P-384 or P-521).
fn algorithms(kind: WorkloadKind) -> &'static [JwsAlgorithm] {
    match kind {
        WorkloadKind::GithubActions => &[JwsAlgorithm::Rs256],
        WorkloadKind::Kubernetes | WorkloadKind::Oidc => &[
            JwsAlgorithm::Rs256,
            JwsAlgorithm::Es256,
            JwsAlgorithm::Es384,
            JwsAlgorithm::Es512,
        ],
    }
}

/// The issuer a token claims, read before its signature is checked.
#[derive(Deserialize)]
struct ClaimedIssuer {
    iss: String,
}

/// The claims a verified workload token is read for.
#[derive(Deserialize)]
struct WorkloadClaims {
    iss: String,
    aud: Audiences,
    sub: String,
    #[serde(rename = "kubernetes.io", default)]
    kubernetes: Option<KubernetesClaim>,
    #[serde(flatten)]
    times: Times,
}

/// The `kubernetes.io` claim of a service account token.
#[derive(Deserialize)]
struct KubernetesClaim {
    namespace: String,
    serviceaccount: NamedObject,
}

/// An object a Kubernetes token names.
#[derive(Deserialize)]
struct NamedObject {
    name: String,
}

/// The check of workload tokens against the keys their trusted issuers
/// publish and the binding of the bootstrap they are presented for.
pub struct JwksWorkloadTokenVerifier {
    keys: Arc<dyn IssuerKeys>,
}

impl JwksWorkloadTokenVerifier {
    /// A check reading issuers' keys through `keys`, such as
    /// [`DiscoveredIssuerKeys`](crate::proofs::attestation::DiscoveredIssuerKeys).
    #[must_use]
    pub fn new(keys: Arc<dyn IssuerKeys>) -> Self {
        Self { keys }
    }
}

#[async_trait]
impl WorkloadTokenVerifier for JwksWorkloadTokenVerifier {
    async fn verify(
        &self,
        presented: &PresentedWorkloadToken<'_>,
    ) -> Result<VerifiedWorkloadClaims, DomainError> {
        let binding = AttestationBinding::of(presented.nonce, &presented.key.public_key)?;
        let token = read_token(presented.token.expose())?;
        let issuer = trusted_issuer(&token, presented.trusted_issuers)?;
        let key = named_key(
            self.keys.as_ref(),
            issuer,
            &token,
            algorithms(presented.kind),
        )
        .await?;
        let claims: WorkloadClaims = token
            .verified_untyped(&key)
            .map_err(|_| refused("the token does not check against its issuer's key"))?;
        ensure_held(&claims, issuer, &binding, clock::now())?;
        ensure_kind_claims(presented.kind, &claims)?;
        Ok(VerifiedWorkloadClaims {
            issuer: issuer.clone(),
            subject: WorkloadSubject::new(claims.sub)
                .map_err(|_| refused("the token names no workload"))?,
        })
    }
}

/// `text` split as a JWT, refused when it is longer than any token.
fn read_token(text: &str) -> Result<Compact, DomainError> {
    if text.len() > MOST_MATERIAL {
        return Err(refused("the token is too long"));
    }
    Compact::parse(text).map_err(|_| refused("the token is no JWT"))
}

/// The issuer of `trusted` the token claims, before anything else of it is
/// believed.
fn trusted_issuer<'a>(
    token: &Compact,
    trusted: &'a [WorkloadIssuer],
) -> Result<&'a WorkloadIssuer, DomainError> {
    let claimed: ClaimedIssuer = token
        .unchecked_claims()
        .map_err(|_| refused("the token names no issuer"))?;
    trusted
        .iter()
        .find(|issuer| issuer.as_str() == claimed.iss)
        .ok_or_else(|| refused("the token's issuer is not trusted"))
}

/// Refused unless the verified claims name `issuer`, hold at `now`, were
/// made to live no longer than [`LONGEST_LIFETIME`], and are for
/// `binding` alone.
fn ensure_held(
    claims: &WorkloadClaims,
    issuer: &WorkloadIssuer,
    binding: &AttestationBinding,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    if claims.iss != issuer.as_str() {
        return Err(refused("the token names another issuer"));
    }
    claims.times.hold_at(now)?;
    ensure_short_lived(claims.times)?;
    if !is_for_only(&claims.aud, binding.as_hex()) {
        return Err(refused("the token was not made for this bootstrap and key"));
    }
    Ok(())
}

/// Whether `aud` names `binding` and nothing else.
fn is_for_only(aud: &Audiences, binding: &str) -> bool {
    matches!(aud.all().as_slice(), [only] if only == binding)
}

/// Refused unless the token names when it was issued and was made to live
/// no longer than [`LONGEST_LIFETIME`].
fn ensure_short_lived(times: Times) -> Result<(), DomainError> {
    let (Some(exp), Some(iat)) = (times.exp, times.iat) else {
        return Err(refused("the token names no issue time"));
    };
    if exp.saturating_sub(iat) > LONGEST_LIFETIME {
        return Err(refused("the token was made to live too long"));
    }
    Ok(())
}

/// Refused unless the claims only a `kind` token carries agree with it.
fn ensure_kind_claims(kind: WorkloadKind, claims: &WorkloadClaims) -> Result<(), DomainError> {
    match kind {
        WorkloadKind::Kubernetes => ensure_service_account(claims),
        WorkloadKind::GithubActions | WorkloadKind::Oidc => Ok(()),
    }
}

/// Refused unless the `kubernetes.io` claim names the service account the
/// subject does.
fn ensure_service_account(claims: &WorkloadClaims) -> Result<(), DomainError> {
    let Some(bound) = &claims.kubernetes else {
        return Err(refused("the token names no service account"));
    };
    let named = format!(
        "{SERVICE_ACCOUNT_PREFIX}{}:{}",
        bound.namespace, bound.serviceaccount.name
    );
    if named != claims.sub {
        return Err(refused("the token's service account and subject differ"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P384_SHA384_FIXED_SIGNING, ECDSA_P521_SHA512_FIXED_SIGNING, EcdsaKeyPair,
        EcdsaSigningAlgorithm, KeyPair as _,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ianua_app::ports::agents::EnrolledKey;
    use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
    use ianua_domain::domains::crypto::jwk::JwkComponents;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::shared::security::secret::Secret;
    use serde_json::{Value, json};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    use super::*;
    use crate::crypto::jws::keys_for_tests::pair;
    use crate::crypto::jws::{PrivateKey, PublicKey, components};
    use crate::proofs::attestation::discovered::tests::{StandIn, keeping, over_plain_http};
    use crate::proofs::attestation::published::KeyKeeping;
    use crate::proofs::attestation::tests::enrolled_key;

    const NONCE: &str = "workload-bootstrap-nonce-0123456789abcdef";

    /// Where a Kubernetes API server publishes its key set.
    const CLUSTER_KEYS: &str = "/openid/v1/jwks";

    /// Where GitHub publishes its key set, as its discovery document names.
    const GITHUB_KEYS: &str = "/.well-known/jwks";

    /// A stand-in issuer signing with one key of its algorithm, published
    /// under `kid`.
    struct Issuer {
        stand_in: StandIn,
        signer: PrivateKey,
        jwk: Value,
    }

    /// A fresh key of `algorithm` as its private half and its JWK, listed
    /// under `kid`.
    fn key_of(algorithm: SigningAlgorithm, kid: &str) -> (PrivateKey, Value) {
        let (private, public) = pair(algorithm);
        let signer = PrivateKey::from_pem(algorithm, &private).unwrap();
        let public = PublicKey::from_pem(algorithm, &public).unwrap();
        let jwk = match components(&public, kid) {
            JwkComponents::Rsa { kid, n, e } => {
                json!({"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": n, "e": e})
            }
            JwkComponents::Ec { kid, crv, x, y } => {
                json!({"kty": "EC", "alg": "ES256", "use": "sig", "kid": kid, "crv": crv, "x": x, "y": y})
            }
            JwkComponents::Okp { .. } => unreachable!("no workload issuer signs with Ed25519"),
        };
        (signer, jwk)
    }

    /// An issuer publishing one `algorithm` key at `keys_path` through its
    /// discovery document.
    async fn issuer(algorithm: SigningAlgorithm, keys_path: &str) -> Issuer {
        let stand_in = StandIn::start().await;
        let (signer, jwk) = key_of(algorithm, "key-1");
        stand_in
            .publishing(stand_in.issuer.as_str(), keys_path, json!({"keys": [jwk]}))
            .await;
        Issuer {
            stand_in,
            signer,
            jwk,
        }
    }

    impl Issuer {
        fn name(&self) -> &str {
            self.stand_in.issuer.as_str()
        }

        /// `claims` under `header`, signed with this issuer's key whatever
        /// the header names.
        fn signed(&self, header: &Value, claims: &Value) -> Secret {
            signed_by(&self.signer, header, claims)
        }

        /// The header the API server writes for this issuer's key: `alg`
        /// and `kid` alone.
        fn cluster_header(&self) -> Value {
            json!({"alg": self.jwk["alg"], "kid": self.jwk["kid"]})
        }
    }

    /// `claims` under `header`, signed by `signer` whatever the header
    /// names.
    fn signed_by(signer: &PrivateKey, header: &Value, claims: &Value) -> Secret {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = signer.sign(input.as_bytes()).unwrap();
        Secret::new(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    fn now() -> i64 {
        clock::now().unix_timestamp()
    }

    fn nonce() -> AttestationNonce {
        AttestationNonce::new(NONCE).unwrap()
    }

    /// The binding of `nonce` and `key`, as the workload asks for its
    /// audience.
    fn binding(nonce: &AttestationNonce, key: &EnrolledKey) -> String {
        AttestationBinding::of(nonce, &key.public_key)
            .unwrap()
            .as_hex()
            .to_owned()
    }

    /// The service account token payload the Kubernetes documentation
    /// shows for `my-serviceaccount` bound to `my-pod`
    /// (<https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/>,
    /// "Schema for service account private claims"), with the stand-in's
    /// issuer, the binding as its audience, and times from now that keep
    /// its hour's lifetime.
    fn cluster_claims(iss: &str, aud: &str, iat: i64) -> Value {
        json!({
            "aud": [aud],
            "exp": iat + 3600,
            "iat": iat,
            "iss": iss,
            "jti": "aed34954-b33a-4142-b1ec-389d6bbb4936",
            "kubernetes.io": {
                "namespace": "my-namespace",
                "node": {"name": "my-node", "uid": "646e7c5e-32d6-4d42-9dbd-e504e6cbe6b1"},
                "pod": {"name": "my-pod", "uid": "5e0bd49b-f040-43b0-99b7-22765a53f7f3"},
                "serviceaccount": {
                    "name": "my-serviceaccount",
                    "uid": "14ee3fa4-a7e2-420f-9f9a-dbc4507c3798"
                }
            },
            "nbf": iat,
            "sub": "system:serviceaccount:my-namespace:my-serviceaccount"
        })
    }

    /// The token GitHub's documentation shows
    /// (<https://docs.github.com/en/actions/concepts/security/openid-connect>,
    /// "Understanding the OIDC token"), with the stand-in's issuer, the
    /// binding as its audience, and times from now spaced as there:
    /// `nbf` ten minutes before `iat`, `exp` five after.
    fn github_claims(iss: &str, aud: &str, iat: i64) -> Value {
        json!({
            "jti": "example-id",
            "sub": "repo:octo-org/octo-repo:environment:prod",
            "environment": "prod",
            "aud": aud,
            "ref": "refs/heads/main",
            "sha": "example-sha",
            "repository": "octo-org/octo-repo",
            "repository_owner": "octo-org",
            "actor_id": "12",
            "repository_visibility": "private",
            "repository_id": "74",
            "repository_owner_id": "65",
            "run_id": "example-run-id",
            "run_number": "10",
            "run_attempt": "2",
            "runner_environment": "github-hosted",
            "actor": "octocat",
            "workflow": "example-workflow",
            "head_ref": "",
            "base_ref": "",
            "event_name": "workflow_dispatch",
            "repo_property_workspace_id": "ws-abc123",
            "ref_type": "branch",
            "job_workflow_ref": "octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main",
            "iss": iss,
            "nbf": iat - 600,
            "exp": iat + 300,
            "iat": iat
        })
    }

    /// The header GitHub's documentation shows, naming this issuer's key.
    fn github_header(issuer: &Issuer) -> Value {
        json!({"typ": "JWT", "alg": "RS256", "x5t": "example-thumbprint", "kid": issuer.jwk["kid"]})
    }

    /// What a bootstrap presents: a token of `kind` for `issuer`, the
    /// issuers trusted, the challenge and the key.
    struct Bootstrap {
        kind: WorkloadKind,
        token: Secret,
        trusted: Vec<WorkloadIssuer>,
        nonce: AttestationNonce,
        key: EnrolledKey,
    }

    impl Bootstrap {
        fn of(kind: WorkloadKind, issuer: &Issuer, token: Secret, key: EnrolledKey) -> Self {
            Self {
                kind,
                token,
                trusted: vec![issuer.stand_in.issuer.clone()],
                nonce: nonce(),
                key,
            }
        }

        /// The verdict of a verifier reading keys kept as `keeping` says.
        async fn verified_keeping(
            &self,
            keeping: KeyKeeping,
        ) -> Result<VerifiedWorkloadClaims, DomainError> {
            JwksWorkloadTokenVerifier::new(Arc::new(over_plain_http(keeping)))
                .verify(&PresentedWorkloadToken {
                    kind: self.kind,
                    token: &self.token,
                    trusted_issuers: &self.trusted,
                    nonce: &self.nonce,
                    key: &self.key,
                })
                .await
        }

        async fn verified(&self) -> Result<VerifiedWorkloadClaims, DomainError> {
            self.verified_keeping(keeping()).await
        }
    }

    /// A Kubernetes token of the documented shape, made for `key`'s
    /// binding, presented with `key`.
    fn cluster_bootstrap(issuer: &Issuer, claims: &Value, key: EnrolledKey) -> Bootstrap {
        let token = issuer.signed(&issuer.cluster_header(), claims);
        Bootstrap::of(WorkloadKind::Kubernetes, issuer, token, key)
    }

    fn refused_as_unauthorized(read: &Result<VerifiedWorkloadClaims, DomainError>) -> bool {
        matches!(read, Err(DomainError::Unauthorized(_)))
    }

    /// A service account token the cluster signed with RS256 for the
    /// binding verifies, naming the cluster and the service account.
    #[tokio::test]
    async fn a_cluster_token_for_the_binding_verifies() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());

        let verified = cluster_bootstrap(&cluster, &claims, key)
            .verified()
            .await
            .unwrap();

        assert_eq!(verified.issuer, cluster.stand_in.issuer);
        assert_eq!(
            verified.subject.as_str(),
            "system:serviceaccount:my-namespace:my-serviceaccount"
        );
    }

    /// A cluster whose service account key is a P-256 key signs with
    /// ES256, and its token verifies.
    #[tokio::test]
    async fn a_cluster_signing_with_es256_is_taken() {
        let cluster = issuer(SigningAlgorithm::Es256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());

        let verified = cluster_bootstrap(&cluster, &claims, key).verified().await;

        assert!(verified.is_ok());
    }

    /// A fresh ECDSA key for `signing`, and its JWK on `crv` for `alg`,
    /// listed under `key-1`, as a cluster with such a key publishes it.
    fn wide_curve_key(
        signing: &'static EcdsaSigningAlgorithm,
        crv: &str,
        alg: &str,
    ) -> (EcdsaKeyPair, Value) {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(signing, &SystemRandom::new()).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(signing, pkcs8.as_ref()).unwrap();
        let point = pair.public_key().as_ref().get(1..).unwrap().to_vec();
        let (x, y) = point.split_at(point.len() / 2);
        let jwk = json!({
            "kty": "EC", "crv": crv, "alg": alg, "use": "sig", "kid": "key-1",
            "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y)
        });
        (pair, jwk)
    }

    /// `claims` under `header`, signed by `signer` as JWS writes ECDSA.
    fn wide_curve_signed(signer: &EcdsaKeyPair, header: &Value, claims: &Value) -> Secret {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = signer.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
        Secret::new(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }

    /// The verdict on a cluster token signed by `signer` under `alg`, the
    /// cluster publishing `published`.
    async fn wide_curve_verdict(
        published: Value,
        signer: &EcdsaKeyPair,
        alg: &str,
    ) -> Result<VerifiedWorkloadClaims, DomainError> {
        let cluster = StandIn::start().await;
        cluster
            .publishing(
                cluster.issuer.as_str(),
                CLUSTER_KEYS,
                json!({"keys": [published]}),
            )
            .await;
        let key = enrolled_key();
        let claims = cluster_claims(cluster.issuer.as_str(), &binding(&nonce(), &key), now());
        Bootstrap {
            kind: WorkloadKind::Kubernetes,
            token: wide_curve_signed(signer, &json!({"alg": alg, "kid": "key-1"}), &claims),
            trusted: vec![cluster.issuer.clone()],
            nonce: nonce(),
            key,
        }
        .verified()
        .await
    }

    /// A cluster whose service account key is ECDSA on P-384 or P-521
    /// signs with ES384 or ES512, as Kubernetes picks by the key, and its
    /// token verifies.
    #[tokio::test]
    async fn a_cluster_signing_with_es384_or_es512_is_taken() {
        let (p384, p384_jwk) = wide_curve_key(&ECDSA_P384_SHA384_FIXED_SIGNING, "P-384", "ES384");
        let (p521, p521_jwk) = wide_curve_key(&ECDSA_P521_SHA512_FIXED_SIGNING, "P-521", "ES512");

        let es384 = wide_curve_verdict(p384_jwk, &p384, "ES384").await;
        let es512 = wide_curve_verdict(p521_jwk, &p521, "ES512").await;

        assert!(es384.is_ok());
        assert!(es512.is_ok());
    }

    /// A foreign P-384 signature and an ES512 declaration for a P-384 key both fail verification.
    #[tokio::test]
    async fn a_wide_curve_token_not_signed_by_the_cluster_is_refused() {
        let (_, published) = wide_curve_key(&ECDSA_P384_SHA384_FIXED_SIGNING, "P-384", "ES384");
        let (forger, _) = wide_curve_key(&ECDSA_P384_SHA384_FIXED_SIGNING, "P-384", "ES384");
        let (own, own_jwk) = wide_curve_key(&ECDSA_P384_SHA384_FIXED_SIGNING, "P-384", "ES384");

        let forged = wide_curve_verdict(published, &forger, "ES384").await;
        let renamed = wide_curve_verdict(own_jwk, &own, "ES512").await;

        assert!(forged.is_err());
        assert!(renamed.is_err());
    }

    /// A GitHub Actions token of the documented shape, made for the
    /// binding, verifies and names the workflow's subject.
    #[tokio::test]
    async fn a_github_token_for_the_binding_verifies() {
        let github = issuer(SigningAlgorithm::Rs256, GITHUB_KEYS).await;
        let key = enrolled_key();
        let claims = github_claims(github.name(), &binding(&nonce(), &key), now());
        let token = github.signed(&github_header(&github), &claims);

        let verified = Bootstrap::of(WorkloadKind::GithubActions, &github, token, key)
            .verified()
            .await
            .unwrap();

        assert_eq!(
            verified.subject.as_str(),
            "repo:octo-org/octo-repo:environment:prod"
        );
    }

    /// Missing and malformed workload tokens produce unauthorized errors.
    #[tokio::test]
    async fn a_missing_token_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;

        for text in ["", "not.a.jwt", "x"] {
            let bootstrap = Bootstrap::of(
                WorkloadKind::Kubernetes,
                &cluster,
                Secret::new(text),
                enrolled_key(),
            );

            assert!(
                refused_as_unauthorized(&bootstrap.verified().await),
                "{text:?}"
            );
        }
    }

    /// An expired workload token cannot attest the workload despite a trusted issuer.
    #[tokio::test]
    async fn an_expired_token_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now() - 7200);

        let read = cluster_bootstrap(&cluster, &claims, key).verified().await;

        assert!(refused_as_unauthorized(&read));
    }

    /// A future not-before time makes the workload token unauthorized now.
    #[tokio::test]
    async fn a_token_not_yet_valid_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let mut claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());
        claims["nbf"] = json!(now() + 600);

        let read = cluster_bootstrap(&cluster, &claims, key).verified().await;

        assert!(refused_as_unauthorized(&read));
    }

    /// A year-long cluster token exceeds the attestor's one-hour lifetime limit.
    #[tokio::test]
    async fn a_token_made_to_live_too_long_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let iat = now();
        let mut claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), iat);
        claims["exp"] = json!(iat + 31_536_000);
        claims["kubernetes.io"]["warnafter"] = json!(iat + 3607);

        let read = cluster_bootstrap(&cluster, &claims, key).verified().await;

        assert!(refused_as_unauthorized(&read));
    }

    /// An untrusted issuer makes the token unauthorized without any request to its server.
    #[tokio::test]
    async fn a_token_from_an_untrusted_issuer_is_refused_before_any_fetch() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let claims = cluster_claims(
            "https://oidc.mallory.example",
            &binding(&nonce(), &key),
            now(),
        );

        let read = cluster_bootstrap(&cluster, &claims, key).verified().await;

        assert!(refused_as_unauthorized(&read));
        assert!(
            cluster
                .stand_in
                .server
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A policy with no trusted issuer of this kind rejects the workload token.
    #[tokio::test]
    async fn a_token_with_no_issuer_trusted_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());
        let mut bootstrap = cluster_bootstrap(&cluster, &claims, key);
        bootstrap.trusted.clear();

        assert!(refused_as_unauthorized(&bootstrap.verified().await));
    }

    /// A GitHub token addressed to the repository owner does not satisfy the attestation audience.
    #[tokio::test]
    async fn a_token_for_another_audience_is_refused() {
        let github = issuer(SigningAlgorithm::Rs256, GITHUB_KEYS).await;
        let claims = github_claims(github.name(), "https://github.com/octo-org", now());
        let token = github.signed(&github_header(&github), &claims);

        let read = Bootstrap::of(WorkloadKind::GithubActions, &github, token, enrolled_key())
            .verified()
            .await;

        assert!(refused_as_unauthorized(&read));
    }

    /// A workload token bound to one enrolled key is unauthorized for a different key.
    #[tokio::test]
    async fn a_token_made_for_another_key_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let workload = enrolled_key();
        let claims = cluster_claims(cluster.name(), &binding(&nonce(), &workload), now());

        let read = cluster_bootstrap(&cluster, &claims, enrolled_key())
            .verified()
            .await;

        assert!(refused_as_unauthorized(&read));
    }

    /// A token bound to an earlier challenge cannot satisfy the current attestation challenge.
    #[tokio::test]
    async fn a_token_made_for_another_challenge_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let earlier = AttestationNonce::new("an-earlier-bootstrap-nonce-0123456789ab").unwrap();
        let claims = cluster_claims(cluster.name(), &binding(&earlier, &key), now());

        let read = cluster_bootstrap(&cluster, &claims, key).verified().await;

        assert!(refused_as_unauthorized(&read));
    }

    /// Including another audience alongside the correct binding makes a workload token unauthorized.
    #[tokio::test]
    async fn a_token_for_the_binding_and_another_audience_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let mut claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());
        claims["aud"] = json!([binding(&nonce(), &key), "vault"]);

        let read = cluster_bootstrap(&cluster, &claims, key).verified().await;

        assert!(refused_as_unauthorized(&read));
    }

    /// An unknown key ID remains unauthorized after the issuer's keys are consulted.
    #[tokio::test]
    async fn a_token_naming_an_unknown_key_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());
        let token = cluster.signed(&json!({"alg": "RS256", "kid": "key-9"}), &claims);

        let read = Bootstrap::of(WorkloadKind::Kubernetes, &cluster, token, key)
            .verified()
            .await;

        assert!(refused_as_unauthorized(&read));
    }

    /// A cluster that rotated its key since its keys were kept is asked
    /// again once, and the token signed with the new key verifies.
    #[tokio::test]
    async fn an_issuer_that_rotated_its_key_is_asked_again_once() {
        let cluster = rotating_issuer().await;
        let key = enrolled_key();
        let claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());
        let renewing = KeyKeeping {
            renew_after: Duration::ZERO,
            ..keeping()
        };

        let read = cluster_bootstrap(&cluster, &claims, key)
            .verified_keeping(renewing)
            .await;

        assert!(read.is_ok());
        assert_eq!(
            cluster
                .stand_in
                .server
                .received_requests()
                .await
                .unwrap()
                .len(),
            4
        );
    }

    /// Publishes a retired key once, then the current signing key on later reads.
    async fn rotating_issuer() -> Issuer {
        let stand_in = StandIn::start().await;
        let (_, old) = key_of(SigningAlgorithm::Rs256, "key-0");
        let (signer, new) = key_of(SigningAlgorithm::Rs256, "key-1");
        Mock::given(method("GET"))
            .and(path(CLUSTER_KEYS))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": [old]})))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&stand_in.server)
            .await;
        stand_in
            .publishing(
                stand_in.issuer.as_str(),
                CLUSTER_KEYS,
                json!({"keys": [new]}),
            )
            .await;
        Issuer {
            stand_in,
            signer,
            jwk: new,
        }
    }

    /// Headers declaring `none`, HS256, ES256 or RS512 cannot override the published RSA key's algorithm.
    #[tokio::test]
    async fn a_token_naming_another_algorithm_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());

        for alg in ["none", "HS256", "ES256", "RS512"] {
            let token = cluster.signed(&json!({"alg": alg, "kid": "key-1"}), &claims);
            let bootstrap = Bootstrap::of(WorkloadKind::Kubernetes, &cluster, token, key.clone());

            assert!(
                refused_as_unauthorized(&bootstrap.verified().await),
                "{alg}"
            );
        }
    }

    /// The GitHub attestor rejects ES256 even when the issuer publishes the corresponding P-256 key.
    #[tokio::test]
    async fn a_github_token_signed_with_another_algorithm_is_refused() {
        let github = issuer(SigningAlgorithm::Es256, GITHUB_KEYS).await;
        let key = enrolled_key();
        let claims = github_claims(github.name(), &binding(&nonce(), &key), now());
        let token = github.signed(
            &json!({"typ": "JWT", "alg": "ES256", "kid": "key-1"}),
            &claims,
        );

        let read = Bootstrap::of(WorkloadKind::GithubActions, &github, token, key)
            .verified()
            .await;

        assert!(refused_as_unauthorized(&read));
    }

    /// Naming a published key ID cannot validate a signature made with another key.
    #[tokio::test]
    async fn a_token_signed_by_another_key_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let (forger, _) = key_of(SigningAlgorithm::Rs256, "key-1");
        let key = enrolled_key();
        let claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());
        let token = signed_by(&forger, &cluster.cluster_header(), &claims);

        let read = Bootstrap::of(WorkloadKind::Kubernetes, &cluster, token, key)
            .verified()
            .await;

        assert!(refused_as_unauthorized(&read));
    }

    /// An unreachable issuer causes workload-token verification to fail.
    #[tokio::test]
    async fn a_token_whose_issuer_cannot_be_reached_is_refused() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let gone = WorkloadIssuer::new(format!("https://localhost:{port}")).unwrap();
        let (signer, _) = key_of(SigningAlgorithm::Rs256, "key-1");
        let key = enrolled_key();
        let claims = cluster_claims(gone.as_str(), &binding(&nonce(), &key), now());
        let bootstrap = Bootstrap {
            kind: WorkloadKind::Kubernetes,
            token: signed_by(&signer, &json!({"alg": "RS256", "kid": "key-1"}), &claims),
            trusted: vec![gone],
            nonce: nonce(),
            key,
        };

        assert!(bootstrap.verified().await.is_err());
    }

    /// Missing service-account claims or disagreement with the subject make a cluster token unauthorized.
    #[tokio::test]
    async fn a_cluster_token_whose_service_account_differs_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());
        let mut other = claims.clone();
        other["kubernetes.io"]["serviceaccount"]["name"] = json!("runner");
        let mut none = claims;
        none.as_object_mut().unwrap().remove("kubernetes.io");

        for claims in [other, none] {
            let read = cluster_bootstrap(&cluster, &claims, key.clone())
                .verified()
                .await;

            assert!(refused_as_unauthorized(&read));
        }
    }

    /// A workload token without an issue time fails the lifetime check.
    #[tokio::test]
    async fn a_token_naming_no_issue_time_is_refused() {
        let cluster = issuer(SigningAlgorithm::Rs256, CLUSTER_KEYS).await;
        let key = enrolled_key();
        let mut claims = cluster_claims(cluster.name(), &binding(&nonce(), &key), now());
        claims.as_object_mut().unwrap().remove("iat");

        let read = cluster_bootstrap(&cluster, &claims, key).verified().await;

        assert!(refused_as_unauthorized(&read));
    }
}
