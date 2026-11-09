//! The runner beside an agent's sandbox asking the platform's API for what
//! it holds on the agent's behalf: a key, by attesting its workload, and
//! task tokens, by exchanging an assertion that key signs.
//!
//! A key is made in the runner's memory and never leaves it: only its
//! public half is enrolled, by an attestation carrying the binding of the
//! platform's nonce and that key, signed with the workload's SVID key, so
//! nobody who saw the SVID can enrol a key of their own. A key is attested
//! again halfway to its end, and a token exchanged again a little before
//! its end or once the key it was exchanged with changed. One attestation
//! and one exchange of each kind run at a time.
//!
//! Every call is held to its time limit, follows no redirect and reads its
//! answer within a size limit. A refusal from the platform is an
//! `Unauthorized` error; anything else that fails is an infrastructure
//! error. Neither names the key, the token or the SVID.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::agents::{RunnerKey, RunnerKeys, RunnerTokens, TaskToken};
use ianua_app::ports::crypto::KeyGenerator as _;
use ianua_domain::domains::agents::authority::capability::TokenBinding;
use ianua_domain::domains::agents::identity::challenge::AttestationNonce;
use ianua_domain::domains::agents::runner::{key_renewal, token_renewal};
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AgentId, Audience, KeyId, PublicKeyPem, Seconds};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use url::Url;

use crate::crypto::Pkcs8KeyGenerator;
use crate::http::client::{body_within, fixed};
use crate::proofs::AttestationBinding;
use crate::proofs::runner::{assertion, svid_signature};

/// The largest answer read back from the platform: a credential or a task
/// token with what it grants.
const MOST_ANSWER_BYTES: usize = 64 * 1024;

/// The largest SVID file read: a chain of a few certificates, or a key.
const MOST_SVID_BYTES: u64 = 64 * 1024;

/// The agent the runner acts for, and where the platform's API serves it.
#[derive(Debug, Clone)]
pub struct RunnerAgent {
    /// Selects whose bootstrap and token endpoints the runner calls.
    pub agent: AgentId,
    /// The tenant's agents collection on the API, such as
    /// `https://ianua.example/api/v1/organizations/acme/tenants/prod/agents`.
    pub agents_url: Url,
}

impl RunnerAgent {
    /// The address of `rest` under the agent, such as `token`.
    fn url_of(&self, rest: &str) -> Result<Url, DomainError> {
        let base = self.agents_url.as_str().trim_end_matches('/');
        Url::parse(&format!("{base}/{}/{rest}", self.agent)).map_err(DomainError::infra)
    }
}

/// What the runner asks for when it exchanges a task token.
#[derive(Debug, Clone)]
pub struct TokenAsk {
    /// The audience its assertion names: the token endpoint's identifier,
    /// the platform's `AGENT_TOKEN_AUDIENCE`.
    pub audience: Audience,
    /// The capabilities asked for, in the API's form. The platform caps
    /// them by what people delegated to the agent.
    pub granted: Value,
    /// How long each token lives.
    pub lifetime: Seconds,
}

/// The files a SPIFFE helper keeps the runner's SVID in, read again at
/// each attestation since the helper rotates them in place.
#[derive(Debug, Clone)]
pub struct SvidFiles {
    /// The SVID, PEM, the leaf first.
    pub chain: PathBuf,
    /// Its private key, PKCS#8 PEM.
    pub key: PathBuf,
}

/// A key the platform enrolled for the agent, and when to attest again.
struct HeldKey {
    key: RunnerKey,
    renew_at: OffsetDateTime,
}

/// The runner's key, made in its memory and enrolled by attesting its
/// workload with its SPIFFE SVID.
pub struct HttpRunnerKeys {
    client: reqwest::Client,
    agent: RunnerAgent,
    svid: SvidFiles,
    held: Mutex<Option<HeldKey>>,
}

impl HttpRunnerKeys {
    /// Keys for `agent`, attested with `svid`, each call to the platform
    /// held to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(
        agent: RunnerAgent,
        svid: SvidFiles,
        timeout: Duration,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            client: fixed(timeout)?,
            agent,
            svid,
            held: Mutex::new(None),
        })
    }

    /// A fresh key, enrolled for the agent by attesting the workload at
    /// `now`, held until halfway to when the platform stops taking it.
    async fn attested(&self, now: OffsetDateTime) -> Result<HeldKey, DomainError> {
        let pair = Pkcs8KeyGenerator.generate(SigningAlgorithm::EdDsa).await?;
        let body = self.attestation_body(&pair.public_key).await?;
        let minted: Minted = posted(&self.client, self.agent.url_of("bootstrap")?, &body).await?;
        let key = RunnerKey {
            kid: KeyId::new(minted.kid)
                .map_err(|_| DomainError::infra_msg("the credential's key id is no key id"))?,
            algorithm: SigningAlgorithm::EdDsa,
            private_key: pair.private_key,
        };
        Ok(HeldKey {
            key,
            renew_at: key_renewal(now, minted.expires_at),
        })
    }

    /// Answers the platform's challenge with an SVID signature bound to the new key.
    async fn attestation_body(&self, public_key: &PublicKeyPem) -> Result<Value, DomainError> {
        let challenge: Challenge = posted(
            &self.client,
            self.agent.url_of("bootstrap/challenge")?,
            &json!({}),
        )
        .await?;
        let nonce = AttestationNonce::new(challenge.nonce)
            .map_err(|_| DomainError::infra_msg("the challenge is no nonce"))?;
        let binding = AttestationBinding::of(&nonce, public_key)?;
        let signature = svid_signature(&read_svid(&self.svid.key).await?, &binding.signed_bytes())?;
        Ok(json!({
            "algorithm": "EdDSA",
            "public_key": public_key.as_str(),
            "attestation": {
                "method": "spiffe",
                "material": read_svid(&self.svid.chain).await?.expose(),
                "nonce": nonce.as_str(),
                "signature": URL_SAFE_NO_PAD.encode(signature),
            },
        }))
    }
}

#[async_trait]
impl RunnerKeys for HttpRunnerKeys {
    async fn current(&self) -> Result<RunnerKey, DomainError> {
        let mut held = self.held.lock().await;
        let now = clock::now();
        if let Some(current) = held.as_ref().filter(|held| held.renew_at > now) {
            return Ok(current.key.clone());
        }
        let attested = self.attested(now).await?;
        let key = attested.key.clone();
        *held = Some(attested);
        Ok(key)
    }
}

/// A token the platform issued, the key it was exchanged with, and when to
/// exchange again.
struct HeldToken {
    token: TaskToken,
    kid: KeyId,
    renew_at: OffsetDateTime,
}

/// The runner's task tokens, one bound to the agent's key for the gateway
/// and one bearer token for the message relay, each exchanged with an
/// assertion the key signs.
pub struct HttpRunnerTokens {
    client: reqwest::Client,
    agent: RunnerAgent,
    ask: TokenAsk,
    bound: Mutex<Option<HeldToken>>,
    bearer: Mutex<Option<HeldToken>>,
}

impl HttpRunnerTokens {
    /// Tokens for `agent`, asked for as `ask` says, each exchange held to
    /// `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be
    /// built.
    pub fn new(agent: RunnerAgent, ask: TokenAsk, timeout: Duration) -> Result<Self, DomainError> {
        Ok(Self {
            client: fixed(timeout)?,
            agent,
            ask,
            bound: Mutex::new(None),
            bearer: Mutex::new(None),
        })
    }

    /// Where the token of `binding` is held.
    fn slot(&self, binding: TokenBinding) -> &Mutex<Option<HeldToken>> {
        match binding {
            TokenBinding::ProofOfPossession => &self.bound,
            TokenBinding::Bearer => &self.bearer,
        }
    }

    /// A new token of `binding`, exchanged with an assertion `key` signs at
    /// `now`.
    async fn exchanged(
        &self,
        key: &RunnerKey,
        binding: TokenBinding,
        now: OffsetDateTime,
    ) -> Result<TaskToken, DomainError> {
        let signed = assertion(key, &self.agent.agent, &self.ask.audience, now)?;
        let body = json!({
            "assertion": signed.expose(),
            "granted": self.ask.granted,
            "ttl_seconds": self.ask.lifetime.get(),
            "max_depth": 0,
            "sender_constrained": binding == TokenBinding::ProofOfPossession,
        });
        let exchanged: Exchanged = posted(&self.client, self.agent.url_of("token")?, &body).await?;
        Ok(TaskToken::new(exchanged.task_token))
    }
}

#[async_trait]
impl RunnerTokens for HttpRunnerTokens {
    async fn current(
        &self,
        key: &RunnerKey,
        binding: TokenBinding,
    ) -> Result<TaskToken, DomainError> {
        let mut held = self.slot(binding).lock().await;
        let now = clock::now();
        let fresh = held
            .as_ref()
            .filter(|held| held.renew_at > now && held.kid == key.kid);
        if let Some(current) = fresh {
            return Ok(current.token.clone());
        }
        let token = self.exchanged(key, binding, now).await?;
        *held = Some(HeldToken {
            token: token.clone(),
            kid: key.kid.clone(),
            renew_at: token_renewal(now, self.ask.lifetime.duration()),
        });
        Ok(token)
    }

    async fn forget(&self, binding: TokenBinding) {
        *self.slot(binding).lock().await = None;
    }
}

/// The platform's answer to a request for an attestation challenge.
#[derive(Deserialize)]
struct Challenge {
    nonce: String,
}

/// The platform's answer to a bootstrap: the credential it minted.
#[derive(Deserialize)]
struct Minted {
    kid: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

/// The platform's answer to a token exchange.
#[derive(Deserialize)]
struct Exchanged {
    task_token: String,
}

/// The answer to `body` posted to `url`, read as `T` within its size
/// limit, or why there is none.
async fn posted<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: Url,
    body: &Value,
) -> Result<T, DomainError> {
    let response = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|_| DomainError::infra_msg("the platform could not be reached"))?;
    let status = response.status();
    if status.is_client_error() {
        return Err(DomainError::unauthorized(message!(
            "infra-the-platform-refused-the-runner",
            "the platform refused the runner"
        )));
    }
    if !status.is_success() {
        return Err(DomainError::infra_msg(
            "the platform failed the runner's call",
        ));
    }
    let answer = body_within(response, MOST_ANSWER_BYTES).await?;
    serde_json::from_slice(&answer)
        .map_err(|_| DomainError::infra_msg("the platform's answer does not read"))
}

/// The SVID file at `path`, refused past its size limit. A secret: the key
/// file is one, and neither is ever quoted.
async fn read_svid(path: &Path) -> Result<Secret, DomainError> {
    let size = tokio::fs::metadata(path)
        .await
        .map_err(|_| DomainError::infra_msg("an SVID file cannot be read"))?
        .len();
    if size > MOST_SVID_BYTES {
        return Err(DomainError::infra_msg(
            "an SVID file is larger than allowed",
        ));
    }
    tokio::fs::read_to_string(path)
        .await
        .map(Secret::new)
        .map_err(|_| DomainError::infra_msg("an SVID file cannot be read"))
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::crypto::jws::keys_for_tests::pair;

    fn agent_at(server: &MockServer, agent: AgentId) -> RunnerAgent {
        RunnerAgent {
            agent,
            agents_url: Url::parse(&format!("{}/agents/", server.uri())).unwrap(),
        }
    }

    fn ask() -> TokenAsk {
        TokenAsk {
            audience: Audience::new("https://ianua.test").unwrap(),
            granted: json!({"http": ["routing:view"]}),
            lifetime: Seconds::new(600),
        }
    }

    fn key(kid: &str) -> RunnerKey {
        let (private, _) = pair(SigningAlgorithm::EdDsa);
        RunnerKey {
            kid: KeyId::new(kid).unwrap(),
            algorithm: SigningAlgorithm::EdDsa,
            private_key: Secret::new(private),
        }
    }

    async fn exchanging(server: &MockServer, agent: AgentId, token: &str, bound: bool) {
        Mock::given(method("POST"))
            .and(path(format!("/agents/{agent}/token")))
            .and(body_partial_json(
                json!({"sender_constrained": bound, "max_depth": 0}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"task_token": token})))
            .mount(server)
            .await;
    }

    /// The bound token is exchanged once and held, the bearer token apart
    /// from it, each asked for with its binding.
    #[tokio::test]
    async fn a_token_is_exchanged_once_and_held_by_binding() {
        let server = MockServer::start().await;
        let agent = AgentId::new();
        exchanging(&server, agent, "bound.token", true).await;
        exchanging(&server, agent, "bearer.token", false).await;
        let tokens =
            HttpRunnerTokens::new(agent_at(&server, agent), ask(), Duration::from_secs(5)).unwrap();
        let key = key("k1");

        let first = tokens
            .current(&key, TokenBinding::ProofOfPossession)
            .await
            .unwrap();
        let again = tokens
            .current(&key, TokenBinding::ProofOfPossession)
            .await
            .unwrap();
        let bearer = tokens.current(&key, TokenBinding::Bearer).await.unwrap();

        assert_eq!(first.reveal(), "bound.token");
        assert_eq!(again.reveal(), "bound.token");
        assert_eq!(bearer.reveal(), "bearer.token");
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// Changing the key ID and then forgetting the held token each trigger
    /// another exchange, producing three requests in total.
    #[tokio::test]
    async fn a_new_key_or_a_forgotten_token_exchanges_again() {
        let server = MockServer::start().await;
        let agent = AgentId::new();
        exchanging(&server, agent, "bound.token", true).await;
        let tokens =
            HttpRunnerTokens::new(agent_at(&server, agent), ask(), Duration::from_secs(5)).unwrap();

        tokens
            .current(&key("k1"), TokenBinding::ProofOfPossession)
            .await
            .unwrap();
        tokens
            .current(&key("k2"), TokenBinding::ProofOfPossession)
            .await
            .unwrap();
        tokens.forget(TokenBinding::ProofOfPossession).await;
        tokens
            .current(&key("k2"), TokenBinding::ProofOfPossession)
            .await
            .unwrap();

        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    /// A 403 response to a token exchange returns an unauthorized error.
    #[tokio::test]
    async fn a_refused_exchange_is_a_refusal() {
        let server = MockServer::start().await;
        let agent = AgentId::new();
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let tokens =
            HttpRunnerTokens::new(agent_at(&server, agent), ask(), Duration::from_secs(5)).unwrap();

        let token = tokens.current(&key("k1"), TokenBinding::Bearer).await;

        assert!(matches!(token, Err(DomainError::Unauthorized(_))));
    }

    /// A token exchange delayed beyond the runner's timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_hung_exchange_is_given_up_on() {
        let server = MockServer::start().await;
        let agent = AgentId::new();
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!({"task_token": "late"}))
                    .set_delay(Duration::from_secs(10)),
            )
            .mount(&server)
            .await;
        let tokens =
            HttpRunnerTokens::new(agent_at(&server, agent), ask(), Duration::from_millis(200))
                .unwrap();

        let token = tokens.current(&key("k1"), TokenBinding::Bearer).await;

        assert!(matches!(token, Err(DomainError::Infrastructure(_))));
    }

    /// The runner attests: it asks for a challenge, then enrols a key it
    /// made, carrying the SVID and its signature over the binding, and
    /// holds the key the platform minted until halfway to its end.
    #[tokio::test]
    async fn a_key_is_attested_once_and_held() {
        let server = MockServer::start().await;
        let agent = AgentId::new();
        let nonce = "n".repeat(43);
        Mock::given(method("POST"))
            .and(path(format!("/agents/{agent}/bootstrap/challenge")))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"nonce": nonce})))
            .mount(&server)
            .await;
        let expires_at = clock::now() + time::Duration::hours(1);
        Mock::given(method("POST"))
            .and(path(format!("/agents/{agent}/bootstrap")))
            .and(body_partial_json(json!({"algorithm": "EdDSA", "attestation": {"method": "spiffe", "nonce": nonce}})))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "kid": "minted-1",
                "expires_at": expires_at.format(&time::format_description::well_known::Rfc3339).unwrap(),
            })))
            .mount(&server)
            .await;
        let folder = tempfile::tempdir().unwrap();
        let files = svid_files(folder.path());
        let keys =
            HttpRunnerKeys::new(agent_at(&server, agent), files, Duration::from_secs(5)).unwrap();

        let first = keys.current().await.unwrap();
        let again = keys.current().await.unwrap();

        assert_eq!(first.kid.as_str(), "minted-1");
        assert_eq!(again.kid, first.kid);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// Writes an SVID-shaped chain and EC signing key into the test directory.
    fn svid_files(folder: &Path) -> SvidFiles {
        let (svid_key, _) = pair(SigningAlgorithm::Es256);
        let files = SvidFiles {
            chain: folder.join("svid.pem"),
            key: folder.join("svid_key.pem"),
        };
        std::fs::write(
            &files.chain,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(&files.key, svid_key).unwrap();
        files
    }

    /// A 403 response when requesting an attestation challenge returns an
    /// unauthorized error instead of a runner key.
    #[tokio::test]
    async fn a_refused_attestation_is_a_refusal() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let folder = tempfile::tempdir().unwrap();
        let files = SvidFiles {
            chain: folder.path().join("svid.pem"),
            key: folder.path().join("svid_key.pem"),
        };
        let keys = HttpRunnerKeys::new(
            agent_at(&server, AgentId::new()),
            files,
            Duration::from_secs(5),
        )
        .unwrap();

        let key = keys.current().await;

        assert!(matches!(key, Err(DomainError::Unauthorized(_))));
    }
}
