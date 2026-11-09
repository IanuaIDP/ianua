//! An external agent: the kind a developer writes with an LLM SDK, running
//! outside the platform and calling its agent API in its own name.
//!
//! It holds its own key pair, enrolled when its owner made it or
//! bootstrapped from a platform attestation. It signs a fresh assertion
//! for every token it asks for (ES256, `iss` and `sub` itself, `aud` the
//! platform, a `jti` of its own, a two-minute life), and makes DPoP proofs
//! with the same key for a key-bound token. It publishes through the
//! message relay with its token as the bearer, backing off on `Status::TOO_MANY_REQUESTS` for as
//! long as `Retry-After` says, and reads its own budget from its token.
//!
//! It also misbehaves on purpose ([`misbehaviour`]), so a scenario sees
//! each misstep refused.
//!
//! At the tenant's apps behind the gateway it sends its key-bound token
//! with a fresh proof ([`ExternalAgent::dpop_proof`]): the agent scenarios'
//! `oversight` folder calls tools over MCP that way, has calls held for a
//! person and spends its request budget. Its developer's backend may also
//! open an approval for it ([`ExternalAgent::ask_approval`]).

mod approvals;
pub mod attest;
mod bootstrap;
pub mod dpop;
mod issued;
pub mod misbehaviour;
mod relay_tools;

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use approvals::ApprovalAsk;
pub use bootstrap::BootstrapAgent;
use dpop::ProvenRequest;
pub use issued::IssuedToken;
pub use relay_tools::{PUBLISH_REPORT, RelayTools};
use serde_json::{Value, json};

use crate::agent::keys::{ALGORITHM, AgentKey};
use crate::api::TenantPath;
use crate::api::agents::delegation::{self, Holder};
use crate::api::agents::{lifecycle, relay, token};
use crate::net::Client;
use crate::stack::Stack;
use crate::wire::agents::authority::{Attenuation, Granted};
use crate::wire::agents::identity::{EnrolledKey, NewAgent};
use crate::wire::agents::token::{TokenAsk, TokenRequest};
use crate::wire::{Answer, Status};

/// How long an assertion lives: long enough to be exchanged at once.
const ASSERTION_LIFE: i64 = 120;

/// How long a `Status::TOO_MANY_REQUESTS` without `Retry-After` is waited out.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(1);

/// One external agent: who it is, the key it holds, and the token it
/// holds now. `Debug` shows neither key nor token.
pub struct ExternalAgent {
    name: String,
    id: String,
    tenant: TenantPath,
    audience: String,
    key: AgentKey,
    kid: String,
    credential_id: String,
    client: Client,
    token: Option<IssuedToken>,
}

/// The workload identity and its locally held key before credential issuance.
struct UnenrolledAgent<'a> {
    name: &'a str,
    id: &'a str,
    key: AgentKey,
}

impl fmt::Debug for ExternalAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalAgent")
            .field("name", &self.name)
            .field("id", &self.id)
            .field("kid", &self.kid)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

/// What publishing with back-off came to: the last answer, and how long
/// each `Status::TOO_MANY_REQUESTS` was waited out.
pub struct BackedOff {
    /// The answer that ended the tries.
    pub answer: Answer<()>,
    /// The waits, one for each `Status::TOO_MANY_REQUESTS`, as `Retry-After` named them.
    pub waits: Vec<Duration>,
}

impl ExternalAgent {
    /// The agent `name` in `tenant`, made by `owner` with a key the agent
    /// made for itself, enrolled at once.
    ///
    /// # Panics
    ///
    /// When the agent cannot be made, or comes back without its key's
    /// credential.
    pub async fn enrolled(stack: &Stack, tenant: &TenantPath, owner: &Client, name: &str) -> Self {
        let key = AgentKey::generate();
        let made = NewAgent {
            name: name.to_owned(),
            description: Some(format!("{name}, an external agent")),
            key: Some(EnrolledKey {
                algorithm: ALGORITHM.to_owned(),
                public_key: key.public_pem(),
            }),
            ..NewAgent::default()
        };
        let created = lifecycle::create(tenant, &made).send(owner).await.ok();
        let Some(credential) = created.credential else {
            panic!("{name} was made with a key, yet no credential came back");
        };
        let mut agent = Self::unenrolled(
            stack,
            tenant,
            UnenrolledAgent {
                name,
                id: &created.id,
                key,
            },
        );
        agent.kid = credential.kid;
        agent.credential_id = credential.id;
        agent
    }

    /// Gives the workload its client and key before enrolling a credential.
    /// Agent scenarios require a usable independent client before enrollment.
    #[allow(clippy::expect_used)]
    fn unenrolled(stack: &Stack, tenant: &TenantPath, identity: UnenrolledAgent<'_>) -> Self {
        let client = Client::new(stack, identity.name).expect("a client for the agent");
        Self {
            name: identity.name.to_owned(),
            id: identity.id.to_owned(),
            tenant: tenant.clone(),
            audience: format!("https://{}", stack.host("app")),
            key: identity.key,
            kid: String::new(),
            credential_id: String::new(),
            client,
            token: None,
        }
    }

    /// Label attached to this workload's scenario requests and diagnostics.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Registered workload identity named in assertion issuer and subject claims.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The tenant it works in.
    #[must_use]
    pub fn tenant(&self) -> &TenantPath {
        &self.tenant
    }

    /// The key it holds.
    #[must_use]
    pub fn key(&self) -> &AgentKey {
        &self.key
    }

    /// The key id its assertions name.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.kid
    }

    /// The credential its key is enrolled as.
    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    /// The client it calls through, bearing its token once it holds one:
    /// how it stands in a matrix.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The token it holds now.
    #[must_use]
    pub fn token(&self) -> Option<&IssuedToken> {
        self.token.as_ref()
    }

    /// A fresh assertion: itself as `iss` and `sub`, the platform as `aud`,
    /// a `jti` of its own, living two minutes, signed with its key.
    #[must_use]
    pub fn assertion(&self) -> String {
        self.assertion_naming(&self.id)
    }

    /// An assertion signed with its own key and key id, naming
    /// `agent_id` as its issuer and subject.
    fn assertion_naming(&self, agent_id: &str) -> String {
        let issued_at = now();
        let header = json!({"alg": ALGORITHM, "typ": "JWT", "kid": self.kid});
        let claims = json!({
            "iss": agent_id,
            "sub": agent_id,
            "aud": self.audience,
            "jti": uuid::Uuid::now_v7().to_string(),
            "iat": issued_at,
            "exp": issued_at + ASSERTION_LIFE
        });
        self.key.signed_jws(&header, &claims)
    }

    /// Asks for a token carrying `ask`, signed in by a fresh assertion.
    pub async fn ask_token(&self, ask: &TokenAsk) -> Answer<Granted> {
        self.exchange_with(&self.assertion(), ask).await
    }

    /// Asks for a token carrying `ask`, signed in by `assertion`.
    pub async fn exchange_with(&self, assertion: &str, ask: &TokenAsk) -> Answer<Granted> {
        let request = TokenRequest {
            assertion: assertion.to_owned(),
            ask: ask.clone(),
        };
        token::exchange(&self.tenant, &self.id, &request)
            .send(&self.client)
            .await
    }

    /// The token `ask` names, held from now on and borne on every call.
    ///
    /// # Panics
    ///
    /// When it is refused.
    pub async fn take_token(&mut self, ask: &TokenAsk) -> IssuedToken {
        let issued = IssuedToken::of(self.ask_token(ask).await.ok());
        self.hold(issued.clone());
        issued
    }

    /// Holds `issued`, bearing it on every call from now on.
    pub fn hold(&mut self, issued: IssuedToken) {
        self.client.authorize(issued.token());
        self.token = Some(issued);
    }

    /// Passes part of the delegation `delegation_id` it holds on to
    /// another agent, signed in by a fresh assertion.
    pub async fn pass_on(&self, delegation_id: &str, attenuation: &Attenuation) -> Answer<Granted> {
        let holder = Holder {
            agent_id: &self.id,
            delegation_id,
        };
        delegation::attenuate(&self.tenant, holder, &self.assertion(), attenuation)
            .send(&self.client)
            .await
    }

    /// A DPoP proof for `request` with its key, naming the token it holds.
    #[must_use]
    pub fn dpop_proof(&self, request: ProvenRequest<'_>) -> String {
        let held = self.token.as_ref().map(IssuedToken::token);
        dpop::proof(&self.key, request, held, now())
    }

    /// Publishes `message` to `topic` through the relay, bearing its
    /// token.
    pub async fn publish(&self, topic: &str, message: &Value) -> Answer<()> {
        relay::publish(&self.tenant, topic, message)
            .send(&self.client)
            .await
    }

    /// Publishes `message` to `topic`, trying up to `tries` times, each
    /// `Status::TOO_MANY_REQUESTS` waited out for as long as its `Retry-After` says, the way an
    /// SDK's retry does.
    pub async fn publish_backing_off(&self, topic: &str, message: &Value, tries: u32) -> BackedOff {
        let mut waits = Vec::new();
        let mut answer = self.publish(topic, message).await;
        for _ in 1..tries {
            if answer.status() != Status::TOO_MANY_REQUESTS {
                break;
            }
            let wait = retry_after(&answer);
            waits.push(wait);
            tokio::time::sleep(wait).await;
            answer = self.publish(topic, message).await;
        }
        BackedOff { answer, waits }
    }
}

/// How long `answer` asks to be waited out: its `Retry-After` in seconds,
/// or a second when it names none.
fn retry_after<T>(answer: &Answer<T>) -> Duration {
    answer
        .header("retry-after")
        .and_then(|seconds| seconds.trim().parse::<u64>().ok())
        .map_or(DEFAULT_RETRY_AFTER, Duration::from_secs)
}

/// The time now, in seconds since the epoch.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}
