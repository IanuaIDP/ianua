//! The proof that a browser passed a challenge, checked with the challenge
//! provider the deployment set up: Cloudflare Turnstile's `siteverify`.
//!
//! The provider accepts a token once and refuses it after, so a solved
//! challenge cannot be replayed, and only for the hostnames the deployment
//! serves its sign-in page on. The call is held to a few seconds and its
//! answer to a few kilobytes. A refused proof is a failed verdict; a
//! provider that fails, answers late, or says its own secret is wrong is
//! an error, which the caller treats as a failed proof too.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::ChallengeVerifier;
use ianua_domain::domains::authentication::risk_engine::challenge::{
    ChallengeKind, ChallengeProof, ChallengeVerdict,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Fact, IpAddress};
use serde::{Deserialize, Serialize};

use crate::http::client::{body_within, fixed};

/// Where Turnstile checks a token.
pub const TURNSTILE_SITEVERIFY: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// The longest a sign-in waits for the provider.
const LONGEST_WAIT: Duration = Duration::from_secs(5);

/// The most of an answer read: a verdict is a few hundred bytes.
const LARGEST_ANSWER: usize = 16 * 1024;

/// What the provider says when the deployment's own setup is wrong or it
/// failed itself, rather than the proof.
const PROVIDER_FAULTS: &[&str] = &[
    "missing-input-secret",
    "invalid-input-secret",
    "internal-error",
];

/// How the deployment reaches its challenge provider.
pub struct ChallengeSettings {
    /// The provider's verify address, [`TURNSTILE_SITEVERIFY`] outside tests.
    pub verify_url: url::Url,
    /// The deployment's secret key with the provider.
    pub secret: Secret,
    /// The hostnames the sign-in page is served on. A proof solved on any
    /// other is refused.
    pub hostnames: Vec<String>,
    /// How long one check may take, at most five seconds.
    pub timeout: Duration,
}

/// Checks Turnstile proofs with Cloudflare.
pub struct HttpChallengeVerifier {
    client: reqwest::Client,
    verify_url: url::Url,
    secret: Secret,
    hostnames: Vec<String>,
}

impl fmt::Debug for HttpChallengeVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpChallengeVerifier")
            .field("verify_url", &self.verify_url.as_str())
            .field("secret", &"<redacted>")
            .field("hostnames", &self.hostnames)
            .finish_non_exhaustive()
    }
}

impl HttpChallengeVerifier {
    /// A verifier asking the provider `settings` names.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when no hostname is named, since
    /// then no proof could be held to the page it was solved on, and
    /// `DomainError::Infrastructure` when the client cannot be built.
    pub fn new(settings: ChallengeSettings) -> Result<Self, DomainError> {
        if settings.hostnames.is_empty() {
            return Err(DomainError::invalid(message!(
                "infra-the-challenge-provider-needs-the-hostnames",
                "the challenge provider needs the hostnames the sign-in page is served on"
            )));
        }
        Ok(Self {
            client: fixed(settings.timeout.min(LONGEST_WAIT))?,
            verify_url: settings.verify_url,
            secret: settings.secret,
            hostnames: settings.hostnames,
        })
    }

    /// The provider's answer about `proof`, as it sent it.
    async fn asked(
        &self,
        proof: &ChallengeProof,
        client_ip: Fact<&IpAddress>,
    ) -> Result<Answer, DomainError> {
        let question = Question {
            secret: self.secret.expose(),
            response: proof.as_str(),
            remoteip: from_address(client_ip),
        };
        let response = self
            .client
            .post(self.verify_url.clone())
            .json(&question)
            .send()
            .await
            .map_err(DomainError::infra)?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(DomainError::infra_msg(format!(
                "the challenge provider answered {status}"
            )));
        }
        let body = body_within(response, LARGEST_ANSWER).await?;
        serde_json::from_slice(&body).map_err(DomainError::infra)
    }

    /// The verdict `answer` comes to.
    fn verdict(&self, answer: &Answer) -> Result<ChallengeVerdict, DomainError> {
        if answer
            .error_codes
            .iter()
            .any(|code| PROVIDER_FAULTS.contains(&code.as_str()))
        {
            return Err(DomainError::infra_msg(
                "the challenge provider refused the deployment's own setup",
            ));
        }
        let on_our_page = answer
            .hostname
            .as_ref()
            .is_some_and(|hostname| self.hostnames.contains(hostname));
        if answer.success && on_our_page {
            return Ok(ChallengeVerdict::Passed);
        }
        Ok(ChallengeVerdict::Failed)
    }
}

#[async_trait]
impl ChallengeVerifier for HttpChallengeVerifier {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Turnstile
    }

    async fn verify(
        &self,
        proof: &ChallengeProof,
        client_ip: Fact<&IpAddress>,
    ) -> Result<ChallengeVerdict, DomainError> {
        let answer = self.asked(proof, client_ip).await?;
        self.verdict(&answer)
    }
}

/// What the provider is asked.
#[derive(Serialize)]
struct Question<'a> {
    secret: &'a str,
    response: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remoteip: Option<&'a str>,
}

/// What the provider answers.
#[derive(Deserialize)]
struct Answer {
    success: bool,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
    hostname: Option<String>,
}

/// The client's address as the provider is told it, when it is known.
fn from_address(client_ip: Fact<&IpAddress>) -> Option<&str> {
    match client_ip {
        Fact::Known(address) => Some(address.as_str()),
        Fact::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const SECRET: &str = "turnstile-secret-distinctive";

    async fn provider(answer: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({ "secret": SECRET })))
            .respond_with(answer)
            .mount(&server)
            .await;
        server
    }

    fn verifier(server: &MockServer) -> HttpChallengeVerifier {
        HttpChallengeVerifier::new(ChallengeSettings {
            verify_url: url::Url::parse(&server.uri()).unwrap(),
            secret: Secret::new(SECRET),
            hostnames: vec!["login.example.com".to_owned()],
            timeout: Duration::from_millis(500),
        })
        .unwrap()
    }

    fn answer(success: bool, hostname: &str, codes: &[&str]) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": success,
            "error-codes": codes,
            "hostname": hostname,
        }))
    }

    fn proof() -> ChallengeProof {
        ChallengeProof::new("0.solved-token").unwrap()
    }

    async fn verdict_of(server: &MockServer) -> Result<ChallengeVerdict, DomainError> {
        let ip = IpAddress::new("203.0.113.9").unwrap();
        verifier(server).verify(&proof(), Fact::Known(&ip)).await
    }

    /// A solved challenge on the deployment's own page passes, and the
    /// provider is told the token and the client's address.
    #[tokio::test]
    async fn a_solved_challenge_on_our_page_passes() {
        let server = provider(answer(true, "login.example.com", &[])).await;

        let verdict = verdict_of(&server).await.unwrap();

        assert_eq!(verdict, ChallengeVerdict::Passed);
        let sent = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&sent.first().unwrap().body).unwrap();
        assert_eq!(body["response"], "0.solved-token");
        assert_eq!(body["remoteip"], "203.0.113.9");
    }

    /// The provider's timeout-or-duplicate response produces a failed
    /// challenge verdict.
    #[tokio::test]
    async fn a_replayed_token_fails() {
        let server = provider(answer(
            false,
            "login.example.com",
            &["timeout-or-duplicate"],
        ))
        .await;

        let verdict = verdict_of(&server).await.unwrap();

        assert_eq!(verdict, ChallengeVerdict::Failed);
    }

    /// A successful proof for an unlisted hostname produces a failed verdict.
    #[tokio::test]
    async fn a_token_solved_on_another_page_fails() {
        let server = provider(answer(true, "phish.example.net", &[])).await;

        let verdict = verdict_of(&server).await.unwrap();

        assert_eq!(verdict, ChallengeVerdict::Failed);
    }

    /// The provider's invalid-secret response returns an infrastructure error.
    #[tokio::test]
    async fn a_wrong_secret_is_an_error() {
        let server = provider(answer(
            false,
            "login.example.com",
            &["invalid-input-secret"],
        ))
        .await;

        let result = verdict_of(&server).await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// HTTP 503, a response delayed beyond the timeout and malformed JSON
    /// each return an infrastructure error.
    #[tokio::test]
    async fn a_failing_or_slow_provider_is_an_error() {
        let down = provider(ResponseTemplate::new(503)).await;
        let slow =
            provider(answer(true, "login.example.com", &[]).set_delay(Duration::from_secs(3)))
                .await;
        let garbled = provider(ResponseTemplate::new(200).set_body_string("ok")).await;

        for server in [&down, &slow, &garbled] {
            assert!(matches!(
                verdict_of(server).await,
                Err(DomainError::Infrastructure(_))
            ));
        }
    }

    /// Building a verifier without permitted hostnames returns a validation
    /// error.
    #[test]
    fn a_verifier_without_hostnames_is_refused() {
        let built = HttpChallengeVerifier::new(ChallengeSettings {
            verify_url: url::Url::parse(TURNSTILE_SITEVERIFY).unwrap(),
            secret: Secret::new(SECRET),
            hostnames: Vec::new(),
            timeout: Duration::from_secs(1),
        });

        assert!(matches!(built, Err(DomainError::Validation(_))));
    }

    /// The secret key reaches the provider and never a log line.
    #[tokio::test]
    async fn the_secret_is_sent_but_never_shown() {
        let server = provider(answer(true, "login.example.com", &[])).await;
        let verifier = verifier(&server);

        verifier.verify(&proof(), Fact::Unknown).await.unwrap();

        assert!(!format!("{verifier:?}").contains(SECRET));
        assert_eq!(verifier.kind(), ChallengeKind::Turnstile);
    }
}
