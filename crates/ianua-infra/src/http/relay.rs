//! The sealed channel the gateway asks the API's internal listener through:
//! one JSON question posted, its body sealed, one JSON answer read back.
//!
//! The API trusts nothing on this channel but the seal, so every question
//! is sealed under the key of its channel, and the seal travels in
//! [`SEAL_HEADER`]. The gateway trusts nothing but the seal either: the
//! API seals its answer under the same key, bound to the question's nonce,
//! so nobody else on the internal network can answer in its place, nor
//! hand back the answer to an earlier question. Deny by default on the way
//! back: a status that is not a success, an answer that is too large, not
//! sealed for this question or does not read, a call that does not end in
//! time or that would exceed the questions allowed in flight, each is an
//! error, never an answer.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::authentication::{RequestSeal as _, SEAL_HEADER};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Nonce;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Semaphore;

use crate::crypto::{HmacRequestSeal, random_bytes};
use crate::http::calls::succeeded;
use crate::http::client::{InternalLink, body_within};

/// How a channel is bounded.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayLimits {
    /// How long one question may take, answer read included.
    pub(crate) timeout: Duration,
    /// How many questions may wait on the API at once. One past it is
    /// refused at once rather than queued.
    pub(crate) in_flight: usize,
    /// The largest answer read back.
    pub(crate) answer_bytes: usize,
}

/// The internal listener and the channel path joined beneath it.
#[derive(Clone, Copy)]
pub(crate) struct RelayEndpoint<'a> {
    /// The configured internal listener address.
    pub(crate) base_url: &'a url::Url,
    /// The relative route serving this channel.
    pub(crate) path: &'a str,
}

/// Posts sealed questions to one path on the API's internal listener.
pub(crate) struct SealedRelay {
    client: reqwest::Client,
    url: url::Url,
    seal: HmacRequestSeal,
    in_flight: Semaphore,
    answer_bytes: usize,
}

impl SealedRelay {
    /// A channel to `path` on the relay listener at `base_url`, reached as
    /// `link` says, sealing with `seal`, the key of this channel alone,
    /// bounded by `limits`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the address does not join
    /// or the client cannot be built.
    pub(crate) fn new(
        endpoint: RelayEndpoint<'_>,
        seal: HmacRequestSeal,
        limits: RelayLimits,
        link: &InternalLink,
    ) -> Result<Self, DomainError> {
        let url = endpoint
            .base_url
            .join(endpoint.path)
            .map_err(DomainError::infra)?;
        Ok(Self {
            client: link.client(limits.timeout)?,
            url,
            seal,
            in_flight: Semaphore::new(limits.in_flight),
            answer_bytes: limits.answer_bytes,
        })
    }

    /// Posts `question`, which carries `nonce`, sealed, and reads the
    /// answer back once the API's seal over it holds for that nonce.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when too many questions are in
    /// flight, the API cannot be reached in time, it answers with a status
    /// that is not a success, its answer is too large, carries no seal or
    /// one that does not hold for this question, or does not read.
    pub(crate) async fn ask<Q, A>(&self, nonce: &Nonce, question: &Q) -> Result<A, DomainError>
    where
        Q: Serialize + Sync,
        A: DeserializeOwned,
    {
        let Ok(_permit) = self.in_flight.try_acquire() else {
            return Err(DomainError::infra_msg(
                "too many questions to the API in flight",
            ));
        };
        let body = serde_json::to_vec(question).map_err(DomainError::infra)?;
        let seal = self.seal.seal(&body);
        let answer = succeeded(
            self.client
                .post(self.url.as_str())
                .header(SEAL_HEADER, seal)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await,
        )?;
        let answer_seal = answer_seal(&answer);
        let bytes = body_within(answer, self.answer_bytes).await?;
        let sealed =
            answer_seal.is_some_and(|seal| self.seal.verifies_answer(nonce, &bytes, &seal));
        if !sealed {
            return Err(DomainError::infra_msg(
                "the answer is not sealed for this question",
            ));
        }
        serde_json::from_slice(&bytes).map_err(DomainError::infra)
    }
}

/// The seal the API put on `answer`, if it carries a readable one.
fn answer_seal(answer: &reqwest::Response) -> Option<String> {
    answer
        .headers()
        .get(SEAL_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// A nonce used once, so a captured question cannot be sent again.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the secure generator cannot
/// be read.
pub(crate) fn fresh_nonce() -> Result<Nonce, DomainError> {
    let bytes = random_bytes::<32>()?;
    Nonce::new(URL_SAFE_NO_PAD.encode(bytes)).map_err(DomainError::infra)
}

#[cfg(test)]
pub(crate) mod tests {
    use ianua_app::ports::authentication::RequestSeal;
    use serde::Deserialize;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::crypto::keys::tests::test_root;

    #[derive(Serialize)]
    struct Question {
        ask: &'static str,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Answer {
        said: String,
    }

    const LIMITS: RelayLimits = RelayLimits {
        timeout: Duration::from_secs(1),
        in_flight: 4,
        answer_bytes: 1024,
    };

    async fn relay_to(server: &MockServer, limits: RelayLimits) -> SealedRelay {
        let base = url::Url::parse(&server.uri()).unwrap();
        SealedRelay::new(
            RelayEndpoint {
                base_url: &base,
                path: "/internal/ask",
            },
            HmacRequestSeal::new(&test_root()),
            limits,
            &InternalLink::PlainInDevelopment,
        )
        .unwrap()
    }

    async fn answering(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internal/ask"))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    fn nonce(text: &str) -> Nonce {
        Nonce::new(format!("{text}-nonce-of-length")).unwrap()
    }

    /// `200` with `answer`, sealed through `seal` as the API seals its
    /// answer to the question that carried `nonce`.
    pub(crate) fn sealed_answer(
        seal: &HmacRequestSeal,
        nonce: &Nonce,
        answer: &serde_json::Value,
    ) -> ResponseTemplate {
        let body = serde_json::to_vec(answer).unwrap();
        let sealed = seal.seal_answer(nonce, &body);
        ResponseTemplate::new(200)
            .insert_header(SEAL_HEADER, sealed.as_str())
            .set_body_raw(body, "application/json")
    }

    /// Answers like the API: `answer`, sealed through `seal` for the nonce
    /// the question carries at `nonce_at`, a JSON pointer into it.
    pub(crate) struct SealingApi {
        seal: HmacRequestSeal,
        nonce_at: &'static str,
        answer: serde_json::Value,
        delay: Duration,
    }

    impl SealingApi {
        /// Answers `answer` at once.
        pub(crate) fn new(
            seal: HmacRequestSeal,
            nonce_at: &'static str,
            answer: serde_json::Value,
        ) -> Self {
            Self {
                seal,
                nonce_at,
                answer,
                delay: Duration::ZERO,
            }
        }

        /// Answers only after `delay`.
        pub(crate) fn delayed(self, delay: Duration) -> Self {
            Self { delay, ..self }
        }
    }

    impl wiremock::Respond for SealingApi {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            let question: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let nonce = question
                .pointer(self.nonce_at)
                .and_then(serde_json::Value::as_str)
                .unwrap();
            sealed_answer(&self.seal, &Nonce::new(nonce).unwrap(), &self.answer)
                .set_delay(self.delay)
        }
    }

    fn sealed_for(nonce: &Nonce, answer: &serde_json::Value) -> ResponseTemplate {
        sealed_answer(&HmacRequestSeal::new(&test_root()), nonce, answer)
    }

    /// The question goes sealed over its exact body, and the answer, sealed
    /// for it, reads back.
    #[tokio::test]
    async fn a_question_goes_sealed_and_its_answer_reads_back() {
        let server = MockServer::start().await;
        let body = serde_json::to_vec(&Question { ask: "hold" }).unwrap();
        Mock::given(method("POST"))
            .and(path("/internal/ask"))
            .and(header(
                SEAL_HEADER,
                RequestSeal::seal(&HmacRequestSeal::new(&test_root()), &body).as_str(),
            ))
            .respond_with(sealed_for(
                &nonce("first"),
                &serde_json::json!({"said": "ok"}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let relay = relay_to(&server, LIMITS).await;

        let answer: Answer = relay
            .ask(&nonce("first"), &Question { ask: "hold" })
            .await
            .unwrap();

        assert_eq!(answer.said, "ok");
    }

    /// A well-formed answer without the API's seal returns an infrastructure
    /// error.
    #[tokio::test]
    async fn an_unsealed_answer_is_refused() {
        let server =
            answering(ResponseTemplate::new(200).set_body_json(serde_json::json!({"said": "ok"})))
                .await;
        let relay = relay_to(&server, LIMITS).await;

        let answer: Result<Answer, _> = relay.ask(&nonce("first"), &Question { ask: "hold" }).await;

        assert!(matches!(answer, Err(DomainError::Infrastructure(_))));
    }

    /// An answer sealed for an earlier nonce returns an infrastructure error
    /// when received for the next question.
    #[tokio::test]
    async fn an_answer_sealed_for_another_question_is_refused() {
        let server = answering(sealed_for(
            &nonce("earlier"),
            &serde_json::json!({"said": "ok"}),
        ))
        .await;
        let relay = relay_to(&server, LIMITS).await;

        let answer: Result<Answer, _> = relay.ask(&nonce("next"), &Question { ask: "hold" }).await;

        assert!(matches!(answer, Err(DomainError::Infrastructure(_))));
    }

    /// Changing a sealed answer from refusal to grant invalidates its seal
    /// and returns an infrastructure error.
    #[tokio::test]
    async fn an_altered_answer_is_refused() {
        let sealed = serde_json::to_vec(&serde_json::json!({"said": "no"})).unwrap();
        let seal = HmacRequestSeal::new(&test_root()).seal_answer(&nonce("first"), &sealed);
        let server = answering(
            ResponseTemplate::new(200)
                .insert_header(SEAL_HEADER, seal.as_str())
                .set_body_json(serde_json::json!({"said": "ok"})),
        )
        .await;
        let relay = relay_to(&server, LIMITS).await;

        let answer: Result<Answer, _> = relay.ask(&nonce("first"), &Question { ask: "hold" }).await;

        assert!(matches!(answer, Err(DomainError::Infrastructure(_))));
    }

    /// The API's empty 401 response returns an infrastructure error.
    #[tokio::test]
    async fn a_status_that_is_not_a_success_is_an_error() {
        let server = answering(ResponseTemplate::new(401)).await;
        let relay = relay_to(&server, LIMITS).await;

        let answer: Result<Answer, _> = relay.ask(&nonce("first"), &Question { ask: "hold" }).await;

        assert!(matches!(answer, Err(DomainError::Infrastructure(_))));
    }

    /// A sealed answer exceeding the channel's byte limit returns an
    /// infrastructure error.
    #[tokio::test]
    async fn an_answer_too_large_is_refused() {
        let said = "x".repeat(4096);
        let server = answering(sealed_for(
            &nonce("first"),
            &serde_json::json!({ "said": said }),
        ))
        .await;
        let relay = relay_to(&server, LIMITS).await;

        let answer: Result<Answer, _> = relay.ask(&nonce("first"), &Question { ask: "hold" }).await;

        assert!(matches!(answer, Err(DomainError::Infrastructure(_))));
    }

    /// An API answer delayed beyond the channel timeout returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_late_answer_is_given_up_on() {
        let server = answering(
            sealed_for(&nonce("first"), &serde_json::json!({"said": "late"}))
                .set_delay(Duration::from_secs(3)),
        )
        .await;
        let relay = relay_to(&server, LIMITS).await;

        let answer: Result<Answer, _> = relay.ask(&nonce("first"), &Question { ask: "hold" }).await;

        assert!(matches!(answer, Err(DomainError::Infrastructure(_))));
    }

    /// With one question allowed in flight, a concurrent second question
    /// fails while the first receives its delayed answer.
    #[tokio::test]
    async fn a_question_past_the_limit_is_refused_at_once() {
        let server = answering(
            sealed_for(&nonce("first"), &serde_json::json!({"said": "slow"}))
                .set_delay(Duration::from_millis(500)),
        )
        .await;
        let relay = relay_to(
            &server,
            RelayLimits {
                in_flight: 1,
                ..LIMITS
            },
        )
        .await;

        let (held, spent) = (nonce("first"), nonce("second"));

        let (first, second) = tokio::join!(
            relay.ask::<_, Answer>(&held, &Question { ask: "hold" }),
            relay.ask::<_, Answer>(&spent, &Question { ask: "spend" }),
        );

        assert!(first.is_ok());
        assert!(matches!(second, Err(DomainError::Infrastructure(_))));
    }

    /// Two nonces drawn are never the same, and each is one the API takes.
    #[test]
    fn nonces_are_fresh() {
        let one = fresh_nonce().unwrap();
        let two = fresh_nonce().unwrap();

        assert_ne!(one, two);
    }
}
