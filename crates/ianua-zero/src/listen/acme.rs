//! What port 80 answers: HTTP-01 challenges, and a redirect to HTTPS for
//! everything else.
//!
//! A certificate authority proves a domain by fetching
//! `http://<domain>/.well-known/acme-challenge/<token>` and expecting the
//! answer the control plane published. The fetch is plain HTTP on port 80,
//! since it comes before there is a certificate to encrypt with. Nothing
//! else is served here: no request is proxied, no upstream reached and no
//! policy asked, since a request that never presented a certificate has no
//! tenant behind it. A visitor who typed `http://` is sent to HTTPS.
//!
//! Run it as the [`Handler`] of a plain [`Listener`](super::Listener).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_TYPE, HOST, HeaderValue, LOCATION};
use hyper::{Request, Response, StatusCode};
use ianua_app::ports::domain::AcmeChallengeStore;
use ianua_domain::domains::tenant::custom_domains::acme_challenge::ChallengeToken;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DomainName;

use super::connection::ConnectionFacts;
use super::handler::Handler;

/// The path an authority fetches, fixed by RFC 8555.
const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Answers HTTP-01 challenges from the store the control plane publishes
/// them to, and sends everything else to HTTPS.
#[derive(Clone)]
pub(crate) struct AcmeResponder {
    challenges: Arc<dyn AcmeChallengeStore>,
    lookup: Duration,
}

impl AcmeResponder {
    /// Answers from `challenges`, giving up on a lookup after `lookup`.
    #[must_use]
    pub(crate) fn new(challenges: Arc<dyn AcmeChallengeStore>, lookup: Duration) -> Self {
        Self { challenges, lookup }
    }

    /// The response `reply` stands for, looking a challenge up when it
    /// names one.
    async fn reply(&self, reply: Reply) -> Response<Full<Bytes>> {
        match reply {
            Reply::Ready(response) => response,
            Reply::Challenge(raw_token) => self.challenge(&raw_token).await,
        }
    }

    /// The answer to the challenge `raw_token` names, within the lookup
    /// timeout.
    async fn challenge(&self, raw_token: &str) -> Response<Full<Bytes>> {
        match tokio::time::timeout(self.lookup, self.answer(raw_token)).await {
            Ok(Ok(Some(answer))) => text(answer),
            Ok(Ok(None)) => empty(StatusCode::NOT_FOUND),
            Ok(Err(error)) => {
                tracing::warn!(%error, "an ACME challenge could not be looked up");
                empty(StatusCode::SERVICE_UNAVAILABLE)
            }
            Err(_) => {
                tracing::warn!("an ACME challenge lookup did not answer in time");
                empty(StatusCode::SERVICE_UNAVAILABLE)
            }
        }
    }

    /// The published answer for `raw_token`, while it is outstanding.
    ///
    /// A token that does not parse is not found. It came in a URL path, and
    /// parsing it is what keeps a traversal attempt from reaching the store.
    async fn answer(&self, raw_token: &str) -> Result<Option<String>, DomainError> {
        let Ok(token) = ChallengeToken::new(raw_token) else {
            return Ok(None);
        };
        let Some(challenge) = self.challenges.find(&token).await? else {
            return Ok(None);
        };
        Ok(challenge
            .answer(clock::now())
            .map(|answer| answer.as_str().to_owned()))
    }
}

impl Handler for AcmeResponder {
    type Body = Full<Bytes>;

    fn handle(
        &self,
        request: Request<Incoming>,
        _connection: Arc<ConnectionFacts>,
    ) -> impl Future<Output = Response<Self::Body>> + Send {
        let reply = reply_to(&request);
        async move { self.reply(reply).await }
    }
}

/// What a request on port 80 gets: a response known from the request
/// alone, or the answer to a challenge, to be looked up.
enum Reply {
    Ready(Response<Full<Bytes>>),
    Challenge(String),
}

/// What `request` gets. Generic over the body, which is never read: a
/// challenge is answered from the path, a redirect from the path and the
/// host.
fn reply_to<B>(request: &Request<B>) -> Reply {
    let Some(raw_token) = request.uri().path().strip_prefix(CHALLENGE_PREFIX) else {
        return Reply::Ready(redirect_to_https(request));
    };
    Reply::Challenge(raw_token.to_owned())
}

/// Sends a plain HTTP caller to the same path over HTTPS, permanently,
/// since this port serves nothing else. A host that is not a domain name
/// has nowhere to be sent and is refused rather than echoed into a
/// `Location`.
fn redirect_to_https<B>(request: &Request<B>) -> Response<Full<Bytes>> {
    let Some(host) = host_of(request) else {
        return empty(StatusCode::BAD_REQUEST);
    };
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str());
    let Ok(location) = HeaderValue::from_str(&format!("https://{host}{path}")) else {
        return empty(StatusCode::BAD_REQUEST);
    };
    let mut response = empty(StatusCode::PERMANENT_REDIRECT);
    response.headers_mut().insert(LOCATION, location);
    response
}

/// The domain the request was sent to, without its port.
fn host_of<B>(request: &Request<B>) -> Option<DomainName> {
    let host = request.headers().get(HOST)?.to_str().ok()?;
    let name = host.split_once(':').map_or(host, |(name, _port)| name);
    DomainName::new(name)
        .ok()
        .filter(|name| !name.is_wildcard())
}

fn text(body: String) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use http_body_util::BodyExt;
    use ianua_domain::domains::tenant::custom_domains::acme_challenge::{
        AcmeChallenge, AcmeChallengeRow, KeyAuthorization,
    };

    use super::*;

    const LOOKUP: Duration = Duration::from_millis(200);

    /// Holds what was published and records every token looked up, so a
    /// test can show the store was never reached.
    #[derive(Default)]
    struct FakeChallenges {
        published: Mutex<Vec<AcmeChallenge>>,
        looked_up: Mutex<Vec<String>>,
    }

    impl FakeChallenges {
        fn holding(challenge: AcmeChallenge) -> Self {
            let store = Self::default();
            store.published.lock().unwrap().push(challenge);
            store
        }

        fn lookups(&self) -> Vec<String> {
            self.looked_up.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AcmeChallengeStore for FakeChallenges {
        async fn publish(&self, challenge: &AcmeChallenge) -> Result<(), DomainError> {
            self.published.lock().unwrap().push(challenge.clone());
            Ok(())
        }

        async fn find(&self, token: &ChallengeToken) -> Result<Option<AcmeChallenge>, DomainError> {
            self.looked_up
                .lock()
                .unwrap()
                .push(token.as_str().to_owned());
            Ok(self
                .published
                .lock()
                .unwrap()
                .iter()
                .find(|challenge| challenge.token() == token)
                .cloned())
        }

        async fn withdraw(&self, token: &ChallengeToken) -> Result<(), DomainError> {
            self.published
                .lock()
                .unwrap()
                .retain(|challenge| challenge.token() != token);
            Ok(())
        }

        async fn purge_expired(&self) -> Result<u64, DomainError> {
            Ok(0)
        }
    }

    /// A store that never answers.
    struct HangingChallenges;

    #[async_trait]
    impl AcmeChallengeStore for HangingChallenges {
        async fn publish(&self, _challenge: &AcmeChallenge) -> Result<(), DomainError> {
            std::future::pending().await
        }

        async fn find(
            &self,
            _token: &ChallengeToken,
        ) -> Result<Option<AcmeChallenge>, DomainError> {
            std::future::pending().await
        }

        async fn withdraw(&self, _token: &ChallengeToken) -> Result<(), DomainError> {
            std::future::pending().await
        }

        async fn purge_expired(&self) -> Result<u64, DomainError> {
            std::future::pending().await
        }
    }

    fn challenge(token: &str) -> AcmeChallenge {
        AcmeChallenge::open(
            ChallengeToken::new(token).unwrap(),
            KeyAuthorization::new(format!("{token}.thumbprint")).unwrap(),
            DomainName::new("hello.acme.com").unwrap(),
        )
    }

    fn responder(store: Arc<dyn AcmeChallengeStore>) -> AcmeResponder {
        AcmeResponder::new(store, LOOKUP)
    }

    impl AcmeResponder {
        async fn respond<B>(&self, request: &Request<B>) -> Response<Full<Bytes>> {
            self.reply(reply_to(request)).await
        }
    }

    fn get(path: &str) -> Request<()> {
        Request::builder()
            .uri(path)
            .header(HOST, "hello.acme.com")
            .body(())
            .unwrap()
    }

    async fn body_of(response: Response<Full<Bytes>>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// A published challenge is answered with its key authorization.
    #[tokio::test]
    async fn a_published_challenge_is_answered() {
        let responder = responder(Arc::new(FakeChallenges::holding(challenge("tok_abc"))));

        let response = responder
            .respond(&get("/.well-known/acme-challenge/tok_abc"))
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, "tok_abc.thumbprint");
    }

    /// A token nobody published is not found.
    #[tokio::test]
    async fn an_unknown_token_is_not_found() {
        let responder = responder(Arc::new(FakeChallenges::default()));

        let response = responder
            .respond(&get("/.well-known/acme-challenge/tok_missing"))
            .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A traversal attempt is stopped by parsing, before the store is asked.
    #[tokio::test]
    async fn a_traversal_attempt_never_reaches_the_store() {
        let store = Arc::new(FakeChallenges::default());
        let responder = responder(Arc::clone(&store) as Arc<dyn AcmeChallengeStore>);

        let response = responder
            .respond(&get("/.well-known/acme-challenge/..%2f..%2fetc"))
            .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(store.lookups().is_empty());
    }

    /// A challenge past its expiry stops being answered, even when its row
    /// outlived the cleanup.
    #[tokio::test]
    async fn an_expired_challenge_is_not_answered() {
        let expired = AcmeChallenge::reconstitute(AcmeChallengeRow {
            token: ChallengeToken::new("tok_old").unwrap(),
            key_authorization: KeyAuthorization::new("tok_old.thumbprint").unwrap(),
            domain: DomainName::new("hello.acme.com").unwrap(),
            expires_at: clock::now() - time::Duration::seconds(1),
        })
        .unwrap();
        let responder = responder(Arc::new(FakeChallenges::holding(expired)));

        let response = responder
            .respond(&get("/.well-known/acme-challenge/tok_old"))
            .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A store that does not answer is given up on, and the authority is
    /// told to try again rather than kept waiting.
    #[tokio::test]
    async fn a_hanging_store_is_given_up_on() {
        let responder = responder(Arc::new(HangingChallenges));

        let response = responder
            .respond(&get("/.well-known/acme-challenge/tok_abc"))
            .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Every other path goes to HTTPS, with its query.
    #[tokio::test]
    async fn any_other_path_redirects_to_https() {
        let responder = responder(Arc::new(FakeChallenges::default()));

        let response = responder.respond(&get("/dashboard?a=1")).await;

        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers()[LOCATION],
            "https://hello.acme.com/dashboard?a=1"
        );
    }

    /// The port is dropped from the host the visitor is sent to.
    #[tokio::test]
    async fn the_port_is_dropped_from_the_redirect() {
        let responder = responder(Arc::new(FakeChallenges::default()));
        let request = Request::builder()
            .uri("/")
            .header(HOST, "hello.acme.com:80")
            .body(())
            .unwrap();

        let response = responder.respond(&request).await;

        assert_eq!(response.headers()[LOCATION], "https://hello.acme.com/");
    }

    /// A request without a host, or with one that is not a domain name, is
    /// refused rather than echoed into a redirect.
    #[tokio::test]
    async fn a_request_without_a_usable_host_is_refused() {
        let responder = responder(Arc::new(FakeChallenges::default()));
        let without = Request::builder().uri("/dashboard").body(()).unwrap();
        let odd = Request::builder()
            .uri("/dashboard")
            .header(HOST, "evil.test/@x")
            .body(())
            .unwrap();

        let without = responder.respond(&without).await;
        let odd = responder.respond(&odd).await;

        assert_eq!(without.status(), StatusCode::BAD_REQUEST);
        assert_eq!(odd.status(), StatusCode::BAD_REQUEST);
    }
}
