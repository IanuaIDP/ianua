//! The calls a service's watcher makes to register, renew and remove a
//! workflow's trigger, through the same access and headers as its steps,
//! so a registration's token is handled exactly as a step's is.
//!
//! A call follows no redirect, is held to a time limit and reads a bounded
//! answer. A busy or unreachable service is [`WatchFailure::Unreachable`],
//! to be tried again; whatever else it answers is handed back for the
//! watcher to read.

use std::time::Duration;

use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::shared::errors::DomainError;
use reqwest::StatusCode;
use reqwest::header::{CONTENT_TYPE, HeaderMap};
use serde_json::Value;
use url::form_urlencoded::Serializer;

use crate::answer::body_within;
use crate::events::{HeldCredential, WatchFailure};
use crate::rest::access::{Access, with_acting_for, with_authorization};
use crate::rest::operation::Verb;
use crate::rest::service::headers;
use crate::{Renewed, client};

/// The most of a registration's answer read.
const LARGEST_WATCH_ANSWER: usize = 256 * 1024;

/// One call to the service about a registration.
#[derive(Clone, Copy)]
pub struct WatchCall<'a> {
    /// HTTP method used to register, renew, inspect or remove the trigger.
    pub verb: Verb,
    /// Its path under the account's address, each segment escaped.
    pub path: &'a [&'a str],
    /// Name/value pairs appended to the service URL with query encoding.
    pub query: &'a [(&'a str, &'a str)],
    /// Its body, if it sends one.
    pub body: Option<WatchBody<'a>>,
}

/// The body of a call about a registration.
#[derive(Clone, Copy)]
pub enum WatchBody<'a> {
    /// A JSON value, as most services take it.
    Json(&'a Value),
    /// A form, each name with its value, a name given more than once
    /// repeated, as Mailgun and Twilio take it.
    Form(&'a [(&'a str, &'a str)]),
}

/// What the service answered a call with.
#[derive(Debug, Clone, PartialEq)]
pub struct Answered {
    /// HTTP response code used to distinguish acceptance from refusal.
    pub status: u16,
    /// The body as JSON, null when it was empty or not JSON.
    pub json: Value,
}

impl Answered {
    /// The body, when the service took the call.
    ///
    /// # Errors
    ///
    /// [`WatchFailure::Refused`] naming `service` and the status when it
    /// did not.
    pub fn taken(self, service: &str) -> Result<Value, WatchFailure> {
        if (200..300).contains(&self.status) {
            return Ok(self.json);
        }
        Err(WatchFailure::Refused(format!(
            "{service} refused the registration with {}",
            self.status
        )))
    }
}

/// The calls one service's watcher makes.
pub struct WatchCalls {
    access: Access,
    headers: HeaderMap,
    client: reqwest::Client,
}

impl WatchCalls {
    /// Calls made through `access` with `pairs` as headers, each taking at
    /// most `timeout`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a header cannot be sent
    /// or the client cannot be built.
    pub fn new(
        access: Access,
        pairs: &[(&'static str, &'static str)],
        timeout: Duration,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            access,
            headers: headers(pairs)?,
            client: client(timeout)?,
        })
    }

    /// What the service answers `call`, made through `credential`, which
    /// keeps a credential the service replaced on the way.
    ///
    /// # Errors
    ///
    /// [`WatchFailure::Refused`] when the credential cannot be used or the
    /// path cannot be placed; [`WatchFailure::Unreachable`] when the
    /// service cannot be reached, is busy or fails.
    pub async fn send(
        &self,
        credential: &HeldCredential,
        call: WatchCall<'_>,
    ) -> Result<Answered, WatchFailure> {
        let reached = self
            .access
            .reach(&self.client, Some(&credential.current()))
            .await
            .map_err(watch_failure)?;
        if let Renewed::To(renewed) = reached.renewed {
            credential.replace(renewed);
        }
        let mut url = reached.endpoint.url(call.path).map_err(watch_failure)?;
        if !call.query.is_empty() {
            url.query_pairs_mut().extend_pairs(call.query);
        }
        let request = with_acting_for(
            with_authorization(
                self.client
                    .request(call.verb.method(), url)
                    .headers(self.headers.clone()),
                reached.authorization,
            ),
            reached.acting_for,
        );
        let response = with_body(request, call.body)
            .send()
            .await
            .map_err(|_| WatchFailure::Unreachable)?;
        answered(response).await
    }
}

/// `request` carrying `body`, if it sends one.
fn with_body(
    request: reqwest::RequestBuilder,
    body: Option<WatchBody<'_>>,
) -> reqwest::RequestBuilder {
    match body {
        Some(WatchBody::Json(body)) => request.json(body),
        Some(WatchBody::Form(fields)) => request
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Serializer::new(String::new()).extend_pairs(fields).finish()),
        None => request,
    }
}

/// What `response` says, a busy or failing service unreachable.
async fn answered(response: reqwest::Response) -> Result<Answered, WatchFailure> {
    let status = response.status();
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return Err(WatchFailure::Unreachable);
    }
    let body = body_within(response, LARGEST_WATCH_ANSWER)
        .await
        .map_err(|_| WatchFailure::Unreachable)?;
    Ok(Answered {
        status: status.as_u16(),
        json: serde_json::from_slice(&body).unwrap_or(Value::Null),
    })
}

/// `outcome`, a step's refusal, as a registration's.
fn watch_failure(outcome: ActionOutcome) -> WatchFailure {
    match outcome {
        ActionOutcome::Failed(why) => WatchFailure::Refused(why.as_str().to_owned()),
        ActionOutcome::TurnedAway(_)
        | ActionOutcome::Succeeded { .. }
        | ActionOutcome::NotYet { .. } => WatchFailure::Unreachable,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::security::secret::Secret;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::ServiceEndpoint;

    fn calls(server: &MockServer) -> WatchCalls {
        WatchCalls::new(
            Access::Bearer {
                endpoint: ServiceEndpoint::at(&server.uri()).unwrap(),
            },
            &[("x-api-version", "2026")],
            Duration::from_secs(2),
        )
        .unwrap()
    }

    fn token() -> HeldCredential {
        HeldCredential::new(Secret::new("test token for ann".to_owned()))
    }

    /// A registration goes to the account's address with its token, the
    /// service's headers and the body, and the service's answer comes back.
    #[tokio::test]
    async fn a_call_carries_the_token_headers_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/web/hooks"))
            .and(header("authorization", "Bearer test token for ann"))
            .and(header("x-api-version", "2026"))
            .and(body_json(serde_json::json!({ "name": "web" })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({ "id": 9 })))
            .mount(&server)
            .await;
        let body = serde_json::json!({ "name": "web" });

        let answered = calls(&server)
            .send(
                &token(),
                WatchCall {
                    verb: Verb::Post,
                    path: &["repos", "acme", "web", "hooks"],
                    query: &[],
                    body: Some(WatchBody::Json(&body)),
                },
            )
            .await
            .unwrap();

        assert_eq!(answered.taken("GitHub").unwrap()["id"], 9);
    }

    /// A refusal is handed back to be read; a busy service is unreachable.
    #[tokio::test]
    async fn a_refusal_is_read_and_a_busy_service_is_unreachable() {
        let server = MockServer::start().await;
        Mock::given(path("/locked"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        Mock::given(path("/busy"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let calls = calls(&server);
        let get = |path| WatchCall {
            verb: Verb::Get,
            path,
            query: &[],
            body: None,
        };

        let locked = calls.send(&token(), get(&["locked"])).await.unwrap();
        let busy = calls.send(&token(), get(&["busy"])).await;

        assert!(matches!(
            locked.taken("GitHub"),
            Err(WatchFailure::Refused(_))
        ));
        assert_eq!(busy, Err(WatchFailure::Unreachable));
    }

    /// A blank watcher token is refused without sending a request to the service.
    #[tokio::test]
    async fn a_blank_token_sends_nothing() {
        let server = MockServer::start().await;

        let sent = calls(&server)
            .send(
                &HeldCredential::new(Secret::new("  ".to_owned())),
                WatchCall {
                    verb: Verb::Get,
                    path: &["user"],
                    query: &[],
                    body: None,
                },
            )
            .await;

        assert!(matches!(sent, Err(WatchFailure::Refused(_))));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
