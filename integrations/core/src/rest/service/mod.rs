//! A whole integration for a REST service, made from its description: its
//! profile, its operations, how an account reaches it, the headers it asks
//! every call to carry, the request that proves a credential, and how it
//! says yes. A service that fits needs no request code of its own.

mod verdict;

use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::account_check::AccountCheck;
use ianua_domain::domains::workflows::integration::events::{ServiceEventGuide, ServiceEventSpec};
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::profile::IntegrationProfile;
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationSpec};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::UntrustedText;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};

use self::verdict::{
    by_limited_status, by_status, checked_by, graphql_verdict, judged, refused, verdict,
};
use crate::answer::{LARGEST_ANSWER, failed, outcome_of, turned_away};
use crate::client::{ServiceReach, client_reaching};
use crate::connect::SignIn;
use crate::describe::{ProfileText, profile};
use crate::events::Events;
use crate::form::PreviewText;
use crate::rest::access::{Access, Reached, with_acting_for, with_authorization};
use crate::rest::event::{DescribedEvents, ServiceEvents, described_events};
use crate::rest::operation::{Described, Offered, Operation, Verb, described};
use crate::rest::request::prepare;
use crate::{Called, Checked, Integration, Renewed, ServiceEndpoint, client};

/// How a service says whether it did what it was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answers {
    /// By the status: success is done, `429` and `503` are busy, anything
    /// else is a refusal.
    ByStatus,
    /// By `"ok"` in a JSON answer sent with success, as Slack's Web API
    /// answers: `false` is a refusal naming its `"error"`, and the error
    /// `ratelimited` is busy.
    OkFlag,
    /// As a GraphQL API answers, such as Linear's: success with a
    /// non-empty `"errors"` list is a refusal naming the first error's
    /// `"message"`, the code `RATELIMITED` is busy, and success without
    /// `"data"` does not say it was done. A probe answered with anything
    /// but success is read by its status.
    GraphQl,
}

/// The cheapest request that proves a credential works, such as GitHub's
/// `GET /user`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// The verb it calls with.
    pub verb: Verb,
    /// Its path under the account's API address.
    pub path: &'static [&'static str],
    /// Values its query carries, such as an API version.
    pub query: &'static [(&'static str, &'static str)],
}

/// What a REST service is made from.
pub struct RestServiceParams {
    /// The key it is installed under, such as `github`.
    pub key: &'static str,
    /// How it presents itself.
    pub profile: ProfileText<'static>,
    /// Every operation it offers.
    pub operations: Vec<&'static Operation>,
    /// How the steps of some of them are previewed, shaped like the
    /// service's own product.
    pub previews: &'static [PreviewText],
    /// How an account reaches it.
    pub access: Access,
    /// Headers every call carries, such as an API version.
    pub headers: &'static [(&'static str, &'static str)],
    /// The request that proves a credential.
    pub probe: Probe,
    /// How it says yes.
    pub answers: Answers,
    /// How long one call may take.
    pub timeout: Duration,
    /// The most sensitive data a step may send it, and so the most
    /// sensitive an answer is counted as.
    pub ceiling: DataClassLevel,
    /// Signing in at the service to connect an account, when the
    /// deployment registered an app with it.
    pub sign_in: Option<Box<dyn SignIn>>,
    /// The events the service sends that a workflow may start on, and what
    /// registers workflows for them; none for a service offering none.
    pub events: Option<ServiceEvents>,
}

/// An integration for a REST service, made from its description.
pub struct RestService {
    profile: IntegrationProfile,
    specs: Vec<OperationSpec>,
    guides: Vec<OperationGuide>,
    operations: Vec<&'static Operation>,
    access: Access,
    headers: HeaderMap,
    probe: Probe,
    answers: Answers,
    client: reqwest::Client,
    timeout: Duration,
    ceiling: DataClassLevel,
    sign_in: Option<Box<dyn SignIn>>,
    event_specs: Vec<ServiceEventSpec>,
    event_guides: Vec<ServiceEventGuide>,
    watcher: Option<Box<dyn Events>>,
}

/// Event descriptions paired with the watcher that implements their registrations.
struct EventSupport {
    described: DescribedEvents,
    watcher: Option<Box<dyn Events>>,
}

impl EventSupport {
    /// Builds event metadata before the service itself, preserving validation order.
    fn describe(offered: Option<ServiceEvents>, key: &IntegrationKey) -> Result<Self, DomainError> {
        match offered {
            Some(offered) => Ok(Self {
                described: described_events(&offered.described, key)?,
                watcher: Some(offered.watcher),
            }),
            None => Ok(Self {
                described: DescribedEvents {
                    specs: Vec::new(),
                    guides: Vec::new(),
                },
                watcher: None,
            }),
        }
    }
}

impl RestService {
    /// The integration `params` describe.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when a name, text or header in the
    ///   description breaks its rules.
    /// - `DomainError::Infrastructure` when the client cannot be built.
    pub fn new(params: RestServiceParams) -> Result<Self, DomainError> {
        let key = IntegrationKey::new(params.key)?;
        let offered = Offered {
            operations: &params.operations,
            previews: params.previews,
        };
        let Described { specs, guides } = described(&offered, &key, params.ceiling)?;
        let events = EventSupport::describe(params.events, &key)?;
        Ok(Self {
            profile: profile(&key, &params.profile)?,
            specs,
            guides,
            operations: params.operations,
            access: params.access,
            headers: headers(params.headers)?,
            probe: params.probe,
            answers: params.answers,
            client: client(params.timeout)?,
            timeout: params.timeout,
            ceiling: params.ceiling,
            sign_in: params.sign_in,
            event_specs: events.described.specs,
            event_guides: events.described.guides,
            watcher: events.watcher,
        })
    }

    /// The same service calling through a client that looks names up and
    /// trusts as `reach` says, such as a deployment's named resolvers and
    /// one extra authority while its deliveries are being proved.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the client cannot be built.
    pub fn reaching(mut self, reach: &ServiceReach) -> Result<Self, DomainError> {
        self.client = client_reaching(self.timeout, reach)?;
        Ok(self)
    }

    /// The request `call` asks for, with the credential reaching the
    /// service replaced, or why none is sent.
    async fn request(
        &self,
        action: &ActionCall,
        credential: Option<&Secret>,
    ) -> Result<(reqwest::RequestBuilder, Renewed), ActionOutcome> {
        let operation = self.operation(action.operation.as_str())?;
        let prepared = prepare(operation, &action.arguments)?;
        let Reached {
            endpoint,
            authorization,
            acting_for,
            renewed,
            ..
        } = self.access.reach(&self.client, credential).await?;
        let built = prepared.at(&endpoint)?;
        let payload = built.payload();
        let request = with_acting_for(
            with_authorization(
                self.client
                    .request(operation.verb.method(), built.url)
                    .headers(self.headers.clone()),
                authorization,
            ),
            acting_for,
        );
        let Some(payload) = payload else {
            return Ok((request, renewed));
        };
        let request = request
            .header(CONTENT_TYPE, built.shape.content_type())
            .body(payload);
        Ok((request, renewed))
    }

    /// Finds the declared operation before validating arguments or using an account.
    fn operation(&self, key: &str) -> Result<&Operation, ActionOutcome> {
        self.operations
            .iter()
            .copied()
            .find(|operation| operation.key == key)
            .ok_or_else(|| failed("the operation is not one this integration offers"))
    }

    /// The probe's request through `credential`, with the credential
    /// reaching the service replaced.
    async fn probe_request(
        &self,
        credential: &Secret,
    ) -> Result<(reqwest::RequestBuilder, Proof, Renewed), AccountCheck> {
        let Reached {
            endpoint,
            authorization,
            acting_for,
            place,
            renewed,
        } = self
            .access
            .reach(&self.client, Some(credential))
            .await
            .map_err(refused)?;
        let (verb, url, proof) = match place {
            None => (self.probe.verb, self.probe_url(&endpoint)?, Proof::Probe),
            Some(place) => self.limited_probe(&endpoint, &place)?,
        };
        let request = with_acting_for(
            with_authorization(
                self.client
                    .request(verb.method(), url)
                    .headers(self.headers.clone()),
                authorization,
            ),
            acting_for,
        );
        Ok((request, proof, renewed))
    }

    /// The address of the probe under `endpoint`.
    fn probe_url(&self, endpoint: &ServiceEndpoint) -> Result<url::Url, AccountCheck> {
        let Ok(mut url) = endpoint.url(self.probe.path) else {
            return Err(AccountCheck::Unreachable);
        };
        for (name, value) in self.probe.query {
            url.query_pairs_mut().append_pair(name, value);
        }
        Ok(url)
    }

    /// The probe for a credential limited to `place`, refused when the
    /// service has no such credentials.
    fn limited_probe(
        &self,
        endpoint: &ServiceEndpoint,
        place: &str,
    ) -> Result<(Verb, url::Url, Proof), AccountCheck> {
        let Some(limited) = self.access.limited_probe() else {
            return Err(AccountCheck::Refused(UntrustedText::record(
                "the service takes no credential limited to one place",
            )));
        };
        let segments: Vec<&str> = limited
            .before
            .iter()
            .copied()
            .chain([place])
            .chain(limited.after.iter().copied())
            .collect();
        let Ok(url) = endpoint.url(&segments) else {
            return Err(AccountCheck::Refused(UntrustedText::record(
                "the credential's place cannot be placed in the service's address",
            )));
        };
        Ok((limited.verb, url, Proof::Limited(limited.taken)))
    }

    /// How `action` went, sent through `credential`, with the credential
    /// reaching the service replaced. A replaced credential is kept
    /// whatever the call came to, since the old one no longer works.
    async fn made(&self, action: &ActionCall, credential: Option<&Secret>) -> Called {
        let (request, renewed) = match self.request(action, credential).await {
            Ok(request) => request,
            Err(refused) => return refused.into(),
        };
        Called {
            outcome: self.sent(request).await,
            renewed,
        }
    }

    /// How `request`, a step's call, went.
    async fn sent(&self, request: reqwest::RequestBuilder) -> ActionOutcome {
        let outcome = match request.send().await {
            Ok(response) => outcome_of(response, LARGEST_ANSWER, self.ceiling).await,
            Err(error) if error.is_connect() => {
                return turned_away("the service could not be reached");
            }
            Err(_) => return failed("the call did not complete, and may have reached the service"),
        };
        match self.answers {
            Answers::ByStatus => outcome,
            Answers::OkFlag => judged(outcome, verdict),
            Answers::GraphQl => judged(outcome, graphql_verdict),
        }
    }

    /// What the service says of the credential `request`, its probe, was
    /// sent through, proven as `proof` says.
    async fn verdict_of(&self, request: reqwest::RequestBuilder, proof: Proof) -> AccountCheck {
        let Ok(response) = request.send().await else {
            return AccountCheck::Unreachable;
        };
        let status = response.status();
        if let Proof::Limited(taken) = proof {
            return by_limited_status(status, taken);
        }
        let outcome = outcome_of(response, LARGEST_ANSWER, self.ceiling).await;
        match self.answers {
            Answers::ByStatus => by_status(status),
            Answers::OkFlag => checked_by(&verdict(&outcome)),
            Answers::GraphQl if !status.is_success() => by_status(status),
            Answers::GraphQl => checked_by(&graphql_verdict(&outcome)),
        }
    }
}

/// What a probe's answer proves of a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proof {
    /// The service's probe: success takes it.
    Probe,
    /// A request at the one place the credential is limited to, which the
    /// service answers with this status once it has taken the credential.
    Limited(u16),
}

#[async_trait]
impl Integration for RestService {
    fn profile(&self) -> &IntegrationProfile {
        &self.profile
    }

    fn operations(&self) -> &[OperationSpec] {
        &self.specs
    }

    fn guides(&self) -> &[OperationGuide] {
        &self.guides
    }

    async fn check_account(&self, credential: &Secret) -> AccountCheck {
        self.checked(credential).await.verdict
    }

    async fn checked(&self, credential: &Secret) -> Checked {
        let (request, proof, renewed) = match self.probe_request(credential).await {
            Ok(probe) => probe,
            Err(verdict) => {
                return Checked {
                    verdict,
                    renewed: Renewed::Unchanged,
                };
            }
        };
        Checked {
            verdict: self.verdict_of(request, proof).await,
            renewed,
        }
    }

    async fn call(&self, action: &ActionCall, credential: Option<&Secret>) -> Called {
        self.made(action, credential).await
    }

    fn grant_due(&self, credential: &Secret) -> bool {
        self.access.grant_due(credential)
    }

    async fn renew_grant(&self, credential: &Secret) -> Result<Renewed, ActionOutcome> {
        self.access.renew_grant(&self.client, credential).await
    }

    fn events(&self) -> &[ServiceEventSpec] {
        &self.event_specs
    }

    fn event_guides(&self) -> &[ServiceEventGuide] {
        &self.event_guides
    }

    fn sign_in(&self) -> Option<&dyn SignIn> {
        self.sign_in.as_deref()
    }

    fn watcher(&self) -> Option<&dyn Events> {
        self.watcher.as_deref()
    }
}

/// The headers every call carries, refused when one cannot be sent.
pub(crate) fn headers(pairs: &[(&'static str, &'static str)]) -> Result<HeaderMap, DomainError> {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) else {
            return Err(DomainError::infra_msg("a service's header cannot be sent"));
        };
        headers.insert(name, value);
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::integration::{ActionAccount, OperationKey};
    use ianua_domain::shared::events::chain::EventOrigin;
    use ianua_domain::types::{ActionCallId, ActionClass, DeclaredAction, IntegrationAccountId};
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::ServiceEndpoint;
    use crate::rest::operation::{Field, Kind, Place, Segment, Shape};

    const POST: Operation = Operation {
        key: "post-note",
        title: "Post a note",
        description: "Posts a note.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[Segment::Fixed("notes")],
        fields: &[Field::required(
            "text",
            Kind::Text,
            Place::Body,
            "What it says.",
        )],
        fixed: &[],
        query: &[("version", "2")],
        shape: Shape::Object,
        outputs: &[("status", "The status.")],
    };

    const TOKEN: &str = "test token for notes";

    fn service(server: &MockServer, answers: Answers) -> RestService {
        RestService::new(RestServiceParams {
            key: "notes",
            profile: ProfileText {
                title: "Notes",
                description: "Posts notes.",
                icon: "notes",
                picture: r#"<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M0 0h24v24H0z"/></svg>"#,
                brand: "24292f",
            },
            operations: vec![&POST],
            previews: &[],
            access: Access::Bearer {
                endpoint: ServiceEndpoint::at(&server.uri()).unwrap(),
            },
            headers: &[("x-api-version", "2026")],
            probe: Probe {
                verb: Verb::Get,
                path: &["me"],
                query: &[],
            },
            answers,
            timeout: Duration::from_secs(2),
            ceiling: DataClassLevel::Internal,
            sign_in: None,
            events: None,
        })
        .unwrap()
    }

    fn note() -> ActionCall {
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("notes").unwrap(),
            operation: OperationKey::new("post-note").unwrap(),
            account: ActionAccount::Account(IntegrationAccountId::new()),
            arguments: FlowData::map(vec![(
                FieldName::new("text").unwrap(),
                FlowData::text("hello").unwrap(),
            )])
            .unwrap(),
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn token() -> Secret {
        Secret::new(TOKEN.to_owned())
    }

    /// A step's call carries the token, the service's headers, the fixed
    /// query and the body, all from the description alone.
    #[tokio::test]
    async fn a_call_is_made_from_the_description_alone() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/notes"))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(header("x-api-version", "2026"))
            .and(wiremock::matchers::query_param("version", "2"))
            .and(body_json(json!({ "text": "hello" })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 1 })))
            .expect(1)
            .mount(&server)
            .await;

        let outcome = service(&server, Answers::ByStatus)
            .call(&note(), Some(&token()))
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// An HTTP success carrying `"ok": false` fails the step with the
    /// service's error; a rate-limit error turns it away.
    #[tokio::test]
    async fn an_ok_flag_saying_no_fails_the_step() {
        let refused = MockServer::start().await;
        Mock::given(path("/notes"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "ok": false, "error": "not_allowed" })),
            )
            .mount(&refused)
            .await;
        let limited = MockServer::start().await;
        Mock::given(path("/notes"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "ok": false, "error": "ratelimited" })),
            )
            .mount(&limited)
            .await;

        let no = service(&refused, Answers::OkFlag)
            .call(&note(), Some(&token()))
            .await
            .outcome;
        let busy = service(&limited, Answers::OkFlag)
            .call(&note(), Some(&token()))
            .await
            .outcome;

        let ActionOutcome::Failed(why) = no else {
            panic!("a refusal counted as done: {no:?}");
        };
        assert!(why.as_str().contains("not_allowed"));
        assert!(matches!(busy, ActionOutcome::TurnedAway(_)));
    }

    /// A service answering `/notes` with success and `body`.
    async fn answering(body: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(path("/notes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        server
    }

    /// Calls the sample note through the supplied service's response convention.
    async fn call_note(server: &MockServer, answers: Answers) -> ActionOutcome {
        service(server, answers)
            .call(&note(), Some(&token()))
            .await
            .outcome
    }

    /// Mounts a probe response, optionally requiring one authorization header.
    async fn mount_probe(
        server: &MockServer,
        authorization: Option<&str>,
        response: ResponseTemplate,
    ) {
        let probe = Mock::given(path("/me"));
        let probe = match authorization {
            Some(authorization) => probe.and(header("authorization", authorization)),
            None => probe,
        };
        probe.respond_with(response).mount(server).await;
    }

    /// Registers success, refusal, rate-limit and fallback responses for GraphQL probes.
    async fn graphql_probes(server: &MockServer) {
        mount_probe(
            server,
            Some(&format!("Bearer {TOKEN}")),
            ResponseTemplate::new(200)
                .set_body_json(json!({ "data": { "viewer": { "id": "1" } } })),
        )
        .await;
        mount_probe(
            server,
            Some("Bearer a refused token"),
            ResponseTemplate::new(200)
                .set_body_json(json!({ "errors": [{ "message": "Authentication required" }] })),
        )
        .await;
        mount_probe(
            server,
            Some("Bearer a busy token"),
            ResponseTemplate::new(200).set_body_json(json!({ "errors": [{ "message": "Slow down", "extensions": { "code": "RATELIMITED" } }] })),
        )
        .await;
        mount_probe(server, None, ResponseTemplate::new(401)).await;
    }

    /// A GraphQL service answering with data and no errors did the step.
    #[tokio::test]
    async fn graphql_data_without_errors_is_done() {
        let server = answering(json!({ "data": { "noteCreate": { "success": true } } })).await;

        let outcome = service(&server, Answers::GraphQl)
            .call(&note(), Some(&token()))
            .await
            .outcome;

        assert!(
            matches!(outcome, ActionOutcome::Succeeded { .. }),
            "{outcome:?}"
        );
    }

    /// GraphQL errors fail the step with the first error's message, while
    /// rate limiting turns it away. An answer without data also fails.
    #[tokio::test]
    async fn graphql_errors_fail_the_step_and_rate_limits_turn_it_away() {
        let refused = answering(json!({
            "data": null,
            "errors": [
                { "message": "Entity not found: Team", "extensions": { "code": "INVALID_INPUT" } },
                { "message": "a second error" }
            ]
        }))
        .await;
        let limited = answering(json!({
            "errors": [{ "message": "Rate limit exceeded", "extensions": { "code": "RATELIMITED" } }]
        }))
        .await;
        let silent = answering(json!({ "data": null })).await;

        let no = call_note(&refused, Answers::GraphQl).await;
        let busy = call_note(&limited, Answers::GraphQl).await;
        let unclear = call_note(&silent, Answers::GraphQl).await;

        let ActionOutcome::Failed(why) = no else {
            panic!("a refusal counted as done: {no:?}");
        };
        assert!(why.as_str().contains("Entity not found: Team"));
        assert!(matches!(busy, ActionOutcome::TurnedAway(_)));
        assert!(matches!(unclear, ActionOutcome::Failed(_)), "{unclear:?}");
    }

    /// A GraphQL probe: data proves the token, a `401` or an errors list
    /// refuses it, and a rate limit says nothing of it.
    #[tokio::test]
    async fn a_graphql_probe_reads_its_errors_and_its_status() {
        let server = MockServer::start().await;
        graphql_probes(&server).await;
        let notes = service(&server, Answers::GraphQl);

        let accepted = notes.check_account(&token()).await;
        let refused = notes
            .check_account(&Secret::new("a refused token".to_owned()))
            .await;
        let busy = notes
            .check_account(&Secret::new("a busy token".to_owned()))
            .await;
        let unknown = notes
            .check_account(&Secret::new("an unknown token".to_owned()))
            .await;

        assert_eq!(accepted, AccountCheck::Accepted);
        assert!(matches!(refused, AccountCheck::Refused(_)), "{refused:?}");
        assert_eq!(busy, AccountCheck::Unreachable);
        assert!(matches!(unknown, AccountCheck::Refused(_)), "{unknown:?}");
    }

    /// The probe proves a credential: taken on success, refused on `401`,
    /// unknown when the service is down; and a blank token is refused
    /// before anything is sent.
    #[tokio::test]
    async fn the_probe_proves_a_credential() {
        let server = MockServer::start().await;
        mount_probe(
            &server,
            Some(&format!("Bearer {TOKEN}")),
            ResponseTemplate::new(200),
        )
        .await;
        mount_probe(&server, None, ResponseTemplate::new(401)).await;
        let down = MockServer::start().await;
        mount_probe(&down, None, ResponseTemplate::new(503)).await;
        let notes = service(&server, Answers::ByStatus);

        assert_eq!(notes.check_account(&token()).await, AccountCheck::Accepted);
        assert!(matches!(
            notes.check_account(&Secret::new("wrong".to_owned())).await,
            AccountCheck::Refused(_)
        ));
        assert!(matches!(
            notes.check_account(&Secret::new(" ".to_owned())).await,
            AccountCheck::Refused(_)
        ));
        assert_eq!(
            service(&down, Answers::ByStatus)
                .check_account(&token())
                .await,
            AccountCheck::Unreachable
        );
    }

    /// An unknown operation or absent account fails the step without
    /// sending a request to the service.
    #[tokio::test]
    async fn an_unknown_operation_or_no_account_sends_nothing() {
        let server = MockServer::start().await;
        let notes = service(&server, Answers::ByStatus);
        let unknown = ActionCall {
            operation: OperationKey::new("delete-everything").unwrap(),
            ..note()
        };

        let refused = notes.call(&unknown, Some(&token())).await.outcome;
        let without = notes.call(&note(), None).await.outcome;

        assert!(matches!(refused, ActionOutcome::Failed(_)));
        assert!(matches!(without, ActionOutcome::Failed(_)));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
