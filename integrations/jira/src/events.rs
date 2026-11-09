//! What Jira sends that a workflow may start on: an issue created, and an
//! issue updated, in one project.
//!
//! Publishing a workflow registers a webhook through the account, which
//! Jira allows only an account that signed in through the platform's
//! Atlassian app; an account holding an API token is refused with Jira's
//! reason. The registration's address carries its own secret, and a
//! delivery to it without that secret is read no further. Jira lets a
//! webhook lapse after thirty days unless refreshed, so a sweep refreshes it
//! before then; archiving deletes it. Jira keeps at most five webhooks per
//! app, person and site.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::shared::clock;
use ianua_integration::events::{
    Delivery, Events, HeldCredential, Read, Watch, WatchFailure, Watching,
};
use ianua_integration::rest::event::{EventText, FilterText, picked};
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::watch::{Answered, WatchBody, WatchCall, WatchCalls};
use ianua_integration::signature::{carries_secret, with_secret};
use serde_json::{Value, json};
use time::Duration;

/// How long Jira keeps a webhook unless it is refreshed.
const WEBHOOK_LIFETIME: Duration = Duration::days(30);

/// The project every event is watched in.
const PROJECT: FilterText = FilterText {
    name: "project",
    need: InputNeed::Required,
    meaning: "The project to watch, by its key, such as OPS.",
};

/// What every issue event gives.
const ISSUE_VALUES: &[(&str, &str)] = &[
    ("issue.key", "The issue's key, such as OPS-12."),
    ("issue.fields.summary", "Its summary."),
    ("issue.fields.issuetype.name", "Its type, such as Bug."),
    ("issue.fields.status.name", "Its status, such as To Do."),
    ("issue.fields.project.key", "Its project's key."),
];

/// An issue created.
const ISSUE_CREATED: EventText = EventText {
    key: "issue-created",
    title: "An issue is created",
    description: "Someone creates an issue in the project.",
    filters: &[PROJECT],
    outputs: ISSUE_VALUES,
};

/// An issue updated.
const ISSUE_UPDATED: EventText = EventText {
    key: "issue-updated",
    title: "An issue is updated",
    description: "Someone changes an issue in the project, such as its status or assignee.",
    filters: &[PROJECT],
    outputs: ISSUE_VALUES,
};

/// One event as Jira names it.
struct Kind {
    text: &'static EventText,
    sent_as: &'static str,
}

/// Every event, with Jira's name for it.
const KINDS: &[Kind] = &[
    Kind {
        text: &ISSUE_CREATED,
        sent_as: "jira:issue_created",
    },
    Kind {
        text: &ISSUE_UPDATED,
        sent_as: "jira:issue_updated",
    },
];

/// Every event Jira offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    KINDS.iter().map(|kind| kind.text).collect()
}

/// Jira's dynamic webhooks for workflow triggers.
pub(crate) struct Webhooks {
    calls: WatchCalls,
    exposure: DataClassLevel,
}

/// The supported webhook changes and their fixed Jira endpoints.
#[derive(Clone, Copy)]
enum WebhookAction {
    /// Creates a webhook with its registration settings.
    Register,
    /// Extends a registered webhook's lifetime.
    Renew,
    /// Removes a webhook by its remote identifier.
    Remove,
}

impl WebhookAction {
    /// The request that registers, renews or removes the webhook, with
    /// the caller's prepared JSON body.
    fn call(self, body: &Value) -> WatchCall<'_> {
        let (verb, path): (Verb, &[&str]) = match self {
            Self::Register => (Verb::Post, &["webhook"]),
            Self::Renew => (Verb::Put, &["webhook", "refresh"]),
            Self::Remove => (Verb::Delete, &["webhook"]),
        };
        WatchCall {
            verb,
            path,
            query: &[],
            body: Some(WatchBody::Json(body)),
        }
    }
}

impl Webhooks {
    /// Webhooks registered through `calls`, their deliveries counted as
    /// sensitive as `exposure`.
    pub(crate) fn new(calls: WatchCalls, exposure: DataClassLevel) -> Self {
        Self { calls, exposure }
    }

    /// Sends the webhook change with its prepared JSON body through the held credential.
    async fn webhooks(
        &self,
        credential: &HeldCredential,
        action: WebhookAction,
        body: &Value,
    ) -> Result<Answered, WatchFailure> {
        self.calls.send(credential, action.call(body)).await
    }
}

#[async_trait]
impl Events for Webhooks {
    async fn register(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let kind = kind_of(watch.event).ok_or_else(unknown)?;
        let project = project(watch)?;
        let address = with_secret(watch.address, watch.secret)
            .ok_or_else(|| WatchFailure::Refused("the registration has no address".to_owned()))?;
        let body = json!({
            "url": address,
            "webhooks": [{
                "events": [kind.sent_as],
                "jqlFilter": format!("project = \"{project}\""),
            }],
        });
        let taken = self
            .webhooks(credential, WebhookAction::Register, &body)
            .await?
            .taken("Jira")?;
        let created = &taken["webhookRegistrationResult"][0];
        let Some(id) = created["createdWebhookId"].as_u64() else {
            let reason = created["errors"][0]
                .as_str()
                .unwrap_or("it named no webhook");
            return Err(WatchFailure::Refused(format!("Jira refused it: {reason}")));
        };
        Ok(lasting(id.to_string()))
    }

    async fn renew(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let id = webhook_id(watch)?;
        let body = json!({ "webhookIds": [id] });
        self.webhooks(credential, WebhookAction::Renew, &body)
            .await?
            .taken("Jira")?;
        Ok(lasting(id.to_string()))
    }

    async fn unregister(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<(), WatchFailure> {
        let Ok(id) = webhook_id(watch) else {
            return Ok(());
        };
        let body = json!({ "webhookIds": [id] });
        let answered = self
            .webhooks(credential, WebhookAction::Remove, &body)
            .await?;
        if answered.status == 404 {
            return Ok(());
        }
        answered.taken("Jira").map(|_| ())
    }

    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read {
        if !carries_secret(delivery.address, watch.secret) {
            return Read::Forged;
        }
        let Some(kind) = kind_of(watch.event) else {
            return Read::Skip;
        };
        let Ok(payload) = serde_json::from_slice::<Value>(delivery.body) else {
            return Read::Skip;
        };
        let Some(id) = delivery.header("x-atlassian-webhook-identifier") else {
            return Read::Skip;
        };
        let in_project = watch
            .filter(PROJECT.name)
            .is_some_and(|project| payload["issue"]["fields"]["project"]["key"] == project);
        if payload["webhookEvent"] != kind.sent_as || !in_project {
            return Read::Skip;
        }
        let Ok(input) = picked(kind.text, &payload) else {
            return Read::Skip;
        };
        Read::Start {
            delivery: id.to_owned(),
            input,
            exposure: self.exposure,
        }
    }
}

/// The event `key` names, if Jira offers it.
fn kind_of(key: &ServiceEventKey) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.text.key == key.as_str())
}

/// The refusal of an event Jira does not offer.
fn unknown() -> WatchFailure {
    WatchFailure::Refused("Jira sends no such event".to_owned())
}

/// The project `watch` watches, by its key.
fn project<'a>(watch: Watch<'a>) -> Result<&'a str, WatchFailure> {
    let key = watch
        .filter(PROJECT.name)
        .ok_or_else(|| WatchFailure::Refused("the trigger names no project".to_owned()))?;
    let plain = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    match plain {
        true => Ok(key),
        false => Err(WatchFailure::Refused(
            "the project is named by its key, such as OPS".to_owned(),
        )),
    }
}

/// The id Jira gave the registration's webhook.
fn webhook_id(watch: Watch<'_>) -> Result<u64, WatchFailure> {
    watch
        .remote
        .and_then(|remote| remote.parse().ok())
        .ok_or_else(|| WatchFailure::Refused("the webhook was never registered".to_owned()))
}

/// A webhook Jira keeps as `remote` for thirty days from now.
fn lasting(remote: String) -> Watching {
    Watching {
        remote,
        lapses: Some(clock::now().saturating_add(WEBHOOK_LIFETIME)),
        routed_by: None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowValue};
    use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue};
    use ianua_domain::shared::security::secret::Secret;
    use ianua_integration::rest::access::{Access, AllowedSites, AtlassianCloud};
    use ianua_integration::rest::grant::GrantAt;
    use ianua_integration::rest::sign_in::TokenBody;
    use ianua_integration::{Renewed, ServiceEndpoint};
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const ADDRESS: &str =
        "https://ianua.test/api/v1/integrations/events/7d3f2c1a-0000-4000-8000-000000000004";

    const SECRET: &str = "the registration's jira words";

    const GRANT: &str = r#"{"cloud_id":"acme-cloud","client_id":"the app","client_secret":"the app's words","refresh_token":"first grant"}"#;

    const WEBHOOK: &str = "/ex/jira/acme-cloud/rest/api/2/webhook";

    async fn webhooks(server: &MockServer) -> Webhooks {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "an hour's token", "refresh_token": "next grant"
            })))
            .mount(server)
            .await;
        Webhooks::new(
            WatchCalls::new(
                Access::Site {
                    sites: AllowedSites::new([".atlassian.net"]),
                    api: &["rest", "api", "2"],
                    cloud: Some(AtlassianCloud {
                        gateway: ServiceEndpoint::at(&server.uri()).unwrap(),
                        grant: GrantAt {
                            token: ServiceEndpoint::at(&format!("{}/oauth/token", server.uri()))
                                .unwrap(),
                            body: TokenBody::Json,
                            scope: None,
                        },
                    }),
                },
                &[],
                StdDuration::from_secs(2),
            )
            .unwrap(),
            DataClassLevel::Internal,
        )
    }

    struct Watched {
        event: ServiceEventKey,
        filters: Vec<EventFilter>,
        secret: Secret,
        remote: Option<&'static str>,
    }

    impl Watched {
        fn on(event: &str, remote: Option<&'static str>) -> Self {
            Self {
                event: ServiceEventKey::new(event).unwrap(),
                filters: vec![EventFilter::new(
                    FieldName::new("project").unwrap(),
                    FilterValue::new("OPS").unwrap(),
                )],
                secret: Secret::new(SECRET.to_owned()),
                remote,
            }
        }

        fn watch(&self) -> Watch<'_> {
            Watch {
                event: &self.event,
                filters: &self.filters,
                address: ADDRESS,
                secret: &self.secret,
                remote: self.remote,
            }
        }
    }

    /// Ann's workflow watches OPS for new issues: publishing registers a
    /// webhook through Atlassian's gateway with a token exchanged for the
    /// grant, and the refresh token Atlassian replaced is kept.
    #[tokio::test]
    async fn registering_makes_a_webhook_and_keeps_the_replaced_grant() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(WEBHOOK))
            .and(header("authorization", "Bearer an hour's token"))
            .and(body_partial_json(json!({
                "webhooks": [{ "events": ["jira:issue_created"], "jqlFilter": "project = \"OPS\"" }]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "webhookRegistrationResult": [{ "createdWebhookId": 1000 }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on("issue-created", None);
        let held = HeldCredential::new(Secret::new(GRANT.to_owned()));

        let watching = webhooks(&server)
            .await
            .register(&held, watched.watch())
            .await
            .unwrap();

        assert_eq!(watching.remote, "1000");
        assert!(watching.lapses.is_some());
        let Renewed::To(kept) = held.into_renewed() else {
            panic!("the replaced grant was not kept");
        };
        assert!(kept.expose().contains("next grant"));
    }

    /// Jira's registration response reports invalid JQL, and the refusal
    /// retains that reason instead of returning a webhook registration.
    #[tokio::test]
    async fn a_refused_registration_names_jira_s_reason() {
        let server = MockServer::start().await;
        Mock::given(path(WEBHOOK))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "webhookRegistrationResult": [{ "errors": ["Invalid JQL"] }]
            })))
            .mount(&server)
            .await;
        let watched = Watched::on("issue-created", None);

        let refused = webhooks(&server)
            .await
            .register(
                &HeldCredential::new(Secret::new(GRANT.to_owned())),
                watched.watch(),
            )
            .await;

        assert!(
            matches!(&refused, Err(WatchFailure::Refused(why)) if why.contains("Invalid JQL")),
            "{refused:?}"
        );
    }

    fn created(project: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "webhookEvent": "jira:issue_created",
            "issue": {
                "key": "OPS-12",
                "fields": {
                    "summary": "Disk full on db-2",
                    "issuetype": { "name": "Bug" },
                    "status": { "name": "To Do" },
                    "project": { "key": project }
                }
            }
        }))
        .unwrap()
    }

    fn read(watched: &Watched, address: &str, body: &[u8]) -> Read {
        let headers = [(
            "x-atlassian-webhook-identifier".to_owned(),
            "delivery-1".to_owned(),
        )];
        let webhooks = Webhooks::new(
            WatchCalls::new(
                Access::Site {
                    sites: AllowedSites::new([".atlassian.net"]),
                    api: &["rest", "api", "2"],
                    cloud: None,
                },
                &[],
                StdDuration::from_secs(1),
            )
            .unwrap(),
            DataClassLevel::Internal,
        );
        webhooks.read(
            watched.watch(),
            Delivery {
                address,
                headers: &headers,
                body,
            },
        )
    }

    fn secret_given(secret: &str) -> String {
        with_secret(ADDRESS, &Secret::new(secret.to_owned())).unwrap()
    }

    /// Pat files OPS-12: the delivery to the address with its secret starts
    /// the workflow with the issue's key and summary.
    #[test]
    fn a_new_issue_to_the_secret_address_starts_the_workflow() {
        let watched = Watched::on("issue-created", Some("1000"));

        let read = read(&watched, &secret_given(SECRET), &created("OPS"));

        let Read::Start {
            delivery, input, ..
        } = read
        else {
            panic!("nothing started: {read:?}");
        };
        assert_eq!(delivery, "delivery-1");
        assert_eq!(
            input
                .at(&DataPath::parse("issue.key").unwrap())
                .map(|key| key.value()),
            Some(FlowValue::Text("OPS-12"))
        );
    }

    /// A delivery without the secret is marked forged. Authenticated HR
    /// issues and OPS updates are skipped by the trigger for new OPS issues.
    #[test]
    fn a_forged_delivery_or_another_project_starts_nothing() {
        let watched = Watched::on("issue-created", Some("1000"));
        let updated = serde_json::to_vec(&json!({
            "webhookEvent": "jira:issue_updated",
            "issue": { "fields": { "project": { "key": "OPS" } } }
        }))
        .unwrap();

        assert_eq!(read(&watched, ADDRESS, &created("OPS")), Read::Forged);
        assert_eq!(
            read(&watched, &secret_given(SECRET), &created("HR")),
            Read::Skip
        );
        assert_eq!(read(&watched, &secret_given(SECRET), &updated), Read::Skip);
    }
}
