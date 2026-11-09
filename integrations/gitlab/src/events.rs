//! What GitLab sends that a workflow may start on: an issue opened, a merge
//! request opened or merged, and a pipeline finished, each in one project.
//!
//! Publishing a workflow registers a project webhook through the account's
//! token, carrying the platform's address for the registration and its
//! secret as the webhook's secret token; GitLab sends that token back in
//! `X-Gitlab-Token` with every delivery, and a delivery without it is read
//! no further. Only the values each event describes reach the workflow.
//! Confidential issues are never asked for. GitLab's webhooks never lapse,
//! so renewing one keeps it as it stands.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::events::{
    Delivery, Events, HeldCredential, Read, Watch, WatchFailure, Watching,
};
use ianua_integration::rest::event::{EventText, FilterText, picked};
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::watch::{WatchBody, WatchCall, WatchCalls};
use ianua_integration::signature::same_secret;
use serde_json::{Map, Value, json};

/// The project every event is watched in.
const PROJECT: FilterText = FilterText {
    name: "project",
    need: InputNeed::Required,
    meaning: "The project to watch, by its full path such as acme/web, or its id.",
};

/// An issue opened.
const ISSUE_OPENED: EventText = EventText {
    key: "issue-opened",
    title: "An issue is opened",
    description: "Someone opens an issue in the project that is not confidential.",
    filters: &[PROJECT],
    outputs: &[
        (
            "project.path_with_namespace",
            "The project, as its full path.",
        ),
        (
            "object_attributes.iid",
            "The issue's number in the project.",
        ),
        ("object_attributes.title", "The issue's title."),
        (
            "object_attributes.description",
            "What the issue says, as its author wrote it.",
        ),
        ("object_attributes.url", "The issue's page at GitLab."),
        ("user.username", "Who opened it."),
    ],
};

/// A merge request opened.
const MERGE_REQUEST_OPENED: EventText = EventText {
    key: "merge-request-opened",
    title: "A merge request is opened",
    description: "Someone opens a merge request in the project.",
    filters: &[PROJECT],
    outputs: &[
        (
            "project.path_with_namespace",
            "The project, as its full path.",
        ),
        (
            "object_attributes.iid",
            "The merge request's number in the project.",
        ),
        ("object_attributes.title", "Its title."),
        (
            "object_attributes.description",
            "What it says, as its author wrote it.",
        ),
        ("object_attributes.url", "Its page at GitLab."),
        (
            "object_attributes.source_branch",
            "The branch it brings in.",
        ),
        (
            "object_attributes.target_branch",
            "The branch it goes into.",
        ),
        ("user.username", "Who opened it."),
    ],
};

/// A merge request merged.
const MERGE_REQUEST_MERGED: EventText = EventText {
    key: "merge-request-merged",
    title: "A merge request is merged",
    description: "A merge request in the project is merged.",
    filters: &[PROJECT],
    outputs: &[
        (
            "project.path_with_namespace",
            "The project, as its full path.",
        ),
        (
            "object_attributes.iid",
            "The merge request's number in the project.",
        ),
        ("object_attributes.title", "Its title."),
        ("object_attributes.url", "Its page at GitLab."),
        (
            "object_attributes.target_branch",
            "The branch it went into.",
        ),
        (
            "object_attributes.merge_commit_sha",
            "The commit the merge made.",
        ),
        ("user.username", "Who merged it."),
    ],
};

/// A pipeline finished.
const PIPELINE_FINISHED: EventText = EventText {
    key: "pipeline-finished",
    title: "A pipeline finishes",
    description: "A pipeline in the project succeeds, fails or is canceled, on any branch or on one.",
    filters: &[
        PROJECT,
        FilterText {
            name: "branch",
            need: InputNeed::Optional,
            meaning: "Only pipelines on this branch or tag, such as main; every one when left out.",
        },
    ],
    outputs: &[
        (
            "project.path_with_namespace",
            "The project, as its full path.",
        ),
        ("object_attributes.id", "The pipeline's id."),
        (
            "object_attributes.ref",
            "The branch or tag it ran on, such as main.",
        ),
        (
            "object_attributes.status",
            "How it ended: success, failed or canceled.",
        ),
        ("object_attributes.sha", "The commit it ran on."),
        ("object_attributes.duration", "How long it ran, in seconds."),
        ("object_attributes.url", "The pipeline's page at GitLab."),
        ("user.username", "Who started it."),
    ],
};

/// The pipeline statuses that end a pipeline.
const FINISHED: &[&str] = &["success", "failed", "canceled"];

/// When a delivery of a webhook's kind is the event.
enum Moment {
    /// When its `object_attributes.action` is this, such as `open`.
    Action(&'static str),
    /// When its pipeline has ended.
    Finished,
}

/// One event as GitLab names it: the `X-Gitlab-Event` it comes as, the
/// webhook setting that asks for it, and when a delivery of it counts.
struct Kind {
    text: &'static EventText,
    sent_as: &'static str,
    asked_by: &'static str,
    moment: Moment,
}

/// Every event, with GitLab's names for it.
const KINDS: &[Kind] = &[
    Kind {
        text: &ISSUE_OPENED,
        sent_as: "Issue Hook",
        asked_by: "issues_events",
        moment: Moment::Action("open"),
    },
    Kind {
        text: &MERGE_REQUEST_OPENED,
        sent_as: "Merge Request Hook",
        asked_by: "merge_requests_events",
        moment: Moment::Action("open"),
    },
    Kind {
        text: &MERGE_REQUEST_MERGED,
        sent_as: "Merge Request Hook",
        asked_by: "merge_requests_events",
        moment: Moment::Action("merge"),
    },
    Kind {
        text: &PIPELINE_FINISHED,
        sent_as: "Pipeline Hook",
        asked_by: "pipeline_events",
        moment: Moment::Finished,
    },
];

/// Every event GitLab offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    KINDS.iter().map(|kind| kind.text).collect()
}

/// GitLab's project webhooks for workflow triggers.
pub(crate) struct Hooks {
    calls: WatchCalls,
    exposure: DataClassLevel,
}

impl Hooks {
    /// Webhooks registered through `calls`, their deliveries counted as
    /// sensitive as `exposure`.
    pub(crate) fn new(calls: WatchCalls, exposure: DataClassLevel) -> Self {
        Self { calls, exposure }
    }

    /// The webhook body for `watch`, asking only for `kind`'s deliveries:
    /// GitLab sends pushes unless told not to.
    fn hook(watch: Watch<'_>, kind: &Kind) -> Value {
        let mut hook = Map::new();
        hook.insert("url".to_owned(), json!(watch.address));
        hook.insert("token".to_owned(), json!(watch.secret.expose()));
        hook.insert("enable_ssl_verification".to_owned(), json!(true));
        hook.insert("push_events".to_owned(), json!(false));
        hook.insert(kind.asked_by.to_owned(), json!(true));
        Value::Object(hook)
    }
}

#[async_trait]
impl Events for Hooks {
    async fn register(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let kind = kind_of(watch.event).ok_or_else(unknown)?;
        let project = project(watch)?;
        let body = Self::hook(watch, kind);
        let taken = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Post,
                    path: &["projects", project, "hooks"],
                    query: &[],
                    body: Some(WatchBody::Json(&body)),
                },
            )
            .await?
            .taken("GitLab")?;
        let Some(id) = taken.get("id").and_then(Value::as_u64) else {
            return Err(WatchFailure::Refused("GitLab named no webhook".to_owned()));
        };
        Ok(standing(id.to_string()))
    }

    async fn renew(
        &self,
        _credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let Some(remote) = watch.remote else {
            return Err(WatchFailure::Refused(
                "the webhook was never registered".to_owned(),
            ));
        };
        Ok(standing(remote.to_owned()))
    }

    async fn unregister(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<(), WatchFailure> {
        let Some(remote) = watch.remote else {
            return Ok(());
        };
        let project = project(watch)?;
        let answered = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Delete,
                    path: &["projects", project, "hooks", remote],
                    query: &[],
                    body: None,
                },
            )
            .await?;
        if answered.status == 404 {
            return Ok(());
        }
        answered.taken("GitLab").map(|_| ())
    }

    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read {
        if !proven(watch.secret, delivery) {
            return Read::Forged;
        }
        let Some(kind) = kind_of(watch.event) else {
            return Read::Skip;
        };
        let (Some(id), Some(event)) = (delivery_id(&delivery), delivery.header("x-gitlab-event"))
        else {
            return Read::Skip;
        };
        let Ok(payload) = serde_json::from_slice::<Value>(delivery.body) else {
            return Read::Skip;
        };
        if event != kind.sent_as || !passes(kind, &payload, watch) {
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

/// The event `key` names, if GitLab offers it.
fn kind_of(key: &ServiceEventKey) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.text.key == key.as_str())
}

/// The refusal of an event GitLab does not offer.
fn unknown() -> WatchFailure {
    WatchFailure::Refused("GitLab sends no such event".to_owned())
}

/// The project `watch` watches, as one part of the address: an id, or a
/// full path whose every part is plain.
fn project<'a>(watch: Watch<'a>) -> Result<&'a str, WatchFailure> {
    let written = watch
        .filter(PROJECT.name)
        .map(str::trim)
        .ok_or_else(|| WatchFailure::Refused("the trigger names no project".to_owned()))?;
    if !written.split('/').all(plain) {
        return Err(WatchFailure::Refused(
            "the project is not written as an id or a full path".to_owned(),
        ));
    }
    Ok(written)
}

/// Whether `part` of a project's path is made only of letters, digits,
/// dots, dashes and underscores, and is not `.` or `..`.
fn plain(part: &str) -> bool {
    !part.is_empty()
        && !matches!(part, "." | "..")
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// A webhook GitLab keeps as `remote` until it is removed.
fn standing(remote: String) -> Watching {
    Watching {
        remote,
        lapses: None,
        routed_by: None,
    }
}

/// Whether `delivery` carries the registration's `secret` as GitLab's
/// token.
fn proven(secret: &Secret, delivery: Delivery<'_>) -> bool {
    delivery
        .header("x-gitlab-token")
        .is_some_and(|given| same_secret(secret.expose(), given))
}

/// GitLab's id for `delivery`, which a resent one keeps: its idempotency
/// key, or the event's id on a GitLab too old to send one.
fn delivery_id<'d>(delivery: &'d Delivery<'_>) -> Option<&'d str> {
    delivery
        .header("idempotency-key")
        .or_else(|| delivery.header("x-gitlab-event-uuid"))
}

/// Whether `payload` is `kind`'s moment, in the watched project, and on the
/// watched branch when the trigger names one.
fn passes(kind: &Kind, payload: &Value, watch: Watch<'_>) -> bool {
    let attributes = &payload["object_attributes"];
    let at_moment = match kind.moment {
        Moment::Action(action) => attributes["action"].as_str() == Some(action),
        Moment::Finished => attributes["status"]
            .as_str()
            .is_some_and(|status| FINISHED.contains(&status)),
    };
    let in_project = watch
        .filter(PROJECT.name)
        .is_some_and(|watched| same_project(&payload["project"], watched.trim()));
    let on_branch = watch
        .filter("branch")
        .is_none_or(|branch| attributes["ref"].as_str() == Some(branch));
    at_moment && in_project && on_branch
}

/// Whether `project`, as a delivery describes it, is the one `watched`
/// names by its id or its full path.
fn same_project(project: &Value, watched: &str) -> bool {
    let by_id = project["id"]
        .as_u64()
        .is_some_and(|id| id.to_string() == watched);
    let by_path = project["path_with_namespace"]
        .as_str()
        .is_some_and(|path| path.eq_ignore_ascii_case(watched));
    by_id || by_path
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowValue};
    use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue};
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::access::Access;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const ADDRESS: &str = "https://ianua.test/api/v1/integrations/gitlab/events/one";

    const SECRET: &str = "the registration's secret words";

    fn hooks_at(base: &str) -> Hooks {
        Hooks::new(
            WatchCalls::new(
                Access::Bearer {
                    endpoint: ServiceEndpoint::at(base).unwrap(),
                },
                &[("accept", "application/json")],
                Duration::from_secs(2),
            )
            .unwrap(),
            DataClassLevel::Internal,
        )
    }

    fn hooks(server: &MockServer) -> Hooks {
        hooks_at(&format!("{}/api/v4/", server.uri()))
    }

    fn filters(entries: &[(&str, &str)]) -> Vec<EventFilter> {
        entries
            .iter()
            .map(|&(name, value)| {
                EventFilter::new(
                    FieldName::new(name).unwrap(),
                    FilterValue::new(value).unwrap(),
                )
            })
            .collect()
    }

    struct Watched {
        event: ServiceEventKey,
        filters: Vec<EventFilter>,
        secret: Secret,
        remote: Option<&'static str>,
    }

    impl Watched {
        fn on(event: &str, entries: &[(&str, &str)]) -> Self {
            Self {
                event: ServiceEventKey::new(event).unwrap(),
                filters: filters(entries),
                secret: Secret::new(SECRET.to_owned()),
                remote: Some("12"),
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

    fn token() -> HeldCredential {
        HeldCredential::new(Secret::new("acme gitlab token for workflows".to_owned()))
    }

    /// A delivery GitLab sent of `event`, carrying `secret` as its token.
    fn sent(event: &str, secret: &str) -> Vec<(String, String)> {
        vec![
            ("x-gitlab-event".to_owned(), event.to_owned()),
            ("idempotency-key".to_owned(), "delivery one".to_owned()),
            ("x-gitlab-token".to_owned(), secret.to_owned()),
        ]
    }

    fn issue(action: &str, project: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "object_kind": "issue",
            "user": { "username": "pat", "email": "pat@acme.test" },
            "project": { "id": 15, "path_with_namespace": project },
            "object_attributes": {
                "iid": 7,
                "title": "Login fails",
                "description": "Steps to reproduce",
                "url": "https://gitlab.com/acme/web/-/issues/7",
                "action": action
            }
        }))
        .unwrap()
    }

    fn pipeline(status: &str, branch: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "object_kind": "pipeline",
            "project": { "id": 15, "path_with_namespace": "acme/web" },
            "object_attributes": { "id": 31, "ref": branch, "status": status, "sha": "abc123" },
            "user": { "username": "pat" }
        }))
        .unwrap()
    }

    fn read(watched: &Watched, headers: &[(String, String)], body: &[u8]) -> Read {
        hooks_at("https://gitlab.test/api/v4/").read(
            watched.watch(),
            Delivery {
                address: ADDRESS,
                headers,
                body,
            },
        )
    }

    /// Ann's workflow watches acme/web for new issues: publishing registers
    /// a webhook on the project, named as one part with its slash escaped,
    /// asking only for issue events and carrying the platform's address and
    /// the registration's secret as its token, and keeps GitLab's id for it.
    #[tokio::test]
    async fn registering_makes_a_webhook_on_the_project() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v4/projects/acme%2Fweb/hooks"))
            .and(header(
                "authorization",
                "Bearer acme gitlab token for workflows",
            ))
            .and(body_partial_json(json!({
                "url": ADDRESS,
                "token": SECRET,
                "issues_events": true,
                "push_events": false,
                "enable_ssl_verification": true
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 12 })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on("issue-opened", &[("project", "acme/web")]);

        let watching = hooks(&server)
            .register(&token(), watched.watch())
            .await
            .unwrap();

        assert_eq!(watching.remote, "12");
        assert_eq!(watching.lapses, None);
    }

    /// A project path containing `..` is refused before a request;
    /// GitLab's 403 also refuses registration, leaving one request recorded.
    #[tokio::test]
    async fn a_crooked_project_or_a_refusal_registers_nothing() {
        let server = MockServer::start().await;
        Mock::given(path("/api/v4/projects/acme%2Flocked/hooks"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let hooks = hooks(&server);
        let crooked = Watched::on("issue-opened", &[("project", "acme/../admin")]);
        let locked = Watched::on("issue-opened", &[("project", "acme/locked")]);

        let climbed = hooks.register(&token(), crooked.watch()).await;
        let refused = hooks.register(&token(), locked.watch()).await;

        assert!(matches!(climbed, Err(WatchFailure::Refused(_))));
        assert!(matches!(refused, Err(WatchFailure::Refused(_))));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// Archiving removes the webhook; one GitLab no longer knows counts as
    /// removed.
    #[tokio::test]
    async fn unregistering_removes_the_webhook_even_when_gone() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v4/projects/acme%2Fweb/hooks/12"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/v4/projects/acme%2Fgone/hooks/12"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let hooks = hooks(&server);
        let web = Watched::on("issue-opened", &[("project", "acme/web")]);
        let gone = Watched::on("issue-opened", &[("project", "acme/gone")]);

        assert_eq!(hooks.unregister(&token(), web.watch()).await, Ok(()));
        assert_eq!(hooks.unregister(&token(), gone.watch()).await, Ok(()));
    }

    /// Pat opens issue 7 in acme/web: the delivery carrying the token
    /// starts the workflow with the issue's number and title, under
    /// GitLab's idempotency key, and Pat's email stays behind.
    #[test]
    fn an_issue_opened_with_the_token_starts_the_workflow() {
        let watched = Watched::on("issue-opened", &[("project", "acme/web")]);
        let body = issue("open", "acme/web");

        let read = read(&watched, &sent("Issue Hook", SECRET), &body);

        let Read::Start {
            delivery, input, ..
        } = read
        else {
            panic!("the delivery started nothing: {read:?}");
        };
        assert_eq!(delivery, "delivery one");
        assert_eq!(
            input
                .at(&DataPath::parse("object_attributes.iid").unwrap())
                .map(|value| value.value()),
            Some(FlowValue::Number(7.0))
        );
        assert!(input.at(&DataPath::parse("user.email").unwrap()).is_none());
    }

    /// A trigger naming the project by its id starts on the same delivery.
    #[test]
    fn a_project_named_by_its_id_is_matched() {
        let watched = Watched::on("issue-opened", &[("project", "15")]);
        let body = issue("open", "acme/web");

        let read = read(&watched, &sent("Issue Hook", SECRET), &body);

        assert!(matches!(read, Read::Start { .. }), "{read:?}");
    }

    /// An issue delivery with the wrong token or no token is marked forged
    /// rather than returned as a workflow start.
    #[test]
    fn a_delivery_with_another_token_is_forged() {
        let watched = Watched::on("issue-opened", &[("project", "acme/web")]);
        let body = issue("open", "acme/web");
        let forged = sent("Issue Hook", "mallory's own secret words");
        let unsigned: Vec<(String, String)> = forged
            .iter()
            .filter(|(name, _)| name != "x-gitlab-token")
            .cloned()
            .collect();

        assert_eq!(read(&watched, &forged, &body), Read::Forged);
        assert_eq!(read(&watched, &unsigned, &body), Read::Forged);
    }

    /// A delivery with the token that is another event, another action or
    /// another project starts nothing.
    #[test]
    fn another_event_action_or_project_is_skipped() {
        let watched = Watched::on("issue-opened", &[("project", "acme/web")]);
        let opened = issue("open", "acme/web");
        let closed = issue("close", "acme/web");
        let elsewhere = issue("open", "acme/api");

        assert_eq!(
            read(&watched, &sent("Note Hook", SECRET), &opened),
            Read::Skip
        );
        assert_eq!(
            read(&watched, &sent("Issue Hook", SECRET), &closed),
            Read::Skip
        );
        assert_eq!(
            read(&watched, &sent("Issue Hook", SECRET), &elsewhere),
            Read::Skip
        );
    }

    /// A pipeline that failed on main starts a trigger watching main; one
    /// still running, and one on another branch, do not.
    #[test]
    fn a_pipeline_starts_only_once_finished_on_the_watched_branch() {
        let watched = Watched::on(
            "pipeline-finished",
            &[("project", "acme/web"), ("branch", "main")],
        );
        let headers = sent("Pipeline Hook", SECRET);
        let (failed, running, elsewhere) = (
            pipeline("failed", "main"),
            pipeline("running", "main"),
            pipeline("success", "feature"),
        );

        let on_main = read(&watched, &headers, &failed);

        assert!(matches!(on_main, Read::Start { .. }), "{on_main:?}");
        assert_eq!(read(&watched, &headers, &running), Read::Skip);
        assert_eq!(read(&watched, &headers, &elsewhere), Read::Skip);
    }

    /// A merge request merged starts the merged trigger, not the opened one.
    #[test]
    fn a_merged_merge_request_starts_only_the_merged_trigger() {
        let merged = Watched::on("merge-request-merged", &[("project", "acme/web")]);
        let opened = Watched::on("merge-request-opened", &[("project", "acme/web")]);
        let body = serde_json::to_vec(&json!({
            "object_kind": "merge_request",
            "project": { "id": 15, "path_with_namespace": "acme/web" },
            "object_attributes": { "iid": 3, "action": "merge", "target_branch": "main" },
            "user": { "username": "pat" }
        }))
        .unwrap();
        let headers = sent("Merge Request Hook", SECRET);

        let started = read(&merged, &headers, &body);

        assert!(matches!(started, Read::Start { .. }), "{started:?}");
        assert_eq!(read(&opened, &headers, &body), Read::Skip);
    }
}
