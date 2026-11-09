//! What GitHub sends that a workflow may start on: an issue opened, a pull
//! request opened, and a push, each in one repository.
//!
//! Publishing a workflow registers a webhook on its repository through the
//! account's token, carrying the platform's address for the registration
//! and its secret; GitHub signs every delivery with that secret, and a
//! delivery whose signature does not check out is read no further. Only
//! the values each event describes reach the workflow. GitHub's webhooks
//! never lapse, so renewing one keeps it as it stands.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::shared::security::secret::Secret;
use ianua_integration::events::{
    Delivery, Events, HeldCredential, Read, Watch, WatchFailure, Watching,
};
use ianua_integration::rest::event::{EventText, FilterText, picked};
use ianua_integration::rest::names::pair;
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::watch::{WatchBody, WatchCall, WatchCalls};
use ianua_integration::signature::{hmac_sha256, matches_hex};
use serde_json::{Value, json};

/// The repository every event is watched in.
const REPOSITORY: FilterText = FilterText {
    name: "repository",
    need: InputNeed::Required,
    meaning: "The repository to watch, as owner/name, such as acme/web.",
};

/// An issue opened.
const ISSUE_OPENED: EventText = EventText {
    key: "issue-opened",
    title: "An issue is opened",
    description: "Someone opens an issue in the repository.",
    filters: &[REPOSITORY],
    outputs: &[
        ("repository.full_name", "The repository, as owner/name."),
        ("issue.number", "The issue's number."),
        ("issue.title", "The issue's title."),
        ("issue.body", "What the issue says, as its author wrote it."),
        ("issue.html_url", "The issue's page at GitHub."),
        ("issue.user.login", "Who opened it."),
    ],
};

/// A pull request opened.
const PULL_REQUEST_OPENED: EventText = EventText {
    key: "pull-request-opened",
    title: "A pull request is opened",
    description: "Someone opens a pull request in the repository.",
    filters: &[REPOSITORY],
    outputs: &[
        ("repository.full_name", "The repository, as owner/name."),
        ("pull_request.number", "The pull request's number."),
        ("pull_request.title", "Its title."),
        ("pull_request.body", "What it says, as its author wrote it."),
        ("pull_request.html_url", "Its page at GitHub."),
        ("pull_request.user.login", "Who opened it."),
        ("pull_request.head.ref", "The branch it brings in."),
        ("pull_request.base.ref", "The branch it goes into."),
    ],
};

/// A push to a branch.
const PUSHED: EventText = EventText {
    key: "pushed",
    title: "Commits are pushed",
    description: "Someone pushes commits to the repository, or to one branch of it.",
    filters: &[
        REPOSITORY,
        FilterText {
            name: "branch",
            need: InputNeed::Optional,
            meaning: "Only pushes to this branch, such as main; every branch when left out.",
        },
    ],
    outputs: &[
        ("repository.full_name", "The repository, as owner/name."),
        (
            "ref",
            "The full name of what was pushed, such as refs/heads/main.",
        ),
        ("after", "The commit the branch now points at."),
        ("pusher.name", "Who pushed."),
        ("head_commit.message", "The newest commit's message."),
    ],
};

/// One event as GitHub names it: its webhook event and, for one GitHub
/// sends for several actions, the action.
struct Kind {
    text: &'static EventText,
    sent_as: &'static str,
    action: Option<&'static str>,
}

/// Every event, with GitHub's names for it.
const KINDS: &[Kind] = &[
    Kind {
        text: &ISSUE_OPENED,
        sent_as: "issues",
        action: Some("opened"),
    },
    Kind {
        text: &PULL_REQUEST_OPENED,
        sent_as: "pull_request",
        action: Some("opened"),
    },
    Kind {
        text: &PUSHED,
        sent_as: "push",
        action: None,
    },
];

/// Every event GitHub offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    KINDS.iter().map(|kind| kind.text).collect()
}

/// GitHub's webhooks for workflow triggers.
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

    /// The webhook `body` for `watch`, of GitHub's event `sent_as`.
    fn hook(watch: Watch<'_>, sent_as: &str) -> Value {
        json!({
            "name": "web",
            "active": true,
            "events": [sent_as],
            "config": {
                "url": watch.address,
                "content_type": "json",
                "secret": watch.secret.expose(),
                "insecure_ssl": "0",
            },
        })
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
        let (owner, name) = repository(watch)?;
        let body = Self::hook(watch, kind.sent_as);
        let taken = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Post,
                    path: &["repos", owner, name, "hooks"],
                    query: &[],
                    body: Some(WatchBody::Json(&body)),
                },
            )
            .await?
            .taken("GitHub")?;
        let Some(id) = taken.get("id").and_then(Value::as_u64) else {
            return Err(WatchFailure::Refused("GitHub named no webhook".to_owned()));
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
        let (owner, name) = repository(watch)?;
        let answered = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Delete,
                    path: &["repos", owner, name, "hooks", remote],
                    query: &[],
                    body: None,
                },
            )
            .await?;
        if answered.status == 404 {
            return Ok(());
        }
        answered.taken("GitHub").map(|_| ())
    }

    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read {
        if !signed(watch.secret, delivery) {
            return Read::Forged;
        }
        let Some(kind) = kind_of(watch.event) else {
            return Read::Skip;
        };
        let (Some(id), Some(event)) = (
            delivery.header("x-github-delivery"),
            delivery.header("x-github-event"),
        ) else {
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

/// The event `key` names, if GitHub offers it.
fn kind_of(key: &ServiceEventKey) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.text.key == key.as_str())
}

/// The refusal of an event GitHub does not offer.
fn unknown() -> WatchFailure {
    WatchFailure::Refused("GitHub sends no such event".to_owned())
}

/// The owner and name of the repository `watch` watches.
fn repository<'a>(watch: Watch<'a>) -> Result<(&'a str, &'a str), WatchFailure> {
    let written = watch
        .filter(REPOSITORY.name)
        .ok_or_else(|| WatchFailure::Refused("the trigger names no repository".to_owned()))?;
    pair(REPOSITORY.name, written).map_err(|_| {
        WatchFailure::Refused("the repository is not written as owner/name".to_owned())
    })
}

/// A webhook GitHub keeps as `remote` until it is removed.
fn standing(remote: String) -> Watching {
    Watching {
        remote,
        lapses: None,
        routed_by: None,
    }
}

/// Whether `delivery` carries GitHub's signature of its body under
/// `secret`.
fn signed(secret: &Secret, delivery: Delivery<'_>) -> bool {
    let Some(given) = delivery
        .header("x-hub-signature-256")
        .and_then(|header| header.strip_prefix("sha256="))
    else {
        return false;
    };
    matches_hex(
        &hmac_sha256(secret.expose().as_bytes(), &[delivery.body]),
        given,
    )
}

/// Whether `payload` is `kind`'s action, in the watched repository, and on
/// the watched branch when the trigger names one.
fn passes(kind: &Kind, payload: &Value, watch: Watch<'_>) -> bool {
    let action = kind
        .action
        .is_none_or(|action| payload["action"].as_str() == Some(action));
    let in_repository = watch.filter(REPOSITORY.name).is_some_and(|watched| {
        payload["repository"]["full_name"]
            .as_str()
            .is_some_and(|sent| sent.eq_ignore_ascii_case(watched))
    });
    let on_branch = watch.filter("branch").is_none_or(|branch| {
        payload["ref"].as_str() == Some(format!("refs/heads/{branch}").as_str())
    });
    action && in_repository && on_branch
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

    const ADDRESS: &str = "https://ianua.test/api/v1/integrations/github/events/one";

    fn hooks(server: &MockServer) -> Hooks {
        Hooks::new(
            WatchCalls::new(
                Access::Bearer {
                    endpoint: ServiceEndpoint::at(&server.uri()).unwrap(),
                },
                &[("accept", "application/vnd.github+json")],
                Duration::from_secs(2),
            )
            .unwrap(),
            DataClassLevel::Internal,
        )
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
                secret: Secret::new("the registration's secret words".to_owned()),
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
        HeldCredential::new(Secret::new("test token for ann".to_owned()))
    }

    /// A delivery GitHub sent of `event` with `body`, signed with `secret`.
    fn sent(event: &str, body: &[u8], secret: &str) -> Vec<(String, String)> {
        let signature = hmac_sha256(secret.as_bytes(), &[body])
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        vec![
            ("x-github-event".to_owned(), event.to_owned()),
            ("x-github-delivery".to_owned(), "delivery one".to_owned()),
            (
                "x-hub-signature-256".to_owned(),
                format!("sha256={signature}"),
            ),
        ]
    }

    fn opened_issue() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "action": "opened",
            "issue": {
                "number": 7,
                "title": "Login fails",
                "body": "Steps to reproduce",
                "html_url": "https://github.com/acme/web/issues/7",
                "user": { "login": "pat" }
            },
            "repository": { "full_name": "acme/web" },
            "sender": { "login": "pat" }
        }))
        .unwrap()
    }

    fn read(watched: &Watched, headers: &[(String, String)], body: &[u8]) -> Read {
        let hooks = Hooks::new(
            WatchCalls::new(
                Access::Bearer {
                    endpoint: ServiceEndpoint::at("https://api.github.test/").unwrap(),
                },
                &[],
                Duration::from_secs(1),
            )
            .unwrap(),
            DataClassLevel::Internal,
        );
        hooks.read(
            watched.watch(),
            Delivery {
                address: ADDRESS,
                headers,
                body,
            },
        )
    }

    /// Ann's workflow watches acme/web for new issues: publishing registers
    /// a webhook there for GitHub's issue events, carrying the platform's
    /// address and the registration's secret, and keeps GitHub's id for it.
    #[tokio::test]
    async fn registering_makes_a_webhook_on_the_repository() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/web/hooks"))
            .and(header("authorization", "Bearer test token for ann"))
            .and(body_partial_json(json!({
                "events": ["issues"],
                "config": {
                    "url": ADDRESS,
                    "secret": "the registration's secret words",
                    "content_type": "json"
                }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 12 })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on("issue-opened", &[("repository", "acme/web")]);

        let watching = hooks(&server)
            .register(&token(), watched.watch())
            .await
            .unwrap();

        assert_eq!(watching.remote, "12");
        assert_eq!(watching.lapses, None);
    }

    /// A repository path containing `..` is refused before a request;
    /// GitHub's 403 also refuses registration, leaving one request recorded.
    #[tokio::test]
    async fn a_crooked_repository_or_a_refusal_registers_nothing() {
        let server = MockServer::start().await;
        Mock::given(path("/repos/acme/locked/hooks"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let hooks = hooks(&server);
        let crooked = Watched::on("issue-opened", &[("repository", "acme/../admin")]);
        let locked = Watched::on("issue-opened", &[("repository", "acme/locked")]);

        let climbed = hooks.register(&token(), crooked.watch()).await;
        let refused = hooks.register(&token(), locked.watch()).await;

        assert!(matches!(climbed, Err(WatchFailure::Refused(_))));
        assert!(matches!(refused, Err(WatchFailure::Refused(_))));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// Archiving removes the webhook; one GitHub no longer knows counts as
    /// removed.
    #[tokio::test]
    async fn unregistering_removes_the_webhook_even_when_gone() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/repos/acme/web/hooks/12"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/repos/acme/gone/hooks/12"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let hooks = hooks(&server);
        let web = Watched::on("issue-opened", &[("repository", "acme/web")]);
        let gone = Watched::on("issue-opened", &[("repository", "acme/gone")]);

        assert_eq!(hooks.unregister(&token(), web.watch()).await, Ok(()));
        assert_eq!(hooks.unregister(&token(), gone.watch()).await, Ok(()));
    }

    /// Pat opens issue 7 in acme/web: the signed delivery starts the
    /// workflow with the issue's number and title, under GitHub's delivery
    /// id.
    #[test]
    fn a_signed_issue_opened_starts_the_workflow() {
        let watched = Watched::on("issue-opened", &[("repository", "acme/web")]);
        let body = opened_issue();
        let headers = sent("issues", &body, "the registration's secret words");

        let read = read(&watched, &headers, &body);

        let Read::Start {
            delivery, input, ..
        } = read
        else {
            panic!("the delivery started nothing: {read:?}");
        };
        assert_eq!(delivery, "delivery one");
        assert_eq!(
            input
                .at(&DataPath::parse("issue.number").unwrap())
                .map(|value| value.value()),
            Some(FlowValue::Number(7.0))
        );
        assert!(input.at(&DataPath::parse("sender").unwrap()).is_none());
    }

    /// An issue delivery signed with another secret or sent unsigned is
    /// marked forged rather than returned as a workflow start.
    #[test]
    fn a_delivery_signed_with_another_secret_is_forged() {
        let watched = Watched::on("issue-opened", &[("repository", "acme/web")]);
        let body = opened_issue();
        let forged = sent("issues", &body, "mallory's own secret words");
        let unsigned: Vec<(String, String)> = forged
            .iter()
            .filter(|(name, _)| name != "x-hub-signature-256")
            .cloned()
            .collect();

        assert_eq!(read(&watched, &forged, &body), Read::Forged);
        assert_eq!(read(&watched, &unsigned, &body), Read::Forged);
    }

    /// A signed delivery that is another event, another action or another
    /// repository starts nothing.
    #[test]
    fn another_event_action_or_repository_is_skipped() {
        let watched = Watched::on("issue-opened", &[("repository", "acme/web")]);
        let elsewhere = Watched::on("issue-opened", &[("repository", "acme/api")]);
        let body = opened_issue();
        let closed = serde_json::to_vec(&json!({
            "action": "closed",
            "repository": { "full_name": "acme/web" }
        }))
        .unwrap();
        let secret = "the registration's secret words";

        assert_eq!(
            read(&watched, &sent("ping", &body, secret), &body),
            Read::Skip
        );
        assert_eq!(
            read(&watched, &sent("issues", &closed, secret), &closed),
            Read::Skip
        );
        assert_eq!(
            read(&elsewhere, &sent("issues", &body, secret), &body),
            Read::Skip
        );
    }

    /// A push to main starts a trigger watching main; a push to another
    /// branch does not.
    #[test]
    fn a_push_starts_only_on_the_watched_branch() {
        let watched = Watched::on("pushed", &[("repository", "acme/web"), ("branch", "main")]);
        let secret = "the registration's secret words";
        let push = |branch: &str| {
            serde_json::to_vec(&json!({
                "ref": format!("refs/heads/{branch}"),
                "after": "abc123",
                "repository": { "full_name": "acme/web" },
                "pusher": { "name": "pat" }
            }))
            .unwrap()
        };
        let (main, feature) = (push("main"), push("feature"));

        let on_main = read(&watched, &sent("push", &main, secret), &main);
        let on_feature = read(&watched, &sent("push", &feature, secret), &feature);

        assert!(matches!(on_main, Read::Start { .. }), "{on_main:?}");
        assert_eq!(on_feature, Read::Skip);
    }
}
