//! What Azure DevOps sends that a workflow may start on: a work item
//! created in one project.
//!
//! Publishing a workflow looks the project up and adds a service hook
//! subscription for it through the account, sending to the registration's
//! address, which carries the registration's own secret; a delivery without
//! that secret is read no further. Service hooks never lapse; archiving
//! deletes the subscription. Azure DevOps names a work item's fields with
//! dots, such as `System.Title`, so the values reach the workflow under
//! plain names instead.

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_integration::events::{
    Delivery, Events, HeldCredential, Read, Watch, WatchFailure, Watching,
};
use ianua_integration::rest::event::{EventText, FilterText, picked};
use ianua_integration::rest::operation::Verb;
use ianua_integration::rest::watch::{WatchBody, WatchCall, WatchCalls};
use ianua_integration::signature::{carries_secret, with_secret};
use serde_json::{Value, json};

/// The version of Azure DevOps' REST API the calls are written for.
const API_VERSION: &[(&str, &str)] = &[("api-version", "7.1")];

/// The project every work item is watched in.
const PROJECT: FilterText = FilterText {
    name: "project",
    need: InputNeed::Required,
    meaning: "The project to watch, by its name.",
};

/// A work item created.
const WORK_ITEM_CREATED: EventText = EventText {
    key: "work-item-created",
    title: "A work item is created",
    description: "Someone creates a work item in the project, such as a bug or a task.",
    filters: &[PROJECT],
    outputs: &[
        ("work_item.id", "The work item's number."),
        ("work_item.title", "Its title."),
        ("work_item.type", "Its type, such as Bug."),
        ("work_item.state", "Its state, such as New."),
        ("work_item.project", "Its project."),
        ("work_item.url", "Its page in Azure DevOps."),
    ],
};

/// Azure DevOps' name for the event.
const SENT_AS: &str = "workitem.created";

/// Every event Azure DevOps offers, described.
pub(crate) fn all() -> Vec<&'static EventText> {
    vec![&WORK_ITEM_CREATED]
}

/// Azure DevOps' service hooks for workflow triggers.
pub(crate) struct ServiceHooks {
    calls: WatchCalls,
    exposure: DataClassLevel,
}

impl ServiceHooks {
    /// Service hooks added through `calls`, their deliveries counted as
    /// sensitive as `exposure`.
    pub(crate) fn new(calls: WatchCalls, exposure: DataClassLevel) -> Self {
        Self { calls, exposure }
    }

    /// The id of the project named `project`.
    async fn project_id(
        &self,
        credential: &HeldCredential,
        project: &str,
    ) -> Result<String, WatchFailure> {
        let found = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Get,
                    path: &["_apis", "projects", project],
                    query: API_VERSION,
                    body: None,
                },
            )
            .await?
            .taken("Azure DevOps")?;
        found["id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| WatchFailure::Refused("Azure DevOps named no project".to_owned()))
    }
}

#[async_trait]
impl Events for ServiceHooks {
    async fn register(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        ensure_known(watch.event)?;
        let project = watch
            .filter(PROJECT.name)
            .ok_or_else(|| WatchFailure::Refused("the trigger names no project".to_owned()))?;
        let project_id = self.project_id(credential, project).await?;
        let address = with_secret(watch.address, watch.secret)
            .ok_or_else(|| WatchFailure::Refused("the registration has no address".to_owned()))?;
        let body = subscription(&project_id, &address);
        let taken = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Post,
                    path: &["_apis", "hooks", "subscriptions"],
                    query: API_VERSION,
                    body: Some(WatchBody::Json(&body)),
                },
            )
            .await?
            .taken("Azure DevOps")?;
        let id = taken["id"].as_str().ok_or_else(|| {
            WatchFailure::Refused("Azure DevOps named no subscription".to_owned())
        })?;
        Ok(standing(id.to_owned()))
    }

    async fn renew(
        &self,
        _credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<Watching, WatchFailure> {
        let id = watch
            .remote
            .ok_or_else(|| WatchFailure::Refused("the subscription was never made".to_owned()))?;
        Ok(standing(id.to_owned()))
    }

    async fn unregister(
        &self,
        credential: &HeldCredential,
        watch: Watch<'_>,
    ) -> Result<(), WatchFailure> {
        let Some(id) = watch.remote else {
            return Ok(());
        };
        let answered = self
            .calls
            .send(
                credential,
                WatchCall {
                    verb: Verb::Delete,
                    path: &["_apis", "hooks", "subscriptions", id],
                    query: API_VERSION,
                    body: None,
                },
            )
            .await?;
        if answered.status == 404 {
            return Ok(());
        }
        answered.taken("Azure DevOps").map(|_| ())
    }

    fn read(&self, watch: Watch<'_>, delivery: Delivery<'_>) -> Read {
        if !carries_secret(delivery.address, watch.secret) {
            return Read::Forged;
        }
        let Ok(payload) = serde_json::from_slice::<Value>(delivery.body) else {
            return Read::Skip;
        };
        let Some(id) = payload["id"].as_str() else {
            return Read::Skip;
        };
        let work_item = work_item(&payload["resource"]);
        let in_project = watch
            .filter(PROJECT.name)
            .is_some_and(|project| work_item["project"] == project);
        if ensure_known(watch.event).is_err() || payload["eventType"] != SENT_AS || !in_project {
            return Read::Skip;
        }
        let Ok(input) = picked(&WORK_ITEM_CREATED, &json!({ "work_item": work_item })) else {
            return Read::Skip;
        };
        Read::Start {
            delivery: id.to_owned(),
            input,
            exposure: self.exposure,
        }
    }
}

/// The refusal of an event Azure DevOps does not offer, unless `key` is
/// one.
fn ensure_known(key: &ServiceEventKey) -> Result<(), WatchFailure> {
    if key.as_str() == WORK_ITEM_CREATED.key {
        return Ok(());
    }
    Err(WatchFailure::Refused(
        "Azure DevOps sends no such event".to_owned(),
    ))
}

/// The subscription sending new work items of `project_id` to `address`.
fn subscription(project_id: &str, address: &str) -> Value {
    json!({
        "publisherId": "tfs",
        "eventType": SENT_AS,
        "resourceVersion": "1.0",
        "consumerId": "webHooks",
        "consumerActionId": "httpRequest",
        "publisherInputs": { "projectId": project_id },
        "consumerInputs": { "url": address },
    })
}

/// The work item `resource` describes, under plain names.
fn work_item(resource: &Value) -> Value {
    let fields = &resource["fields"];
    json!({
        "id": resource["id"],
        "title": fields["System.Title"],
        "type": fields["System.WorkItemType"],
        "state": fields["System.State"],
        "project": fields["System.TeamProject"],
        "url": resource["_links"]["html"]["href"],
    })
}

/// A subscription Azure DevOps keeps until it is deleted, by its `id`.
fn standing(id: String) -> Watching {
    Watching {
        remote: id,
        lapses: None,
        routed_by: None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_domain::domains::workflows::data::{DataPath, FieldName, FlowValue};
    use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue};
    use ianua_domain::shared::security::secret::Secret;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::access::Access;
    use wiremock::matchers::{body_partial_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const ADDRESS: &str =
        "https://ianua.test/api/v1/integrations/events/7d3f2c1a-0000-4000-8000-000000000005";

    const SECRET: &str = "the registration's azure words";

    fn hooks(endpoint: &str) -> ServiceHooks {
        ServiceHooks::new(
            WatchCalls::new(
                Access::Organization {
                    base: ServiceEndpoint::at(endpoint).unwrap(),
                    signed_in: None,
                },
                &[],
                Duration::from_secs(2),
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
        fn on(remote: Option<&'static str>) -> Self {
            Self {
                event: ServiceEventKey::new("work-item-created").unwrap(),
                filters: vec![EventFilter::new(
                    FieldName::new("project").unwrap(),
                    FilterValue::new("Fabrikam").unwrap(),
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

    fn account() -> HeldCredential {
        HeldCredential::new(Secret::new(
            r#"{"organization":"contoso","token":"the team's token words"}"#.to_owned(),
        ))
    }

    fn secret_given(secret: &str) -> String {
        with_secret(ADDRESS, &Secret::new(secret.to_owned())).unwrap()
    }

    /// Ann's workflow watches Fabrikam for new work items: publishing finds
    /// the project and subscribes the registration's address, with its
    /// secret, to its new work items.
    #[tokio::test]
    async fn registering_subscribes_the_address_to_the_project() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/contoso/_apis/projects/Fabrikam"))
            .and(query_param("api-version", "7.1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "proj-1" })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/contoso/_apis/hooks/subscriptions"))
            .and(body_partial_json(json!({
                "eventType": "workitem.created",
                "publisherInputs": { "projectId": "proj-1" },
                "consumerInputs": { "url": secret_given(SECRET) }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "sub-1" })))
            .expect(1)
            .mount(&server)
            .await;
        let watched = Watched::on(None);

        let watching = hooks(&format!("{}/", server.uri()))
            .register(&account(), watched.watch())
            .await
            .unwrap();

        assert_eq!(watching.remote, "sub-1");
    }

    fn created(project: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": "event-1",
            "eventType": "workitem.created",
            "resource": {
                "id": 42,
                "fields": {
                    "System.Title": "Login fails",
                    "System.WorkItemType": "Bug",
                    "System.State": "New",
                    "System.TeamProject": project
                },
                "_links": { "html": { "href": "https://dev.azure.com/contoso/Fabrikam/_workitems/edit/42" } }
            }
        }))
        .unwrap()
    }

    fn read(watched: &Watched, address: &str, body: &[u8]) -> Read {
        hooks("https://dev.azure.test/").read(
            watched.watch(),
            Delivery {
                address,
                headers: &[],
                body,
            },
        )
    }

    /// Pat files bug 42 in Fabrikam: the delivery to the address with its
    /// secret starts the workflow with the work item under plain names.
    #[test]
    fn a_new_work_item_to_the_secret_address_starts_the_workflow() {
        let watched = Watched::on(Some("sub-1"));

        let read = read(&watched, &secret_given(SECRET), &created("Fabrikam"));

        let Read::Start {
            delivery, input, ..
        } = read
        else {
            panic!("nothing started: {read:?}");
        };
        assert_eq!(delivery, "event-1");
        assert_eq!(
            input
                .at(&DataPath::parse("work_item.title").unwrap())
                .map(|title| title.value()),
            Some(FlowValue::Text("Login fails"))
        );
    }

    /// A missing registration secret marks the delivery as forged; a valid
    /// secret with a work item from another project produces no start.
    #[test]
    fn a_forged_delivery_or_another_project_starts_nothing() {
        let watched = Watched::on(Some("sub-1"));

        assert_eq!(read(&watched, ADDRESS, &created("Fabrikam")), Read::Forged);
        assert_eq!(
            read(&watched, &secret_given(SECRET), &created("Contoso Web")),
            Read::Skip
        );
    }
}
