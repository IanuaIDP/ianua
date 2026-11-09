//! Every operation the Azure DevOps integration offers, grouped by topic:
//! work items, pipelines and repositories, each described once with the
//! SDK's [`Operation`].

mod pipelines;
mod repositories;
mod work_items;

use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The version of Azure DevOps' REST API the calls are written for, which
/// every call names in its query.
pub(crate) const API_VERSION: &[(&str, &str)] = &[("api-version", "7.1")];

/// The project a step acts in, in the path.
pub(crate) const PROJECT: Field = Field::required(
    "project",
    Kind::Text,
    Place::Path,
    "The project's name or id, such as Web.",
);

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    work_items::OPERATIONS
        .iter()
        .chain(pipelines::OPERATIONS)
        .chain(repositories::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::call;
    use serde_json::json;

    use super::*;

    /// Every operation keeps the SDK's rules.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("azure-devops").unwrap(), all());

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    fn arguments(entries: Vec<(&str, FlowData)>) -> FlowData {
        FlowData::map(
            entries
                .into_iter()
                .map(|(name, value)| (FieldName::new(name).unwrap(), value))
                .collect(),
        )
        .unwrap()
    }

    fn text(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    fn operation(key: &str) -> &'static Operation {
        all().find(|operation| operation.key == key).unwrap()
    }

    fn acme() -> ServiceEndpoint {
        ServiceEndpoint::at("https://dev.azure.com/acme").unwrap()
    }

    /// Creating a bug writes its type after `$` and its fields as JSON
    /// Patch changes, with the API's version in the query.
    #[test]
    fn creating_a_bug_patches_its_fields() {
        let given = arguments(vec![
            ("project", text("Web")),
            ("type", text("Bug")),
            ("title", text("Login fails")),
            ("tags", text("auth; urgent")),
        ]);

        let made = call(operation("create-work-item"), &acme(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://dev.azure.com/acme/Web/_apis/wit/workitems/$Bug?api-version=7.1"
        );
        assert_eq!(made.shape.content_type(), "application/json-patch+json");
        assert_eq!(
            made.body,
            Some(json!([
                { "op": "add", "path": "/fields/System.Title", "value": "Login fails" },
                { "op": "add", "path": "/fields/System.Tags", "value": "auth; urgent" }
            ]))
        );
    }

    /// Starting a pipeline on a branch nests the branch where Azure DevOps
    /// reads it, and hands the parameters on.
    #[test]
    fn starting_a_pipeline_names_its_branch() {
        let given = arguments(vec![
            ("project", text("Web")),
            ("pipeline", FlowData::number(12.0).unwrap()),
            ("branch", text("refs/heads/main")),
            (
                "parameters",
                arguments(vec![("environment", text("staging"))]),
            ),
        ]);

        let made = call(operation("run-pipeline"), &acme(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://dev.azure.com/acme/Web/_apis/pipelines/12/runs?api-version=7.1"
        );
        assert_eq!(
            made.body,
            Some(json!({
                "resources": { "repositories": { "self": { "refName": "refs/heads/main" } } },
                "templateParameters": { "environment": "staging" }
            }))
        );
    }

    /// Reading a work item in a project named `..` fails request construction.
    #[test]
    fn a_project_that_climbs_out_builds_no_call() {
        let given = arguments(vec![
            ("project", text("..")),
            ("id", FlowData::number(7.0).unwrap()),
        ]);

        assert!(call(operation("get-work-item"), &acme(), &given).is_err());
    }
}
