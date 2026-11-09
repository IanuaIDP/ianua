//! Every operation the Jira integration offers, grouped by topic: issues
//! and people, each described once with the SDK's [`Operation`].

mod issues;
mod people;

use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The issue a step acts on, in the path.
pub(crate) const ISSUE: Field = Field::required(
    "issue",
    Kind::Text,
    Place::Path,
    "The issue's key, such as OPS-42, or its id; such as an earlier step's json.key.",
);

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    issues::OPERATIONS.iter().chain(people::OPERATIONS)
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
        let wrong = misdescribed(&IntegrationKey::new("jira").unwrap(), all());

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

    fn site() -> ServiceEndpoint {
        ServiceEndpoint::at("https://acme.atlassian.net/rest/api/2/").unwrap()
    }

    /// Creating an issue puts every value inside Jira's `fields`, the
    /// project and type by key and name.
    #[test]
    fn creating_an_issue_fills_jiras_fields() {
        let given = arguments(vec![
            ("project", text("OPS")),
            ("type", text("Bug")),
            ("summary", text("Login fails")),
            ("labels", FlowData::list(vec![text("auth")]).unwrap()),
        ]);

        let made = call(operation("create-issue"), &site(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://acme.atlassian.net/rest/api/2/issue"
        );
        assert_eq!(
            made.body,
            Some(json!({ "fields": {
                "project": { "key": "OPS" },
                "issuetype": { "name": "Bug" },
                "summary": "Login fails",
                "labels": ["auth"]
            } }))
        );
    }

    /// Moving an issue names the transition by its id, under Jira's
    /// `transition`.
    #[test]
    fn moving_an_issue_names_its_transition() {
        let given = arguments(vec![("issue", text("OPS-42")), ("transition", text("31"))]);

        let made = call(operation("transition-issue"), &site(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://acme.atlassian.net/rest/api/2/issue/OPS-42/transitions"
        );
        assert_eq!(made.body, Some(json!({ "transition": { "id": "31" } })));
    }

    /// Searching puts the query, escaped, and the limit in the address.
    #[test]
    fn searching_puts_the_jql_in_the_query() {
        let given = arguments(vec![
            ("jql", text("project = OPS AND status = \"To Do\"")),
            ("limit", FlowData::number(10.0).unwrap()),
        ]);

        let made = call(operation("search-issues"), &site(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://acme.atlassian.net/rest/api/2/search/jql?jql=project+%3D+OPS+AND+status+%3D+%22To+Do%22&maxResults=10"
        );
    }
}
