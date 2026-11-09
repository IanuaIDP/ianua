//! Every operation the Linear integration offers, grouped by topic: issues,
//! and the teams, states, labels, projects and people of a workspace, each
//! described once with the SDK's [`Operation`], with the pickers its forms
//! fill from Linear's own lists.
//!
//! Linear's API is GraphQL alone, so every operation posts to `graphql`:
//! the document is a fixed body value under `query`, and each input is
//! placed among its `variables`, where a dot opens an object inside.

mod issues;
mod workspace;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment};

/// The path every operation posts to.
pub(crate) const GRAPHQL: &[Segment] = &[Segment::Fixed("graphql")];

/// The name the GraphQL document goes under in the body.
pub(crate) const DOCUMENT: &str = "query";

/// The teams the account can reach, picked by id and shown by name.
pub(crate) const TEAMS: PickerText = PickerText {
    filled_by: "list-teams",
    items_at: "json.data.teams.nodes",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// The chosen team's workflow states, picked by id.
pub(crate) const STATES: PickerText = PickerText {
    filled_by: "list-states",
    items_at: "json.data.team.states.nodes",
    value_at: "id",
    label_at: "name",
    depends_on: Some("team"),
};

/// The labels the chosen team may use, its own and the workspace's.
pub(crate) const LABELS: PickerText = PickerText {
    filled_by: "list-labels",
    items_at: "json.data.issueLabels.nodes",
    value_at: "id",
    label_at: "name",
    depends_on: Some("team"),
};

/// The workspace's projects, picked by id.
pub(crate) const PROJECTS: PickerText = PickerText {
    filled_by: "list-projects",
    items_at: "json.data.projects.nodes",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// The workspace's people, picked by id and shown by name.
pub(crate) const PEOPLE: PickerText = PickerText {
    filled_by: "list-users",
    items_at: "json.data.users.nodes",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// The issue an operation acts on, among the variables.
pub(crate) const ISSUE: Field = Field::required(
    "issue",
    Kind::Text,
    Place::Body,
    "The issue, by its identifier such as ENG-123 or its id, such as an earlier step's issue identifier.",
)
.sent_as("variables.issue")
.example("ENG-123");

/// How many a list holds at most.
pub(crate) const LIMIT: Field = Field::optional(
    "limit",
    Kind::Count,
    Place::Body,
    "How many to list, at most 250; 50 when not given.",
)
.sent_as("variables.first")
.more_options();

/// The team a listing reads, as a top-level variable.
pub(crate) const TEAM: Field =
    Field::required("team", Kind::Text, Place::Body, "The team, by its id.")
        .sent_as("variables.team")
        .asked_with(Ask::Picker(TEAMS));

/// The team an issue is in, inside the input.
pub(crate) const ISSUE_TEAM: Field = Field::required(
    "team",
    Kind::Text,
    Place::Body,
    "The team the issue is in, by its id.",
)
.sent_as("variables.input.teamId")
.asked_with(Ask::Picker(TEAMS));

/// The team whose labels a step's picker offers. Linear is told only the
/// labels.
pub(crate) const PICKING_TEAM: Field = Field::optional(
    "team",
    Kind::Text,
    Place::Form,
    "The team whose labels the picker offers; Linear is told only the labels.",
)
.asked_with(Ask::Picker(TEAMS));

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    issues::OPERATIONS.iter().chain(workspace::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::execution::step::ActionOutcome;
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::types::{ActionClass, DeclaredAction};
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::operation::Fixed;
    use ianua_integration::rest::request::{Call, call};
    use serde_json::{Value, json};

    use super::*;

    /// Every operation keeps the SDK's rules: a key used once, every input
    /// explained, every path input placed, no body on a read, something
    /// given back.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("linear").unwrap(), all());

        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    fn operation(key: &str) -> &'static Operation {
        all().find(|operation| operation.key == key).unwrap()
    }

    fn document(key: &str) -> &'static str {
        operation(key)
            .fixed
            .iter()
            .find_map(|(name, value)| match (*name, value) {
                (DOCUMENT, Fixed::Text(text)) => Some(*text),
                _ => None,
            })
            .unwrap()
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

    fn made(key: &str, given: Vec<(&str, FlowData)>) -> Result<Call, ActionOutcome> {
        let linear = ServiceEndpoint::at("https://api.linear.app/").unwrap();
        call(operation(key), &linear, &arguments(given))
    }

    fn variables(call: &Call) -> &Value {
        &call.body.as_ref().unwrap()["variables"]
    }

    /// Every operation posts one GraphQL document to `graphql`, and a
    /// change is a mutation while a read is a query.
    #[test]
    fn every_operation_posts_one_document_to_graphql() {
        for operation in all() {
            let written = document(operation.key);
            let reads = operation.effect == DeclaredAction::Declared(ActionClass::Read);

            assert_eq!(operation.path, GRAPHQL, "{}", operation.key);
            assert_eq!(
                written.starts_with("query "),
                reads,
                "{} is written as the wrong kind of document",
                operation.key
            );
        }
    }

    /// Ann's step opens an issue in her team with a title, a description,
    /// two labels and a priority: the document goes under `query` and every
    /// input under its name in the input variable.
    #[test]
    fn opening_an_issue_puts_its_inputs_in_the_input_variable() {
        let opened = made(
            "create-issue",
            vec![
                ("team", text("team one")),
                ("title", text("Login fails on Safari")),
                ("description", text("Seen since the last release.")),
                (
                    "labels",
                    FlowData::list(vec![text("label bug"), text("label web")]).unwrap(),
                ),
                ("priority", text("2")),
            ],
        )
        .unwrap();

        assert_eq!(opened.url.as_str(), "https://api.linear.app/graphql");
        assert_eq!(
            opened.body,
            Some(json!({
                "query": document("create-issue"),
                "variables": {
                    "input": {
                        "teamId": "team one",
                        "title": "Login fails on Safari",
                        "description": "Seen since the last release.",
                        "labelIds": ["label bug", "label web"],
                        "priority": 2
                    }
                }
            }))
        );
    }

    /// Moving ENG-7 names the issue beside the input holding its team and
    /// its new state.
    #[test]
    fn moving_an_issue_names_it_beside_its_new_state() {
        let moved = made(
            "move-issue",
            vec![
                ("issue", text("ENG-7")),
                ("team", text("team one")),
                ("state", text("state done")),
            ],
        )
        .unwrap();

        assert_eq!(
            variables(&moved),
            &json!({
                "issue": "ENG-7",
                "input": { "teamId": "team one", "stateId": "state done" }
            })
        );
    }

    /// A comment goes to the issue it names, its text as the body.
    #[test]
    fn a_comment_names_its_issue_and_text() {
        let comment = made(
            "comment-on-issue",
            vec![
                ("issue", text("ENG-7")),
                ("body", text("Fixed in the next release.")),
            ],
        )
        .unwrap();

        assert_eq!(
            variables(&comment),
            &json!({ "input": { "issueId": "ENG-7", "body": "Fixed in the next release." } })
        );
    }

    /// Searching puts the words, the team and the limit among the
    /// variables.
    #[test]
    fn searching_puts_its_words_and_limit_among_the_variables() {
        let searched = made(
            "search-issues",
            vec![
                ("term", text("login")),
                ("team", text("team one")),
                ("limit", FlowData::number(10.0).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            variables(&searched),
            &json!({ "term": "login", "team": "team one", "first": 10 })
        );
    }

    /// Ann opens the team picker: the account's teams are listed with no
    /// variables. Choosing a team lists its states and labels for the
    /// pickers that depend on it.
    #[test]
    fn pickers_list_teams_then_their_states_and_labels() {
        let teams = made("list-teams", Vec::new()).unwrap();
        let states = made("list-states", vec![("team", text("team one"))]).unwrap();
        let labels = made("list-labels", vec![("team", text("team one"))]).unwrap();

        assert_eq!(teams.body, Some(json!({ "query": document("list-teams") })));
        assert_eq!(variables(&states), &json!({ "team": "team one" }));
        assert_eq!(variables(&labels), &json!({ "team": "team one" }));
    }

    /// Missing teams, issue titles or comment targets, and a nonnumeric
    /// priority each fail request construction.
    #[test]
    fn a_missing_input_or_a_wrong_kind_builds_no_call() {
        let no_team = made("list-states", Vec::new());
        let no_title = made("create-issue", vec![("team", text("team one"))]);
        let worded = made(
            "create-issue",
            vec![
                ("team", text("team one")),
                ("title", text("Login fails")),
                ("priority", text("high")),
            ],
        );
        let no_issue = made("comment-on-issue", vec![("body", text("Fixed."))]);

        for refused in [no_team, no_title, worded, no_issue] {
            assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
        }
    }
}
