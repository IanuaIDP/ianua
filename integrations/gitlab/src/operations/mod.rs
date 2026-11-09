//! Every operation the GitLab integration offers, grouped by topic: issues,
//! merge requests, projects and repository files, each described once with
//! the SDK's [`Operation`], with the pickers its forms fill from GitLab's
//! own lists.
//!
//! A project is named by its id or its full path, such as `acme/web`, and
//! placed in the address as one part, its slashes escaped as `%2F` as
//! GitLab asks. A branch and a file's path are placed the same way.

mod files;
mod issues;
mod merge_requests;
mod projects;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The projects the account is a member of, picked by their full path.
const PROJECTS: PickerText = PickerText {
    filled_by: "list-projects",
    items_at: "json",
    value_at: "path_with_namespace",
    label_at: "name_with_namespace",
    depends_on: None,
};

/// The chosen project's labels, picked by name.
pub(crate) const LABELS: PickerText = PickerText {
    filled_by: "list-labels",
    items_at: "json",
    value_at: "name",
    label_at: "name",
    depends_on: Some("project"),
};

/// The chosen project's branches, picked by name.
pub(crate) const BRANCHES: PickerText = PickerText {
    filled_by: "list-branches",
    items_at: "json",
    value_at: "name",
    label_at: "name",
    depends_on: Some("project"),
};

/// The project every operation but the project listing acts in.
pub(crate) const PROJECT: Field = Field::required(
    "project",
    Kind::Text,
    Place::Path,
    "The project, by its id or its full path, such as acme/web.",
)
.asked_with(Ask::Picker(PROJECTS))
.example("acme/web");

/// How many a listing gives at most, under GitLab's name.
pub(crate) const LIMIT: Field = Field::optional(
    "limit",
    Kind::Count,
    Place::Query,
    "How many to list, at most 100; 20 when not given.",
)
.sent_as("per_page")
.more_options();

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    issues::OPERATIONS
        .iter()
        .chain(merge_requests::OPERATIONS)
        .chain(projects::OPERATIONS)
        .chain(files::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::execution::step::ActionOutcome;
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::{Call, call};
    use serde_json::json;

    use super::*;

    /// Every operation keeps the SDK's rules: a key used once, every input
    /// explained, every path input placed, every picker filled by a read,
    /// no body on a read, something given back.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("gitlab").unwrap(), all());

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

    fn made(key: &str, given: Vec<(&str, FlowData)>) -> Result<Call, ActionOutcome> {
        let operation = all().find(|operation| operation.key == key).unwrap();
        let gitlab = ServiceEndpoint::at("https://gitlab.com/api/v4/").unwrap();
        call(operation, &gitlab, &arguments(given))
    }

    /// Opening an issue in acme/web names the project as one part of the
    /// address, its slash escaped, and sends the title, text and labels.
    #[test]
    fn opening_an_issue_names_the_project_as_one_part() {
        let opened = made(
            "create-issue",
            vec![
                ("project", text("acme/web")),
                ("title", text("Nightly build failed")),
                ("description", text("See the run log.")),
                (
                    "labels",
                    FlowData::list(vec![text("ci"), text("urgent")]).unwrap(),
                ),
            ],
        )
        .unwrap();

        assert_eq!(
            opened.url.as_str(),
            "https://gitlab.com/api/v4/projects/acme%2Fweb/issues"
        );
        assert_eq!(
            opened.body,
            Some(json!({
                "title": "Nightly build failed",
                "description": "See the run log.",
                "labels": ["ci", "urgent"]
            }))
        );
    }

    /// A project named by its id goes in the same place.
    #[test]
    fn a_project_may_be_named_by_its_id() {
        let read = made(
            "get-issue",
            vec![
                ("project", text("278964")),
                ("issue", FlowData::number(7.0).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            read.url.as_str(),
            "https://gitlab.com/api/v4/projects/278964/issues/7"
        );
        assert_eq!(read.body, None, "a read sends no body");
    }

    /// Closing issue 7 puts the close event in its body, under its number.
    #[test]
    fn closing_an_issue_sends_the_close_event() {
        let closed = made(
            "close-issue",
            vec![
                ("project", text("acme/web")),
                ("issue", FlowData::number(7.0).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            closed.url.as_str(),
            "https://gitlab.com/api/v4/projects/acme%2Fweb/issues/7"
        );
        assert_eq!(closed.body, Some(json!({ "state_event": "close" })));
    }

    /// Adding labels sends them under GitLab's add_labels, so the labels
    /// the issue has stay.
    #[test]
    fn adding_labels_keeps_the_ones_there() {
        let labelled = made(
            "add-labels",
            vec![
                ("project", text("acme/web")),
                ("issue", FlowData::number(7.0).unwrap()),
                ("labels", FlowData::list(vec![text("triaged")]).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(labelled.body, Some(json!({ "add_labels": ["triaged"] })));
    }

    /// Listing open issues with two labels puts them in the query, the
    /// labels joined by a comma and the limit under GitLab's name.
    #[test]
    fn listing_issues_puts_its_filters_in_the_query() {
        let listed = made(
            "list-issues",
            vec![
                ("project", text("acme/web")),
                ("state", text("opened")),
                (
                    "labels",
                    FlowData::list(vec![text("bug"), text("urgent")]).unwrap(),
                ),
                ("limit", FlowData::number(50.0).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            listed.url.as_str(),
            "https://gitlab.com/api/v4/projects/acme%2Fweb/issues?state=opened&labels=bug%2Curgent&per_page=50"
        );
    }

    /// A missing issue title, a text issue number, and a project named `..`
    /// each fail request construction.
    #[test]
    fn an_issue_missing_its_title_or_numbered_with_a_word_builds_no_call() {
        let without_title = made("create-issue", vec![("project", text("acme/web"))]);
        let worded = made(
            "get-issue",
            vec![("project", text("acme/web")), ("issue", text("seven"))],
        );
        let climbing = made(
            "get-issue",
            vec![
                ("project", text("..")),
                ("issue", FlowData::number(7.0).unwrap()),
            ],
        );

        for refused in [without_title, worded, climbing] {
            assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
        }
    }

    /// Opening a merge request sends both branches and the squash flag.
    #[test]
    fn opening_a_merge_request_sends_both_branches() {
        let opened = made(
            "create-merge-request",
            vec![
                ("project", text("acme/web")),
                ("title", text("Fix login")),
                ("source_branch", text("fix-login")),
                ("target_branch", text("main")),
                ("squash", FlowData::bool(true)),
            ],
        )
        .unwrap();

        assert_eq!(
            opened.url.as_str(),
            "https://gitlab.com/api/v4/projects/acme%2Fweb/merge_requests"
        );
        assert_eq!(
            opened.body,
            Some(json!({
                "title": "Fix login",
                "source_branch": "fix-login",
                "target_branch": "main",
                "squash": true
            }))
        );
    }

    /// Merging names the merge request and sends the branch removal under
    /// GitLab's name.
    #[test]
    fn merging_sends_the_branch_removal_under_gitlabs_name() {
        let merged = made(
            "merge-merge-request",
            vec![
                ("project", text("acme/web")),
                ("merge_request", FlowData::number(12.0).unwrap()),
                ("remove_source_branch", FlowData::bool(true)),
            ],
        )
        .unwrap();

        assert_eq!(
            merged.url.as_str(),
            "https://gitlab.com/api/v4/projects/acme%2Fweb/merge_requests/12/merge"
        );
        assert_eq!(
            merged.body,
            Some(json!({ "should_remove_source_branch": true }))
        );
    }

    /// Opening a merge request without a target branch fails request
    /// construction.
    #[test]
    fn a_merge_request_without_its_target_builds_no_call() {
        let opened = made(
            "create-merge-request",
            vec![
                ("project", text("acme/web")),
                ("title", text("Fix login")),
                ("source_branch", text("fix-login")),
            ],
        );

        assert!(matches!(opened, Err(ActionOutcome::Failed(_))));
    }

    /// Reading `scripts/tidy.py` at `main` names the file as one part, its
    /// slash escaped, with the ref in the query.
    #[test]
    fn reading_a_file_names_it_as_one_part() {
        let read = made(
            "get-file",
            vec![
                ("project", text("acme/web")),
                ("path", text("scripts/tidy.py")),
                ("ref", text("main")),
            ],
        )
        .unwrap();

        assert_eq!(
            read.url.as_str(),
            "https://gitlab.com/api/v4/projects/acme%2Fweb/repository/files/scripts%2Ftidy.py?ref=main"
        );
    }

    /// Replacing a file sends its branch, its contents marked as base64 and
    /// the commit's message under GitLab's name.
    #[test]
    fn replacing_a_file_sends_its_contents_as_base64() {
        let replaced = made(
            "update-file",
            vec![
                ("project", text("acme/web")),
                ("path", text("scripts/tidy.py")),
                ("branch", text("ianua/tidy")),
                ("content", text("cHJpbnQoMSkK")),
                ("message", text("Tidy version 2")),
            ],
        )
        .unwrap();

        assert_eq!(
            replaced.body,
            Some(json!({
                "branch": "ianua/tidy",
                "content": "cHJpbnQoMSkK",
                "commit_message": "Tidy version 2",
                "encoding": "base64",
            }))
        );
    }

    /// Deleting `feature/login` names the branch as one part, its slash
    /// escaped as GitLab asks, and sends no body.
    #[test]
    fn deleting_a_branch_names_it_as_one_part() {
        let deleted = made(
            "delete-branch",
            vec![
                ("project", text("acme/web")),
                ("branch", text("feature/login")),
            ],
        )
        .unwrap();

        assert_eq!(
            deleted.url.as_str(),
            "https://gitlab.com/api/v4/projects/acme%2Fweb/repository/branches/feature%2Flogin"
        );
        assert_eq!(deleted.body, None);
    }

    /// Starting a pipeline hands its variables on as they are.
    #[test]
    fn starting_a_pipeline_hands_its_variables_on() {
        let variables = FlowData::list(vec![arguments(vec![
            ("key", text("ENVIRONMENT")),
            ("value", text("staging")),
        ])])
        .unwrap();

        let started = made(
            "run-pipeline",
            vec![
                ("project", text("acme/web")),
                ("ref", text("main")),
                ("variables", variables),
            ],
        )
        .unwrap();

        assert_eq!(
            started.url.as_str(),
            "https://gitlab.com/api/v4/projects/acme%2Fweb/pipeline"
        );
        assert_eq!(
            started.body,
            Some(json!({
                "ref": "main",
                "variables": [{ "key": "ENVIRONMENT", "value": "staging" }]
            }))
        );
    }

    /// Starting a pipeline without a branch or tag fails request construction.
    #[test]
    fn a_pipeline_without_a_ref_builds_no_call() {
        let started = made("run-pipeline", vec![("project", text("acme/web"))]);

        assert!(matches!(started, Err(ActionOutcome::Failed(_))));
    }

    /// Ann opens the project picker: the projects she is a member of are
    /// listed, most recently active first. Choosing acme/web then lists its
    /// labels and its branches, fifty at most, for the other pickers.
    #[test]
    fn pickers_list_projects_then_their_labels_and_branches() {
        let projects = made("list-projects", Vec::new()).unwrap();
        let chosen = || {
            vec![
                ("project", text("acme/web")),
                ("limit", FlowData::number(50.0).unwrap()),
            ]
        };
        let labels = made("list-labels", chosen()).unwrap();
        let branches = made("list-branches", chosen()).unwrap();

        assert_eq!(
            projects.url.as_str(),
            "https://gitlab.com/api/v4/projects?membership=true&order_by=last_activity_at&simple=true"
        );
        assert_eq!(
            labels.url.as_str(),
            "https://gitlab.com/api/v4/projects/acme%2Fweb/labels?per_page=50"
        );
        assert_eq!(
            branches.url.as_str(),
            "https://gitlab.com/api/v4/projects/acme%2Fweb/repository/branches?per_page=50"
        );
    }

    /// Listing branches without a project fails request construction.
    #[test]
    fn listing_branches_needs_a_project() {
        let listed = made("list-branches", Vec::new());

        assert!(listed.is_err());
    }
}
