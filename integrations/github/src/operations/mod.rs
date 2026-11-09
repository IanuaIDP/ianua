//! Every operation the GitHub integration offers, grouped by topic: issues,
//! pull requests and repositories, each described once with the SDK's
//! [`Operation`], with the pickers its forms fill from GitHub's own lists.

mod issues;
mod pull_requests;
mod repositories;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The repositories the account can reach, picked by their owner/name.
const REPOSITORIES: PickerText = PickerText {
    filled_by: "list-repositories",
    items_at: "json",
    value_at: "full_name",
    label_at: "full_name",
    depends_on: None,
};

/// The chosen repository's labels, picked by name.
pub(crate) const LABELS: PickerText = PickerText {
    filled_by: "list-labels",
    items_at: "json",
    value_at: "name",
    label_at: "name",
    depends_on: Some("repository"),
};

/// The chosen repository's branches, picked by name.
pub(crate) const BRANCHES: PickerText = PickerText {
    filled_by: "list-branches",
    items_at: "json",
    value_at: "name",
    label_at: "name",
    depends_on: Some("repository"),
};

/// The repository every operation acts in.
pub(crate) const REPOSITORY: Field = Field::required(
    "repository",
    Kind::Text,
    Place::Path,
    "The repository, written as owner/name, such as acme/web.",
)
.asked_with(Ask::Picker(REPOSITORIES))
.example("acme/web");

/// The number of an issue or pull request in the path.
pub(crate) const ISSUE: Field = Field::required(
    "issue",
    Kind::Count,
    Place::Path,
    "The number of the issue or pull request, such as an earlier step's json.number.",
);

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    issues::OPERATIONS
        .iter()
        .chain(pull_requests::OPERATIONS)
        .chain(repositories::OPERATIONS)
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
    /// explained, every path input placed, no body on a read, something
    /// given back.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("github").unwrap(), all());

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
        let github = ServiceEndpoint::at("https://api.github.com/").unwrap();
        call(operation, &github, &arguments(given))
    }

    /// Closing issue 7 patches it with the state and the reason, under its
    /// number.
    #[test]
    fn closing_an_issue_sends_its_state_and_reason() {
        let closed = made(
            "close-issue",
            vec![
                ("repository", text("acme/web")),
                ("issue", FlowData::number(7.0).unwrap()),
                ("reason", text("not_planned")),
            ],
        )
        .unwrap();

        assert_eq!(
            closed.url.as_str(),
            "https://api.github.com/repos/acme/web/issues/7"
        );
        assert_eq!(
            closed.body,
            Some(json!({ "state_reason": "not_planned", "state": "closed" }))
        );
    }

    /// Listing open issues with two labels puts them in the query, the
    /// labels joined by a comma and the limit under GitHub's name.
    #[test]
    fn listing_issues_puts_its_filters_in_the_query() {
        let listed = made(
            "list-issues",
            vec![
                ("repository", text("acme/web")),
                ("state", text("open")),
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
            "https://api.github.com/repos/acme/web/issues?state=open&labels=bug%2Curgent&per_page=50"
        );
        assert_eq!(listed.body, None, "a read sends no body");
    }

    /// Reading a file keeps its folders as parts of the path, and the ref
    /// goes in the query.
    #[test]
    fn reading_a_file_keeps_its_folders() {
        let read = made(
            "get-file",
            vec![
                ("repository", text("acme/web")),
                ("path", text("docs/README.md")),
                ("ref", text("v1.4.0")),
            ],
        )
        .unwrap();

        assert_eq!(
            read.url.as_str(),
            "https://api.github.com/repos/acme/web/contents/docs/README.md?ref=v1.4.0"
        );
    }

    /// Ann opens the repository picker: the account's repositories are
    /// listed most recently changed first. Choosing acme/web then lists its
    /// labels, fifty at most, for the labels picker.
    #[test]
    fn pickers_list_repositories_then_their_labels() {
        let repositories = made("list-repositories", Vec::new()).unwrap();
        let labels = made(
            "list-labels",
            vec![
                ("repository", text("acme/web")),
                ("limit", FlowData::number(50.0).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            repositories.url.as_str(),
            "https://api.github.com/user/repos?sort=updated"
        );
        assert_eq!(
            labels.url.as_str(),
            "https://api.github.com/repos/acme/web/labels?per_page=50"
        );
        assert_eq!(labels.body, None, "a read sends no body");
    }

    /// Listing branches without a repository fails request construction.
    #[test]
    fn listing_branches_needs_a_repository() {
        let listed = made("list-branches", Vec::new());

        assert!(listed.is_err());
    }

    /// Deleting `feature/login` names the branch with its slash, under the
    /// branch heads, and sends no body.
    #[test]
    fn deleting_a_branch_names_it_whole() {
        let deleted = made(
            "delete-branch",
            vec![
                ("repository", text("acme/web")),
                ("branch", text("feature/login")),
            ],
        )
        .unwrap();

        assert_eq!(
            deleted.url.as_str(),
            "https://api.github.com/repos/acme/web/git/refs/heads/feature/login"
        );
        assert_eq!(deleted.body, None);
    }

    /// Starting a workflow hands its named inputs on as they are, asking
    /// for the run's details.
    #[test]
    fn starting_a_workflow_hands_its_inputs_on() {
        let inputs = arguments(vec![("environment", text("staging"))]);

        let started = made(
            "run-workflow",
            vec![
                ("repository", text("acme/web")),
                ("workflow", text("deploy.yml")),
                ("ref", text("main")),
                ("inputs", inputs),
            ],
        )
        .unwrap();

        assert_eq!(
            started.url.as_str(),
            "https://api.github.com/repos/acme/web/actions/workflows/deploy.yml/dispatches"
        );
        assert_eq!(
            started.body,
            Some(json!({
                "ref": "main",
                "inputs": { "environment": "staging" },
                "return_run_details": true
            }))
        );
    }

    /// Reading the commit `feature/login` points to names the branch whole
    /// under the repository's commits.
    #[test]
    fn reading_a_commit_names_its_branch_whole() {
        let read = made(
            "get-commit",
            vec![
                ("repository", text("acme/web")),
                ("ref", text("feature/login")),
            ],
        )
        .unwrap();

        assert_eq!(
            read.url.as_str(),
            "https://api.github.com/repos/acme/web/commits/feature/login"
        );
    }

    /// Replacing `scripts/tidy.py` on `ianua/tidy` sends the message, the
    /// contents, the branch and the version it replaces under GitHub's
    /// name.
    #[test]
    fn writing_a_file_sends_the_version_it_replaces() {
        let written = made(
            "put-file",
            vec![
                ("repository", text("acme/web")),
                ("path", text("scripts/tidy.py")),
                ("message", text("Tidy version 2")),
                ("content", text("cHJpbnQoMSkK")),
                ("branch", text("ianua/tidy")),
                ("replaces", text("3d21ec53a331a6f037a91c368710b99387d012c1")),
            ],
        )
        .unwrap();

        assert_eq!(
            written.url.as_str(),
            "https://api.github.com/repos/acme/web/contents/scripts/tidy.py"
        );
        assert_eq!(
            written.body,
            Some(json!({
                "message": "Tidy version 2",
                "content": "cHJpbnQoMSkK",
                "branch": "ianua/tidy",
                "sha": "3d21ec53a331a6f037a91c368710b99387d012c1",
            }))
        );
    }

    /// Opening a draft pull request sends the flag as true or false.
    #[test]
    fn a_draft_pull_request_sends_its_flag() {
        let opened = made(
            "create-pull-request",
            vec![
                ("repository", text("acme/web")),
                ("title", text("Fix login")),
                ("head", text("fix-login")),
                ("base", text("main")),
                ("draft", FlowData::bool(true)),
            ],
        )
        .unwrap();

        assert_eq!(
            opened.body,
            Some(
                json!({ "title": "Fix login", "head": "fix-login", "base": "main", "draft": true })
            )
        );
    }

    /// A missing issue title, a file path containing parent traversal, and
    /// a text issue number each fail request construction.
    #[test]
    fn a_missing_input_a_crooked_path_or_a_wrong_kind_builds_no_call() {
        let without_title = made("create-issue", vec![("repository", text("acme/web"))]);
        let climbing = made(
            "get-file",
            vec![
                ("repository", text("acme/web")),
                ("path", text("../../etc/passwd")),
            ],
        );
        let worded = made(
            "get-issue",
            vec![("repository", text("acme/web")), ("issue", text("seven"))],
        );

        for refused in [without_title, climbing, worded] {
            assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
        }
    }
}
