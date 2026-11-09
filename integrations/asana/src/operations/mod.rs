//! Every operation the Asana integration offers, grouped by topic: tasks,
//! and the workspaces, projects, sections and people they sit among, each
//! described once with the SDK's [`Operation`], with the pickers its forms
//! fill from Asana's own lists.
//!
//! Asana wraps every body in `data`, so each body input is sent under
//! `data.` and each value given back is read under `json.data`.

mod projects;
mod tasks;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The workspaces the account belongs to, picked by their gid.
pub(crate) const WORKSPACES: PickerText = PickerText {
    filled_by: "list-workspaces",
    items_at: "json.data",
    value_at: "gid",
    label_at: "name",
    depends_on: None,
};

/// The chosen workspace's projects, picked by their gid.
pub(crate) const PROJECTS: PickerText = PickerText {
    filled_by: "list-projects",
    items_at: "json.data",
    value_at: "gid",
    label_at: "name",
    depends_on: Some("workspace"),
};

/// Every project the account can reach, for a step that names no
/// workspace.
pub(crate) const ANY_PROJECT: PickerText = PickerText {
    depends_on: None,
    ..PROJECTS
};

/// The chosen project's sections, picked by their gid.
pub(crate) const SECTIONS: PickerText = PickerText {
    filled_by: "list-sections",
    items_at: "json.data",
    value_at: "gid",
    label_at: "name",
    depends_on: Some("project"),
};

/// The people of the chosen workspace, picked by their gid.
pub(crate) const USERS: PickerText = PickerText {
    filled_by: "list-users",
    items_at: "json.data",
    value_at: "gid",
    label_at: "name",
    depends_on: Some("workspace"),
};

/// Everyone the account can see, for a step that names no workspace.
pub(crate) const ANY_USER: PickerText = PickerText {
    depends_on: None,
    ..USERS
};

/// The task an operation acts on, by its gid in the path.
pub(crate) const TASK: Field = Field::required(
    "task",
    Kind::Text,
    Place::Path,
    "The task's gid, such as an earlier step's json.data.gid.",
)
.example("1204567890123456");

/// The workspace an operation acts in, by its gid in the path.
pub(crate) const WORKSPACE: Field =
    Field::required("workspace", Kind::Text, Place::Path, "The workspace's gid.")
        .asked_with(Ask::Picker(WORKSPACES));

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    tasks::OPERATIONS.iter().chain(projects::OPERATIONS)
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
        let wrong = misdescribed(&IntegrationKey::new("asana").unwrap(), all());

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
        let asana = ServiceEndpoint::at("https://app.asana.com/api/1.0/").unwrap();
        call(operation, &asana, &arguments(given))
    }

    /// Creating a task in a workspace wraps its name, notes, assignee,
    /// projects and due date in Asana's `data`.
    #[test]
    fn creating_a_task_wraps_its_values_in_data() {
        let created = made(
            "create-task",
            vec![
                ("workspace", text("1100")),
                ("name", text("Renew the support contract")),
                ("notes", text("The current one ends in December.")),
                ("assignee", text("me")),
                ("projects", FlowData::list(vec![text("2200")]).unwrap()),
                ("due_on", text("2026-11-30")),
            ],
        )
        .unwrap();

        assert_eq!(created.url.as_str(), "https://app.asana.com/api/1.0/tasks");
        assert_eq!(
            created.body,
            Some(json!({ "data": {
                "workspace": "1100",
                "name": "Renew the support contract",
                "notes": "The current one ends in December.",
                "assignee": "me",
                "projects": ["2200"],
                "due_on": "2026-11-30"
            } }))
        );
    }

    /// Completing a task puts it under its gid and marks it completed;
    /// opening it again marks it not completed.
    #[test]
    fn completing_and_reopening_set_the_completed_flag() {
        let completed = made("complete-task", vec![("task", text("3300"))]).unwrap();
        let reopened = made("reopen-task", vec![("task", text("3300"))]).unwrap();

        assert_eq!(
            completed.url.as_str(),
            "https://app.asana.com/api/1.0/tasks/3300"
        );
        assert_eq!(
            completed.body,
            Some(json!({ "data": { "completed": true } }))
        );
        assert_eq!(
            reopened.body,
            Some(json!({ "data": { "completed": false } }))
        );
    }

    /// A comment goes to the task's stories, its text inside `data`.
    #[test]
    fn a_comment_goes_to_the_tasks_stories() {
        let commented = made(
            "comment-on-task",
            vec![
                ("task", text("3300")),
                ("text", text("Signed and sent back.")),
            ],
        )
        .unwrap();

        assert_eq!(
            commented.url.as_str(),
            "https://app.asana.com/api/1.0/tasks/3300/stories"
        );
        assert_eq!(
            commented.body,
            Some(json!({ "data": { "text": "Signed and sent back." } }))
        );
    }

    /// Adding a task to a project names the project and, when given, the
    /// section it goes into.
    #[test]
    fn adding_to_a_project_names_its_section() {
        let added = made(
            "add-task-to-project",
            vec![
                ("task", text("3300")),
                ("project", text("2200")),
                ("section", text("4400")),
            ],
        )
        .unwrap();

        assert_eq!(
            added.url.as_str(),
            "https://app.asana.com/api/1.0/tasks/3300/addProject"
        );
        assert_eq!(
            added.body,
            Some(json!({ "data": { "project": "2200", "section": "4400" } }))
        );
    }

    /// Searching puts its filters in the query under Asana's names, the
    /// projects joined by a comma, and sends no body.
    #[test]
    fn searching_puts_its_filters_in_the_query() {
        let searched = made(
            "search-tasks",
            vec![
                ("workspace", text("1100")),
                ("text", text("contract")),
                ("assignee", text("me")),
                (
                    "projects",
                    FlowData::list(vec![text("2200"), text("2201")]).unwrap(),
                ),
                ("completed", FlowData::bool(false)),
                ("limit", FlowData::number(20.0).unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(
            searched.url.as_str(),
            "https://app.asana.com/api/1.0/workspaces/1100/tasks/search?text=contract&assignee.any=me&projects.any=2200%2C2201&completed=false&limit=20"
        );
        assert_eq!(searched.body, None, "a read sends no body");
    }

    /// Ann opens the workspace picker, then the project picker for the
    /// workspace she chose, then the section picker for the project: each
    /// list asks for a hundred at most, and projects leave archived ones
    /// out.
    #[test]
    fn pickers_list_workspaces_then_projects_then_sections() {
        let workspaces = made("list-workspaces", Vec::new()).unwrap();
        let projects = made("list-projects", vec![("workspace", text("1100"))]).unwrap();
        let sections = made("list-sections", vec![("project", text("2200"))]).unwrap();

        assert_eq!(
            workspaces.url.as_str(),
            "https://app.asana.com/api/1.0/workspaces?limit=100"
        );
        assert_eq!(
            projects.url.as_str(),
            "https://app.asana.com/api/1.0/projects?limit=100&archived=false&workspace=1100"
        );
        assert_eq!(
            sections.url.as_str(),
            "https://app.asana.com/api/1.0/projects/2200/sections?limit=100"
        );
    }

    /// The people picker lists a workspace's people when one is chosen,
    /// and everyone the account can see when none is.
    #[test]
    fn the_people_picker_narrows_to_the_chosen_workspace() {
        let narrowed = made("list-users", vec![("workspace", text("1100"))]).unwrap();
        let everyone = made("list-users", Vec::new()).unwrap();

        assert_eq!(
            narrowed.url.as_str(),
            "https://app.asana.com/api/1.0/users?limit=100&workspace=1100"
        );
        assert_eq!(
            everyone.url.as_str(),
            "https://app.asana.com/api/1.0/users?limit=100"
        );
    }

    /// Deleting a task names it under its gid and sends no body.
    #[test]
    fn deleting_a_task_sends_no_body() {
        let deleted = made("delete-task", vec![("task", text("3300"))]).unwrap();

        assert_eq!(
            deleted.url.as_str(),
            "https://app.asana.com/api/1.0/tasks/3300"
        );
        assert_eq!(deleted.body, None);
    }

    /// Creating a task without a name, listing sections without a project,
    /// a task ID of `..`, and a text search limit each fail request construction.
    #[test]
    fn a_missing_input_a_crooked_task_or_a_wrong_kind_builds_no_call() {
        let unnamed = made("create-task", vec![("workspace", text("1100"))]);
        let without_project = made("list-sections", Vec::new());
        let climbing = made("get-task", vec![("task", text(".."))]);
        let worded = made(
            "search-tasks",
            vec![("workspace", text("1100")), ("limit", text("twenty"))],
        );

        for refused in [unnamed, without_project, climbing, worded] {
            assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
        }
    }
}
