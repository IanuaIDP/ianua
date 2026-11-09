//! Every operation the ClickUp integration offers, grouped by topic: tasks,
//! and the workspaces, spaces, folders, lists and people they sit among,
//! each described once with the SDK's [`Operation`], with the pickers its
//! forms fill from ClickUp's own lists.
//!
//! ClickUp names every space, folder, list and task by its own id alone.
//! So a step on a list asks in the form only for the workspace, space and
//! folder that narrow its pickers, and sends ClickUp the list alone. A list
//! outside any folder is not offered, and is typed by its id.

mod places;
mod tasks;

use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The workspaces the account belongs to, picked by their id.
const WORKSPACES: PickerText = PickerText {
    filled_by: "list-workspaces",
    items_at: "json.teams",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// The chosen workspace's spaces, picked by their id.
pub(crate) const SPACES: PickerText = PickerText {
    filled_by: "list-spaces",
    items_at: "json.spaces",
    value_at: "id",
    label_at: "name",
    depends_on: Some("workspace"),
};

/// The chosen space's folders, picked by their id.
pub(crate) const FOLDERS: PickerText = PickerText {
    filled_by: "list-folders",
    items_at: "json.folders",
    value_at: "id",
    label_at: "name",
    depends_on: Some("space"),
};

/// The chosen folder's lists, picked by their id.
const FOLDER_LISTS: PickerText = PickerText {
    filled_by: "list-lists",
    items_at: "json.lists",
    value_at: "id",
    label_at: "name",
    depends_on: Some("folder"),
};

/// The chosen list's people, picked by their numeric id and shown by
/// username.
pub(crate) const LIST_PEOPLE: PickerText = PickerText {
    filled_by: "list-members",
    items_at: "json.members",
    value_at: "id",
    label_at: "username",
    depends_on: Some("list"),
};

/// The statuses of the chosen list, picked by their name.
pub(crate) const STATUSES: PickerText = PickerText {
    filled_by: "get-list",
    items_at: "json.statuses",
    value_at: "status",
    label_at: "status",
    depends_on: Some("list"),
};

/// The workspace an operation acts in, by its id in the path.
pub(crate) const WORKSPACE: Field = Field::required(
    "workspace",
    Kind::Text,
    Place::Path,
    "The workspace's id, which ClickUp's API calls a team id.",
)
.asked_with(Ask::Picker(WORKSPACES));

/// The workspace whose spaces a picker offers; ClickUp is told only what
/// is picked.
pub(crate) const PICKING_WORKSPACE: Field = Field::optional(
    "workspace",
    Kind::Text,
    Place::Form,
    "The workspace whose spaces the picker offers; ClickUp is told only what is picked.",
)
.asked_with(Ask::Picker(WORKSPACES));

/// The space whose folders a picker offers; ClickUp is told only what is
/// picked.
pub(crate) const PICKING_SPACE: Field = Field::optional(
    "space",
    Kind::Text,
    Place::Form,
    "The space whose folders the picker offers; ClickUp is told only what is picked.",
)
.asked_with(Ask::Picker(SPACES));

/// The folder whose lists a picker offers; ClickUp is told only the list.
pub(crate) const PICKING_FOLDER: Field = Field::optional(
    "folder",
    Kind::Text,
    Place::Form,
    "The folder whose lists the picker offers; ClickUp is told only the list.",
)
.asked_with(Ask::Picker(FOLDERS));

/// The list an operation acts on, by its id in the path.
pub(crate) const LIST: Field = Field::required(
    "list",
    Kind::Text,
    Place::Path,
    "The list's id, such as one list-lists gave back or the number in the list's address.",
)
.example("901234567")
.asked_with(Ask::Picker(FOLDER_LISTS));

/// The task an operation acts on, by its id in the path.
pub(crate) const TASK: Field = Field::required(
    "task",
    Kind::Text,
    Place::Path,
    "The task's id, such as an earlier step's json.id.",
)
.example("86b1x2y3z");

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    tasks::OPERATIONS.iter().chain(places::OPERATIONS)
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
        let wrong = misdescribed(&IntegrationKey::new("clickup").unwrap(), all());

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

    fn number(value: f64) -> FlowData {
        FlowData::number(value).unwrap()
    }

    fn made(key: &str, given: Vec<(&str, FlowData)>) -> Result<Call, ActionOutcome> {
        let operation = all().find(|operation| operation.key == key).unwrap();
        let clickup = ServiceEndpoint::at("https://api.clickup.com/api/v2/").unwrap();
        call(operation, &clickup, &arguments(given))
    }

    /// Creating a task in a list sends its name, Markdown description,
    /// status, priority as a number, tags, people by their numeric ids and
    /// due time.
    #[test]
    fn creating_a_task_sends_its_values_under_clickups_names() {
        let created = made(
            "create-task",
            vec![
                ("list", text("9001")),
                ("name", text("Renew the support contract")),
                ("description", text("The current one ends in **December**.")),
                ("status", text("to do")),
                ("priority", text("2")),
                ("tags", FlowData::list(vec![text("billing")]).unwrap()),
                ("assignees", FlowData::list(vec![number(183.0)]).unwrap()),
                ("due_date", number(1_767_225_600_000.0)),
            ],
        )
        .unwrap();

        assert_eq!(
            created.url.as_str(),
            "https://api.clickup.com/api/v2/list/9001/task"
        );
        assert_eq!(
            created.body,
            Some(json!({
                "name": "Renew the support contract",
                "markdown_content": "The current one ends in **December**.",
                "status": "to do",
                "priority": 2,
                "tags": ["billing"],
                "assignees": [183],
                "due_date": 1_767_225_600_000_u64
            }))
        );
    }

    /// Editing a task adds and takes off people inside ClickUp's
    /// `assignees` object, beside the new name.
    #[test]
    fn editing_a_task_adds_and_removes_people_together() {
        let edited = made(
            "update-task",
            vec![
                ("task", text("86abc")),
                ("name", text("Renew the support contract now")),
                (
                    "add_assignees",
                    FlowData::list(vec![number(183.0)]).unwrap(),
                ),
                (
                    "remove_assignees",
                    FlowData::list(vec![number(204.0)]).unwrap(),
                ),
            ],
        )
        .unwrap();

        assert_eq!(
            edited.url.as_str(),
            "https://api.clickup.com/api/v2/task/86abc"
        );
        assert_eq!(
            edited.body,
            Some(json!({
                "name": "Renew the support contract now",
                "assignees": { "add": [183], "rem": [204] }
            }))
        );
    }

    /// Setting a status puts only the status on the task.
    #[test]
    fn setting_a_status_sends_only_the_status() {
        let moved = made(
            "set-task-status",
            vec![("task", text("86abc")), ("status", text("in progress"))],
        )
        .unwrap();

        assert_eq!(
            moved.url.as_str(),
            "https://api.clickup.com/api/v2/task/86abc"
        );
        assert_eq!(moved.body, Some(json!({ "status": "in progress" })));
    }

    /// A comment goes to the task's comments as `comment_text`, assigned
    /// to a person by number, never asking ClickUp to notify the author
    /// too.
    #[test]
    fn a_comment_goes_to_the_tasks_comments() {
        let commented = made(
            "comment-on-task",
            vec![
                ("task", text("86abc")),
                ("text", text("Signed and sent back.")),
                ("assignee", text("183")),
            ],
        )
        .unwrap();

        assert_eq!(
            commented.url.as_str(),
            "https://api.clickup.com/api/v2/task/86abc/comment"
        );
        assert_eq!(
            commented.body,
            Some(json!({
                "comment_text": "Signed and sent back.",
                "assignee": 183,
                "notify_all": false
            }))
        );
    }

    /// A tag is named in the path, escaped like every other part.
    #[test]
    fn a_tag_is_named_in_the_path() {
        let tagged = made(
            "add-tag-to-task",
            vec![("task", text("86abc")), ("tag", text("needs review"))],
        )
        .unwrap();

        assert_eq!(
            tagged.url.as_str(),
            "https://api.clickup.com/api/v2/task/86abc/tag/needs%20review"
        );
    }

    /// Reading a task asks for its description in Markdown and sends no
    /// body; deleting one sends no body either.
    #[test]
    fn reading_and_deleting_a_task_send_no_body() {
        let read = made("get-task", vec![("task", text("86abc"))]).unwrap();
        let deleted = made("delete-task", vec![("task", text("86abc"))]).unwrap();

        assert_eq!(
            read.url.as_str(),
            "https://api.clickup.com/api/v2/task/86abc?include_markdown_description=true"
        );
        assert_eq!(read.body, None);
        assert_eq!(
            deleted.url.as_str(),
            "https://api.clickup.com/api/v2/task/86abc"
        );
        assert_eq!(deleted.body, None);
    }

    /// Ann opens the workspace picker, then lists the spaces, folders and
    /// lists below the one she chose, leaving archived ones out.
    #[test]
    fn listing_goes_from_workspaces_down_to_lists() {
        let workspaces = made("list-workspaces", Vec::new()).unwrap();
        let spaces = made("list-spaces", vec![("workspace", text("1100"))]).unwrap();
        let folders = made("list-folders", vec![("space", text("790"))]).unwrap();
        let lists = made("list-lists", vec![("folder", text("457"))]).unwrap();
        let loose = made("list-folderless-lists", vec![("space", text("790"))]).unwrap();

        assert_eq!(
            workspaces.url.as_str(),
            "https://api.clickup.com/api/v2/team"
        );
        assert_eq!(
            spaces.url.as_str(),
            "https://api.clickup.com/api/v2/team/1100/space?archived=false"
        );
        assert_eq!(
            folders.url.as_str(),
            "https://api.clickup.com/api/v2/space/790/folder?archived=false"
        );
        assert_eq!(
            lists.url.as_str(),
            "https://api.clickup.com/api/v2/folder/457/list?archived=false"
        );
        assert_eq!(
            loose.url.as_str(),
            "https://api.clickup.com/api/v2/space/790/list?archived=false"
        );
    }

    /// The status picker on a new task reads the chosen list, and its
    /// people are listed from the same list.
    #[test]
    fn a_lists_statuses_and_people_are_read_from_the_list() {
        let statuses = made("get-list", vec![("list", text("9001"))]).unwrap();
        let people = made("list-members", vec![("list", text("9001"))]).unwrap();

        assert_eq!(
            statuses.url.as_str(),
            "https://api.clickup.com/api/v2/list/9001"
        );
        assert_eq!(
            people.url.as_str(),
            "https://api.clickup.com/api/v2/list/9001/member"
        );
    }

    /// Creating a task without a name, listing spaces without a workspace,
    /// a task ID of `..`, and a nonnumeric priority each fail request construction.
    #[test]
    fn a_missing_input_a_crooked_task_or_a_wrong_kind_builds_no_call() {
        let unnamed = made("create-task", vec![("list", text("9001"))]);
        let without_workspace = made("list-spaces", Vec::new());
        let climbing = made("get-task", vec![("task", text(".."))]);
        let worded = made(
            "update-task",
            vec![("task", text("86abc")), ("priority", text("high"))],
        );

        for refused in [unnamed, without_workspace, climbing, worded] {
            assert!(matches!(refused, Err(ActionOutcome::Failed(_))));
        }
    }
}
