//! Work items: creating, reading, editing and deleting one, commenting on
//! one, and finding them with a WIQL query.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{API_VERSION, PROJECT};

/// The work item a step acts on, in the path.
const WORK_ITEM: Field = Field::required(
    "id",
    Kind::Count,
    Place::Path,
    "The work item's number, such as an earlier step's json.id.",
);

/// The path of one work item.
const ONE_ITEM: &[Segment] = &[
    Segment::Input("project"),
    Segment::Fixed("_apis"),
    Segment::Fixed("wit"),
    Segment::Fixed("workitems"),
    Segment::Input("id"),
];

/// What reading or changing a work item gives back.
const ITEM_OUTPUTS: &[(&str, &str)] = &[
    ("json.id", "The work item's number, which later steps name."),
    ("json.rev", "Its revision, counting its changes."),
    (
        "json.fields",
        "Its fields, such as System.Title and System.State.",
    ),
    (
        "json._links.html.href",
        "The address of the work item's page.",
    ),
];

/// A field set in a work item's JSON Patch body.
const fn field_of(name: &'static str, path: &'static str, meaning: &'static str) -> Field {
    Field::optional(name, Kind::Text, Place::Body, meaning).sent_as(path)
}

/// Every work item operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "create-work-item",
        title: "Create a work item",
        description: "Creates a work item of a type the project has, such as Bug, Task or User Story.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Input("project"),
            Segment::Fixed("_apis"),
            Segment::Fixed("wit"),
            Segment::Fixed("workitems"),
            Segment::Prefixed {
                prefix: "$",
                input: "type",
            },
        ],
        fields: &[
            PROJECT,
            Field::required(
                "type",
                Kind::Text,
                Place::Path,
                "The work item type, such as Bug or Task.",
            ),
            Field::required("title", Kind::Text, Place::Body, "The work item's title.")
                .sent_as("/fields/System.Title"),
            field_of(
                "description",
                "/fields/System.Description",
                "The work item's description, as HTML or plain text.",
            ),
            field_of(
                "assigned_to",
                "/fields/System.AssignedTo",
                "Who it is assigned to, by their email address.",
            ),
            field_of(
                "tags",
                "/fields/System.Tags",
                "Tags, separated by semicolons, such as ci; urgent.",
            ),
            field_of(
                "area",
                "/fields/System.AreaPath",
                "The area path, such as Web\\Login.",
            ),
            field_of(
                "iteration",
                "/fields/System.IterationPath",
                "The iteration path, such as Web\\Sprint 12.",
            ),
        ],
        fixed: &[],
        query: API_VERSION,
        shape: Shape::JsonPatch,
        outputs: ITEM_OUTPUTS,
    },
    Operation {
        key: "get-work-item",
        title: "Get a work item",
        description: "Reads one work item and its fields.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_ITEM,
        fields: &[PROJECT, WORK_ITEM],
        fixed: &[],
        query: API_VERSION,
        shape: Shape::Object,
        outputs: ITEM_OUTPUTS,
    },
    Operation {
        key: "update-work-item",
        title: "Edit a work item",
        description: "Changes a work item's title, description, state, assignee or tags; what is not given stays as it was.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: ONE_ITEM,
        fields: &[
            PROJECT,
            WORK_ITEM,
            field_of(
                "title",
                "/fields/System.Title",
                "The work item's new title.",
            ),
            field_of(
                "description",
                "/fields/System.Description",
                "Its new description.",
            ),
            field_of(
                "state",
                "/fields/System.State",
                "Its new state, such as Active or Closed, as its type allows.",
            ),
            field_of(
                "assigned_to",
                "/fields/System.AssignedTo",
                "Who it is assigned to from now on, by their email address.",
            ),
            field_of(
                "tags",
                "/fields/System.Tags",
                "Its tags from now on, separated by semicolons.",
            ),
        ],
        fixed: &[],
        query: API_VERSION,
        shape: Shape::JsonPatch,
        outputs: ITEM_OUTPUTS,
    },
    Operation {
        key: "comment-on-work-item",
        title: "Comment on a work item",
        description: "Adds a comment to a work item's discussion, which notifies those following it.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[
            Segment::Input("project"),
            Segment::Fixed("_apis"),
            Segment::Fixed("wit"),
            Segment::Fixed("workItems"),
            Segment::Input("id"),
            Segment::Fixed("comments"),
        ],
        fields: &[
            PROJECT,
            WORK_ITEM,
            Field::required(
                "text",
                Kind::Text,
                Place::Body,
                "The comment, as HTML or plain text.",
            ),
        ],
        fixed: &[],
        query: &[("api-version", "7.1-preview.4")],
        shape: Shape::Object,
        outputs: &[("json.id", "The comment's id.")],
    },
    Operation {
        key: "query-work-items",
        title: "Find work items",
        description: "Finds work items with a WIQL query, such as SELECT [System.Id] FROM WorkItems WHERE [System.State] = 'Active'.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: &[
            Segment::Input("project"),
            Segment::Fixed("_apis"),
            Segment::Fixed("wit"),
            Segment::Fixed("wiql"),
        ],
        fields: &[
            PROJECT,
            Field::required("query", Kind::Text, Place::Body, "The WIQL query."),
        ],
        fixed: &[],
        query: API_VERSION,
        shape: Shape::Object,
        outputs: &[(
            "json.workItems",
            "The work items found, each with its id and address.",
        )],
    },
    Operation {
        key: "delete-work-item",
        title: "Delete a work item",
        description: "Deletes a work item, moving it to the project's recycle bin.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE_ITEM,
        fields: &[PROJECT, WORK_ITEM],
        fixed: &[],
        query: API_VERSION,
        shape: Shape::Object,
        outputs: &[("json.id", "The deleted work item's number.")],
    },
];
