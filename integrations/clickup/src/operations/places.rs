//! Where tasks sit: listing workspaces, their spaces, the folders and
//! lists in a space, the lists of a folder, and the people of a list, and
//! reading one list with its statuses, which the pickers and later steps
//! read.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{
    FOLDERS, LIST, PICKING_FOLDER, PICKING_SPACE, PICKING_WORKSPACE, SPACES, WORKSPACE,
};

/// Leaves archived ones out of a list, as ClickUp does when not asked.
const UNARCHIVED: (&str, &str) = ("archived", "false");

/// The space a list is read from, by its id in the path.
const SPACE: Field = Field::required(
    "space",
    Kind::Text,
    Place::Path,
    "The space's id, such as one list-spaces gave back.",
)
.example("790")
.asked_with(Ask::Picker(SPACES));

/// What listing lists gives back.
const LISTS: &[(&str, &str)] = &[
    ("json.lists", "The lists, each with its id and name."),
    ("status", "The status ClickUp answered with."),
];

/// Every operation on where tasks sit.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-workspaces",
        title: "List workspaces",
        description: "Lists the workspaces the account belongs to, which ClickUp's API calls teams.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("team")],
        fields: &[],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.teams",
                "The workspaces, each with its id, name and people.",
            ),
            ("status", "The status ClickUp answered with."),
        ],
    },
    Operation {
        key: "list-spaces",
        title: "List spaces",
        description: "Lists the spaces of a workspace that are not archived.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("team"),
            Segment::Input("workspace"),
            Segment::Fixed("space"),
        ],
        fields: &[WORKSPACE],
        fixed: &[],
        query: &[UNARCHIVED],
        shape: Shape::Object,
        outputs: &[
            ("json.spaces", "The spaces, each with its id and name."),
            ("status", "The status ClickUp answered with."),
        ],
    },
    Operation {
        key: "list-folders",
        title: "List folders",
        description: "Lists the folders of a space that are not archived.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("space"),
            Segment::Input("space"),
            Segment::Fixed("folder"),
        ],
        fields: &[PICKING_WORKSPACE, SPACE],
        fixed: &[],
        query: &[UNARCHIVED],
        shape: Shape::Object,
        outputs: &[
            (
                "json.folders",
                "The folders, each with its id, name and lists.",
            ),
            ("status", "The status ClickUp answered with."),
        ],
    },
    Operation {
        key: "list-lists",
        title: "List lists",
        description: "Lists the lists of a folder that are not archived.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("folder"),
            Segment::Input("folder"),
            Segment::Fixed("list"),
        ],
        fields: &[
            PICKING_WORKSPACE,
            PICKING_SPACE,
            Field::required(
                "folder",
                Kind::Text,
                Place::Path,
                "The folder's id, such as one list-folders gave back.",
            )
            .example("457")
            .asked_with(Ask::Picker(FOLDERS)),
        ],
        fixed: &[],
        query: &[UNARCHIVED],
        shape: Shape::Object,
        outputs: LISTS,
    },
    Operation {
        key: "list-folderless-lists",
        title: "List lists outside folders",
        description: "Lists the lists that sit in a space outside any folder and are not archived.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("space"),
            Segment::Input("space"),
            Segment::Fixed("list"),
        ],
        fields: &[PICKING_WORKSPACE, SPACE],
        fixed: &[],
        query: &[UNARCHIVED],
        shape: Shape::Object,
        outputs: LISTS,
    },
    Operation {
        key: "get-list",
        title: "Get a list",
        description: "Reads one list: its name, where it sits, and the statuses its tasks move through.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("list"), Segment::Input("list")],
        fields: &[PICKING_WORKSPACE, PICKING_SPACE, PICKING_FOLDER, LIST],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.name", "The list's name."),
            ("json.folder", "The folder the list is in."),
            ("json.space", "The space the list is in."),
            (
                "json.statuses",
                "The statuses its tasks move through, each by its name in status.",
            ),
            ("status", "The status ClickUp answered with."),
        ],
    },
    Operation {
        key: "list-members",
        title: "List people of a list",
        description: "Lists the people who can see a list, each with the numeric id a task is assigned by.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("list"),
            Segment::Input("list"),
            Segment::Fixed("member"),
        ],
        fields: &[PICKING_WORKSPACE, PICKING_SPACE, PICKING_FOLDER, LIST],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.members",
                "The people, each with their numeric id, username and email.",
            ),
            ("status", "The status ClickUp answered with."),
        ],
    },
];
