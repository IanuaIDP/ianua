//! Boards and what is on them: the member's boards, and a board's lists,
//! labels and members, which also fill the forms' pickers.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::BOARD;

/// Every board operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-boards",
        title: "List boards",
        description: "Lists the open boards the account's member belongs to.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("members"),
            Segment::Fixed("me"),
            Segment::Fixed("boards"),
        ],
        fields: &[],
        fixed: &[],
        query: &[("filter", "open")],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The boards, each with its id, name, url and shortLink.",
            ),
            ("status", "The status Trello answered with."),
        ],
    },
    Operation {
        key: "list-lists",
        title: "List lists",
        description: "Lists the open lists on a board, in the order they are shown.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("boards"),
            Segment::Input("board"),
            Segment::Fixed("lists"),
        ],
        fields: &[BOARD],
        fixed: &[],
        query: &[("filter", "open")],
        shape: Shape::Object,
        outputs: &[
            ("json", "The lists, each with its id, name and pos."),
            ("status", "The status Trello answered with."),
        ],
    },
    Operation {
        key: "list-labels",
        title: "List labels",
        description: "Lists the labels cards on a board can carry.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("boards"),
            Segment::Input("board"),
            Segment::Fixed("labels"),
        ],
        fields: &[
            BOARD,
            Field::optional(
                "limit",
                Kind::Count,
                Place::Query,
                "How many to list, at most 1000; 50 when not given.",
            )
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json", "The labels, each with its id, name and color."),
            ("status", "The status Trello answered with."),
        ],
    },
    Operation {
        key: "list-members",
        title: "List members",
        description: "Lists the people who are members of a board.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("boards"),
            Segment::Input("board"),
            Segment::Fixed("members"),
        ],
        fields: &[BOARD],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json",
                "The members, each with its id, fullName and username.",
            ),
            ("status", "The status Trello answered with."),
        ],
    },
];
