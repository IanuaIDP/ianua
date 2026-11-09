//! Cards: reading one, creating, changing, moving, archiving and deleting
//! one, commenting on it and labelling it.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{BOARDS, CARD, LABELS, LISTS, MEMBERS, ONE_CARD, PICKING_BOARD};

/// What changing one card gives back.
const CARD_OUTPUTS: &[(&str, &str)] = &[
    ("json.id", "The card's id."),
    ("json.name", "The card's name."),
    ("json.idList", "The id of the list the card is on."),
    ("json.closed", "Whether the card is archived."),
    ("json.url", "The address of the card's page."),
    ("status", "The status Trello answered with."),
];

/// Where a card sits in its list.
const POSITION: Field = Field::optional(
    "position",
    Kind::Text,
    Place::Query,
    "Where the card sits in its list: top or bottom.",
)
.sent_as("pos")
.asked_with(Ask::Choices(&[
    ChoiceText {
        value: "top",
        label: "Top",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "bottom",
        label: "Bottom",
        tone: Tone::Neutral,
    },
]))
.more_options();

/// A card's description.
const DESCRIPTION: Field = Field::optional(
    "description",
    Kind::Text,
    Place::Query,
    "The card's description, in Markdown.",
)
.sent_as("desc")
.asked_with(Ask::LongText);

/// When a card is due.
const DUE: Field = Field::optional(
    "due",
    Kind::Text,
    Place::Query,
    "When the card is due, as a date and time such as 2026-11-30T17:00:00Z.",
)
.asked_with(Ask::DateTime);

/// Every card operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "get-card",
        title: "Get a card",
        description: "Reads one card: its name, description, list, labels, members and due date.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_CARD,
        fields: &[CARD],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.name", "The card's name."),
            ("json.desc", "The card's description."),
            ("json.idList", "The id of the list the card is on."),
            ("json.idBoard", "The id of the board the card is on."),
            ("json.labels", "The labels on the card."),
            ("json.idMembers", "The ids of the card's members."),
            ("json.due", "When the card is due, if it has a due date."),
            ("json.closed", "Whether the card is archived."),
            ("json.url", "The address of the card's page."),
            ("status", "The status Trello answered with."),
        ],
    },
    Operation {
        key: "create-card",
        title: "Create a card",
        description: "Creates a card on a list, as the account's member.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("cards")],
        fields: &[
            PICKING_BOARD,
            Field::required(
                "list",
                Kind::Text,
                Place::Query,
                "The id of the list the card goes on, such as one list-lists gives.",
            )
            .sent_as("idList")
            .asked_with(Ask::Picker(LISTS)),
            Field::required("name", Kind::Text, Place::Query, "The card's name.")
                .example("Call the supplier"),
            DESCRIPTION,
            DUE,
            POSITION,
            Field::optional(
                "labels",
                Kind::TextList,
                Place::Query,
                "The ids of labels to put on the card, such as list-labels gives.",
            )
            .sent_as("idLabels")
            .asked_with(Ask::MultiPicker(LABELS))
            .more_options(),
            Field::optional(
                "members",
                Kind::TextList,
                Place::Query,
                "The ids of members to add to the card, such as list-members gives.",
            )
            .sent_as("idMembers")
            .asked_with(Ask::MultiPicker(MEMBERS))
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.id",
                "The new card's id, which later steps on the card name.",
            ),
            ("json.shortUrl", "A short address of the card's page."),
            ("json.url", "The address of the card's page."),
            (
                "status",
                "The status Trello answered with, 200 when the card was created.",
            ),
        ],
    },
    Operation {
        key: "update-card",
        title: "Edit a card",
        description: "Changes a card's name, description or due date; what is not given stays as it was.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_CARD,
        fields: &[
            CARD,
            Field::optional("name", Kind::Text, Place::Query, "The card's new name."),
            DESCRIPTION,
            DUE,
            Field::optional(
                "due_complete",
                Kind::Flag,
                Place::Query,
                "Whether the due date is marked done.",
            )
            .sent_as("dueComplete"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: CARD_OUTPUTS,
    },
    Operation {
        key: "move-card",
        title: "Move a card",
        description: "Moves a card to another list, on the same board or another one.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_CARD,
        fields: &[
            CARD,
            Field::required(
                "board",
                Kind::Text,
                Place::Query,
                "The id of the board the list is on, such as one list-boards gives.",
            )
            .sent_as("idBoard")
            .asked_with(Ask::Picker(BOARDS)),
            Field::required(
                "list",
                Kind::Text,
                Place::Query,
                "The id of the list the card moves to.",
            )
            .sent_as("idList")
            .asked_with(Ask::Picker(LISTS)),
            POSITION,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: CARD_OUTPUTS,
    },
    Operation {
        key: "archive-card",
        title: "Archive a card",
        description: "Archives a card: it leaves its list, and can be brought back from the board's archive.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE_CARD,
        fields: &[CARD],
        fixed: &[],
        query: &[("closed", "true")],
        shape: Shape::Object,
        outputs: CARD_OUTPUTS,
    },
    Operation {
        key: "delete-card",
        title: "Delete a card",
        description: "Deletes a card for good, with its comments and attachments; it cannot be brought back.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE_CARD,
        fields: &[CARD],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Trello answered with, 200 when the card was deleted.",
        )],
    },
    Operation {
        key: "comment-on-card",
        title: "Comment on a card",
        description: "Adds a comment to a card, which notifies the card's members and watchers.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("cards"),
            Segment::Input("card"),
            Segment::Fixed("actions"),
            Segment::Fixed("comments"),
        ],
        fields: &[
            CARD,
            Field::required(
                "text",
                Kind::Text,
                Place::Query,
                "The comment's text, in Markdown.",
            )
            .asked_with(Ask::LongText),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The comment's id."),
            ("json.date", "When the comment was added."),
            (
                "status",
                "The status Trello answered with, 200 when the comment was added.",
            ),
        ],
    },
    Operation {
        key: "add-label",
        title: "Add a label",
        description: "Puts a label of the card's board on a card, keeping those it has.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("cards"),
            Segment::Input("card"),
            Segment::Fixed("idLabels"),
        ],
        fields: &[
            CARD,
            PICKING_BOARD,
            Field::required(
                "label",
                Kind::Text,
                Place::Query,
                "The label's id, such as one list-labels gives.",
            )
            .sent_as("value")
            .asked_with(Ask::Picker(LABELS)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json", "The ids of every label the card now carries."),
            ("status", "The status Trello answered with."),
        ],
    },
];
