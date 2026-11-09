//! Messages and threads: searching and reading them, sending mail as the
//! account, labelling a message, and moving it to the trash.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{LABELS, LIMIT, SEARCH};

/// The message a step acts on, in the path.
const MESSAGE: Field = Field::required(
    "message",
    Kind::Text,
    Place::Path,
    "The message's id, such as an earlier step's json.messages.0.id.",
);

/// The thread a step reads, in the path.
const THREAD: Field = Field::required(
    "thread",
    Kind::Text,
    Place::Path,
    "The thread's id, such as an earlier step's json.threadId.",
);

/// The headers a read gives back with a message's snippet.
const HEADERS: &[(&str, &str)] = &[
    ("format", "metadata"),
    ("metadataHeaders", "From"),
    ("metadataHeaders", "To"),
    ("metadataHeaders", "Subject"),
    ("metadataHeaders", "Date"),
];

/// Every message operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "search-messages",
        title: "Search messages",
        description: "Finds messages in the mailbox with Gmail's own search words, newest first.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("me"),
            Segment::Fixed("messages"),
        ],
        fields: &[SEARCH, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.messages",
                "The messages found, each with its id and threadId.",
            ),
            (
                "json.resultSizeEstimate",
                "About how many messages match.",
            ),
            ("status", "The status Gmail answered with."),
        ],
    },
    Operation {
        key: "get-message",
        title: "Read a message",
        description: "Reads one message's sender, recipients, subject, date and a snippet of its text, with its labels.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("me"),
            Segment::Fixed("messages"),
            Segment::Input("message"),
        ],
        fields: &[MESSAGE],
        fixed: &[],
        query: HEADERS,
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The message's id."),
            ("json.threadId", "The thread it is in."),
            ("json.snippet", "The start of its text."),
            ("json.labelIds", "The labels it carries."),
            (
                "json.payload.headers",
                "Its From, To, Subject and Date headers, each with a name and value.",
            ),
            ("status", "The status Gmail answered with; 404 when there is no such message."),
        ],
    },
    Operation {
        key: "send-message",
        title: "Send an email",
        description: "Sends a plain-text email from the account's own address, as the account.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("me"),
            Segment::Fixed("messages"),
            Segment::Fixed("send"),
        ],
        fields: &[
            Field::required(
                "to",
                Kind::TextList,
                Place::Body,
                "Who it goes to: a list of addresses.",
            )
            .sent_as("To"),
            Field::optional("cc", Kind::TextList, Place::Body, "Who is copied in.")
                .sent_as("Cc")
                .more_options(),
            Field::optional(
                "bcc",
                Kind::TextList,
                Place::Body,
                "Who is copied in unseen by the others.",
            )
            .sent_as("Bcc")
            .more_options(),
            Field::required("subject", Kind::Text, Place::Body, "The subject line.")
                .sent_as("Subject"),
            Field::required("text", Kind::Text, Place::Body, "The email's text.")
                .asked_with(Ask::LongText),
            Field::optional(
                "thread",
                Kind::Text,
                Place::Body,
                "The thread it is sent in, such as an earlier step's json.threadId; a new thread when not given.",
            )
            .sent_as("threadId")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Mail,
        outputs: &[
            ("json.id", "The sent message's id."),
            ("json.threadId", "The thread it is in."),
            ("status", "The status Gmail answered with."),
        ],
    },
    Operation {
        key: "change-labels",
        title: "Change a message's labels",
        description: "Adds labels to a message and takes others off it, such as UNREAD to mark it read.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("me"),
            Segment::Fixed("messages"),
            Segment::Input("message"),
            Segment::Fixed("modify"),
        ],
        fields: &[
            MESSAGE,
            Field::optional(
                "add",
                Kind::TextList,
                Place::Body,
                "The labels to add, by id, such as STARRED or a label of the account's own.",
            )
            .sent_as("addLabelIds")
            .asked_with(Ask::Picker(LABELS)),
            Field::optional(
                "remove",
                Kind::TextList,
                Place::Body,
                "The labels to take off, by id, such as UNREAD or INBOX.",
            )
            .sent_as("removeLabelIds")
            .asked_with(Ask::Picker(LABELS)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.labelIds", "The labels it carries now."),
            ("status", "The status Gmail answered with."),
        ],
    },
    Operation {
        key: "trash-message",
        title: "Move a message to the trash",
        description: "Moves a message to the trash, where it can be taken back for 30 days before Gmail deletes it.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("me"),
            Segment::Fixed("messages"),
            Segment::Input("message"),
            Segment::Fixed("trash"),
        ],
        fields: &[MESSAGE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.labelIds", "The labels it carries now, TRASH among them."),
            ("status", "The status Gmail answered with."),
        ],
    },
    Operation {
        key: "search-threads",
        title: "Search conversations",
        description: "Finds conversations in the mailbox with Gmail's own search words, newest first.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("me"),
            Segment::Fixed("threads"),
        ],
        fields: &[SEARCH, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.threads",
                "The conversations found, each with its id and a snippet.",
            ),
            ("status", "The status Gmail answered with."),
        ],
    },
    Operation {
        key: "get-thread",
        title: "Read a conversation",
        description: "Reads every message of a conversation: each one's headers and a snippet of its text.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("users"),
            Segment::Fixed("me"),
            Segment::Fixed("threads"),
            Segment::Input("thread"),
        ],
        fields: &[THREAD],
        fixed: &[],
        query: HEADERS,
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The conversation's id."),
            (
                "json.messages",
                "Its messages, oldest first, each with its id, snippet and headers.",
            ),
            ("status", "The status Gmail answered with; 404 when there is no such conversation."),
        ],
    },
];
