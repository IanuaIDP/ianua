//! Data sources, blocks, comments and people: querying a database's data
//! source, reading and adding a page's blocks, commenting on a page, and
//! listing the workspace's people.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{data_source, limit};

/// The block a step reads or adds to: a page's id, or a block's.
const BLOCK: Field = Field::required(
    "block",
    Kind::Text,
    Place::Path,
    "The page or block whose content it is, by its id.",
);

/// Every content operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "query-data-source",
        title: "Query a database",
        description: "Finds the pages of a database's data source that match a filter, in the order given.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("data_sources"),
            Segment::Input("data_source"),
            Segment::Fixed("query"),
        ],
        fields: &[
            data_source(Place::Path),
            Field::optional(
                "filter",
                Kind::Values,
                Place::Body,
                "Which pages, as Notion writes a filter, such as {\"property\": \"Status\", \"status\": {\"equals\": \"Open\"}}; every page when not given.",
            ),
            Field::optional(
                "sorts",
                Kind::Values,
                Place::Body,
                "The order, as Notion writes it, such as [{\"property\": \"Due\", \"direction\": \"ascending\"}].",
            )
            .more_options(),
            limit(Place::Body),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.results", "The pages found, each with its id and properties."),
            ("json.has_more", "Whether there are more than were given."),
            ("status", "The status Notion answered with."),
        ],
    },
    Operation {
        key: "get-data-source",
        title: "Read a database's properties",
        description: "Reads a database's data source: its title and the properties its pages have.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("data_sources"), Segment::Input("data_source")],
        fields: &[data_source(Place::Path)],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.title", "The data source's title."),
            (
                "json.properties",
                "The properties its pages have, each with its type.",
            ),
            ("status", "The status Notion answered with."),
        ],
    },
    Operation {
        key: "list-blocks",
        title: "Read a page's content",
        description: "Reads the blocks of content directly inside a page or block, in order.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("blocks"),
            Segment::Input("block"),
            Segment::Fixed("children"),
        ],
        fields: &[BLOCK, limit(Place::Query)],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.results", "The blocks, each with its id and type."),
            ("json.has_more", "Whether there are more than were given."),
            ("status", "The status Notion answered with."),
        ],
    },
    Operation {
        key: "append-blocks",
        title: "Add content to a page",
        description: "Adds blocks of content after the last one inside a page or block.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: &[
            Segment::Fixed("blocks"),
            Segment::Input("block"),
            Segment::Fixed("children"),
        ],
        fields: &[
            BLOCK,
            Field::required(
                "blocks",
                Kind::Values,
                Place::Body,
                "The blocks to add, as Notion writes blocks, such as [{\"paragraph\": {\"rich_text\": [{\"text\": {\"content\": \"Done\"}}]}}].",
            )
            .sent_as("children"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.results", "The blocks added, each with its id."),
            ("status", "The status Notion answered with."),
        ],
    },
    Operation {
        key: "comment-on-page",
        title: "Comment on a page",
        description: "Adds a comment to a page's discussion, which the people following it are told of.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[Segment::Fixed("comments")],
        fields: &[
            Field::required(
                "page",
                Kind::Text,
                Place::Body,
                "The page, by its id.",
            )
            .sent_as("parent.page_id"),
            Field::required(
                "text",
                Kind::Values,
                Place::Body,
                "The comment, as Notion writes rich text, such as [{\"text\": {\"content\": \"Looks good\"}}].",
            )
            .sent_as("rich_text"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The comment's id."),
            ("status", "The status Notion answered with."),
        ],
    },
    Operation {
        key: "list-users",
        title: "List people",
        description: "Lists the workspace's people and bots, with their ids for a page's people properties.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("users")],
        fields: &[limit(Place::Query)],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.results", "The people and bots, each with its id, name and type."),
            ("status", "The status Notion answered with."),
        ],
    },
];
