//! Pages: finding pages and databases' data sources, reading a page,
//! making one in a data source, changing its properties, and moving it to
//! the trash.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{
    Field, Fixed, Kind, Operation, Place, Segment, Shape, Verb,
};

use crate::operations::{PAGE, PROPERTIES, data_source, limit};

/// What a search finds: pages or databases' data sources.
const KINDS: &[ChoiceText] = &[
    ChoiceText {
        value: "page",
        label: "Pages",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "data_source",
        label: "Databases",
        tone: Tone::Neutral,
    },
];

/// The address of one page.
const ONE_PAGE: &[Segment] = &[Segment::Fixed("pages"), Segment::Input("page")];

/// Every page operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "search",
        title: "Find pages or databases",
        description: "Finds the pages or databases shared with the integration whose titles hold the words given.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: &[Segment::Fixed("search")],
        fields: &[
            Field::optional(
                "words",
                Kind::Text,
                Place::Body,
                "Words the titles hold; every one shared when not given.",
            )
            .sent_as("query"),
            Field::required(
                "kind",
                Kind::Text,
                Place::Body,
                "What to find: page, or data_source for databases.",
            )
            .sent_as("filter.value")
            .asked_with(Ask::Choices(KINDS)),
            limit(Place::Body),
        ],
        fixed: &[("filter.property", Fixed::Text("object"))],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.results",
                "The pages or data sources found, each with its id; a page also has its url.",
            ),
            ("json.has_more", "Whether there are more than were given."),
            ("status", "The status Notion answered with."),
        ],
    },
    Operation {
        key: "list-data-sources",
        title: "List databases",
        description: "Lists the data sources of the databases shared with the integration, which the forms' pickers offer.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: &[Segment::Fixed("search")],
        fields: &[limit(Place::Body)],
        fixed: &[
            ("filter.property", Fixed::Text("object")),
            ("filter.value", Fixed::Text("data_source")),
        ],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.results",
                "The data sources, each with its id and its title.",
            ),
            ("status", "The status Notion answered with."),
        ],
    },
    Operation {
        key: "get-page",
        title: "Read a page",
        description: "Reads a page's properties, such as its title, status and dates.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE_PAGE,
        fields: &[PAGE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The page's id."),
            ("json.url", "The page's address in Notion."),
            ("json.properties", "Its properties, each by its name."),
            ("status", "The status Notion answered with; 404 when the page is not shared with the integration."),
        ],
    },
    Operation {
        key: "create-page",
        title: "Add a page to a database",
        description: "Adds a page to a database's data source with the properties given, and optionally its first blocks of content.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("pages")],
        fields: &[
            data_source(Place::Body).sent_as("parent.data_source_id"),
            PROPERTIES,
            Field::optional(
                "blocks",
                Kind::Values,
                Place::Body,
                "The page's first blocks of content, as Notion writes blocks, such as [{\"paragraph\": {\"rich_text\": [{\"text\": {\"content\": \"Hello\"}}]}}].",
            )
            .sent_as("children")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The new page's id, which later steps name."),
            ("json.url", "Its address in Notion."),
            ("status", "The status Notion answered with."),
        ],
    },
    Operation {
        key: "update-page",
        title: "Change a page's properties",
        description: "Changes the properties given and leaves the others as they are.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: ONE_PAGE,
        fields: &[PAGE, PROPERTIES],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.properties", "Its properties now."),
            ("status", "The status Notion answered with."),
        ],
    },
    Operation {
        key: "trash-page",
        title: "Move a page to the trash",
        description: "Moves a page to Notion's trash, where it can be restored for 30 days.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: ONE_PAGE,
        fields: &[PAGE],
        fixed: &[("in_trash", Fixed::Flag(true))],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.in_trash", "True once it is in the trash."),
            ("status", "The status Notion answered with."),
        ],
    },
];
