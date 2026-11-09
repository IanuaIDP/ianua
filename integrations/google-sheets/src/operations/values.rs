//! Values: reading cells, adding rows, writing over cells and clearing
//! them.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{SPREADSHEET, rendered, written};

/// The cells a step acts on, in the path, in A1 notation.
const RANGE: Field = Field::required(
    "range",
    Kind::Text,
    Place::Path,
    "The cells, in A1 notation: a tab and cells such as Sheet1!A1:C10, or a tab's name alone for all of it.",
)
.example("Sheet1!A1:C10");

/// The tab rows are added to, in the path.
const SHEET: Field = Field::required(
    "sheet",
    Kind::Text,
    Place::Path,
    "The tab whose table the rows go under, such as Sheet1; or a tab and columns such as Sheet1!A:C to name the table.",
)
.asked_with(Ask::Picker(PickerText {
    filled_by: "list-sheets",
    items_at: "json.sheets",
    value_at: "properties.title",
    label_at: "properties.title",
    depends_on: Some("spreadsheet"),
}))
.example("Sheet1");

/// The rows a step writes, in the body.
const ROWS: Field = Field::required(
    "rows",
    Kind::Values,
    Place::Body,
    "The rows, as a list of lists, one list of cells per row, such as [[\"Ann\", 3], [\"Bo\", 5]].",
)
.sent_as("values");

/// How a row is added: written over the empty cells below the table, or
/// into new rows inserted for it.
const INSERT: &[ChoiceText] = &[
    ChoiceText {
        value: "OVERWRITE",
        label: "Into the empty cells below",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "INSERT_ROWS",
        label: "Into new rows",
        tone: Tone::Info,
    },
];

/// The path of one range's values.
const ONE: &[Segment] = &[
    Segment::Fixed("spreadsheets"),
    Segment::Input("spreadsheet"),
    Segment::Fixed("values"),
    Segment::Input("range"),
];

/// Every values operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "read-range",
        title: "Read cells",
        description: "Reads the values in a range of cells, row by row, leaving out empty rows and columns at its end.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE,
        fields: &[SPREADSHEET, RANGE, rendered(Place::Query)],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.values",
                "The rows, each a list of its cells' values; absent when every cell is empty.",
            ),
            ("json.range", "The range read, as Google writes it."),
        ],
    },
    Operation {
        key: "read-ranges",
        title: "Read several ranges",
        description: "Reads the values in several ranges of cells in one call, each range's rows on their own.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("spreadsheets"),
            Segment::Input("spreadsheet"),
            Segment::Fixed("values:batchGetByDataFilter"),
        ],
        fields: &[
            SPREADSHEET,
            Field::required(
                "ranges",
                Kind::Values,
                Place::Body,
                "The ranges, as a list such as [{\"a1Range\": \"Sheet1!A1:C10\"}, {\"a1Range\": \"Totals!B2\"}].",
            )
            .sent_as("dataFilters"),
            rendered(Place::Body),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "json.valueRanges",
            "One entry per range asked for, in order, each with its valueRange holding range and values.",
        )],
    },
    Operation {
        key: "append-rows",
        title: "Add rows",
        description: "Adds rows after the last row of a table on a tab.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("spreadsheets"),
            Segment::Input("spreadsheet"),
            Segment::Fixed("values"),
            Segment::Suffixed {
                input: "sheet",
                suffix: ":append",
            },
        ],
        fields: &[
            SPREADSHEET,
            SHEET,
            ROWS,
            written(Place::Query),
            Field::optional(
                "insert",
                Kind::Text,
                Place::Query,
                "Whether the rows go into the empty cells below the table or into new rows inserted for them; the empty cells when not given.",
            )
            .sent_as("insertDataOption")
            .asked_with(Ask::Choices(INSERT))
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.updates.updatedRange",
                "The cells the rows were written to, such as Sheet1!A11:C12.",
            ),
            ("json.updates.updatedRows", "How many rows were added."),
            (
                "json.tableRange",
                "The table the rows were added after, before they were.",
            ),
        ],
    },
    Operation {
        key: "update-range",
        title: "Write cells",
        description: "Writes values over a range of cells, row by row, leaving cells outside the rows given as they were.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Put,
        path: ONE,
        fields: &[SPREADSHEET, RANGE, ROWS, written(Place::Query)],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.updatedRange", "The cells written."),
            ("json.updatedRows", "How many rows were written."),
            ("json.updatedCells", "How many cells were written."),
        ],
    },
    Operation {
        key: "update-ranges",
        title: "Write several ranges",
        description: "Writes values over several ranges of cells in one call.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("spreadsheets"),
            Segment::Input("spreadsheet"),
            Segment::Fixed("values:batchUpdate"),
        ],
        fields: &[
            SPREADSHEET,
            Field::required(
                "ranges",
                Kind::Values,
                Place::Body,
                "The ranges and their rows, as a list such as [{\"range\": \"Sheet1!A1:B1\", \"values\": [[\"Ann\", 3]]}].",
            )
            .sent_as("data"),
            written(Place::Body),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.totalUpdatedCells", "How many cells were written."),
            (
                "json.responses",
                "One entry per range, each with its updatedRange.",
            ),
        ],
    },
    Operation {
        key: "clear-range",
        title: "Clear cells",
        description: "Removes the values in a range of cells for good, keeping their formatting.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("spreadsheets"),
            Segment::Input("spreadsheet"),
            Segment::Fixed("values"),
            Segment::Suffixed {
                input: "range",
                suffix: ":clear",
            },
        ],
        fields: &[SPREADSHEET, RANGE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[("json.clearedRange", "The cells cleared.")],
    },
];
