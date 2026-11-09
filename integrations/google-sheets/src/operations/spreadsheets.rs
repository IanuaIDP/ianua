//! Spreadsheets: listing a spreadsheet's tabs, adding one, and creating a
//! spreadsheet.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::SPREADSHEET;

/// Every spreadsheet operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-sheets",
        title: "List a spreadsheet's tabs",
        description: "Reads a spreadsheet's title and address, and each of its tabs with its name, number and size.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("spreadsheets"),
            Segment::Input("spreadsheet"),
        ],
        fields: &[SPREADSHEET],
        fixed: &[],
        query: &[(
            "fields",
            "spreadsheetId,spreadsheetUrl,properties.title,sheets.properties",
        )],
        shape: Shape::Object,
        outputs: &[
            (
                "json.sheets",
                "The tabs, each with its properties: title, sheetId, index and gridProperties.",
            ),
            ("json.properties.title", "The spreadsheet's title."),
            (
                "json.spreadsheetUrl",
                "The address of the spreadsheet in Google Sheets.",
            ),
        ],
    },
    Operation {
        key: "add-tab",
        title: "Add a tab",
        description: "Adds an empty tab to a spreadsheet, such as one for the new month.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("spreadsheets"),
            Segment::Suffixed {
                input: "spreadsheet",
                suffix: ":batchUpdate",
            },
        ],
        fields: &[
            SPREADSHEET,
            Field::required(
                "title",
                Kind::Text,
                Place::Body,
                "The new tab's name; it goes after the others.",
            )
            .sent_as("requests[].addSheet.properties.title"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.replies",
                "One reply, whose addSheet.properties hold the new tab's sheetId and title.",
            ),
            ("json.spreadsheetId", "The spreadsheet's id."),
        ],
    },
    Operation {
        key: "create-spreadsheet",
        title: "Create a spreadsheet",
        description: "Creates a spreadsheet in the account's Drive, with one empty tab.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("spreadsheets")],
        fields: &[
            Field::required("title", Kind::Text, Place::Body, "The spreadsheet's title.")
                .sent_as("properties.title"),
            Field::optional(
                "locale",
                Kind::Text,
                Place::Body,
                "How numbers and dates are written, such as en_US or de_DE.",
            )
            .sent_as("properties.locale")
            .more_options(),
            Field::optional(
                "time_zone",
                Kind::Text,
                Place::Body,
                "Its time zone, such as Europe/Berlin.",
            )
            .sent_as("properties.timeZone")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.spreadsheetId",
                "The spreadsheet's id, which its other steps name.",
            ),
            (
                "json.spreadsheetUrl",
                "The address of the spreadsheet in Google Sheets.",
            ),
            ("json.sheets", "Its tabs, each with its properties."),
        ],
    },
];
