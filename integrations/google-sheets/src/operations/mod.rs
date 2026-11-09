//! Every operation the Google Sheets integration offers, grouped by topic:
//! spreadsheets and their values, each described once with the SDK's
//! [`Operation`].

mod spreadsheets;
mod values;

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place};

/// The spreadsheet a step acts on, in the path.
pub(crate) const SPREADSHEET: Field = Field::required(
    "spreadsheet",
    Kind::Text,
    Place::Path,
    "The spreadsheet's id: the long part of its address between /d/ and /edit, or an earlier step's json.spreadsheetId.",
);

/// How written values are read: stored as given, or read as if typed into
/// Google Sheets, where a formula runs.
const INPUTS: &[ChoiceText] = &[
    ChoiceText {
        value: "RAW",
        label: "Stored as given",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "USER_ENTERED",
        label: "As if typed in, running formulas",
        tone: Tone::Warning,
    },
];

/// How read values are given back.
const RENDERINGS: &[ChoiceText] = &[
    ChoiceText {
        value: "FORMATTED_VALUE",
        label: "As shown",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "UNFORMATTED_VALUE",
        label: "Plain numbers",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "FORMULA",
        label: "Formulas",
        tone: Tone::Info,
    },
];

/// How the values a step writes are read, sent at `place`.
pub(crate) const fn written(place: Place) -> Field {
    Field::required(
        "input",
        Kind::Text,
        place,
        "How the values are read: RAW stores them as given; USER_ENTERED reads them as if typed in, so text starting with = runs as a formula.",
    )
    .sent_as("valueInputOption")
    .asked_with(Ask::Choices(INPUTS))
}

/// How the values a step reads are given back, sent at `place`.
pub(crate) const fn rendered(place: Place) -> Field {
    Field::optional(
        "rendering",
        Kind::Text,
        place,
        "How values are given back: FORMATTED_VALUE as shown, UNFORMATTED_VALUE as plain numbers, FORMULA as the formulas; as shown when not given.",
    )
    .sent_as("valueRenderOption")
    .asked_with(Ask::Choices(RENDERINGS))
    .more_options()
}

/// Every operation, topic by topic.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    spreadsheets::OPERATIONS.iter().chain(values::OPERATIONS)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::types::{ActionClass, DeclaredAction};
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::call;
    use serde_json::json;

    use super::*;

    /// Every operation keeps the SDK's rules.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("google-sheets").unwrap(), all());

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

    fn row(cells: &[&str]) -> FlowData {
        FlowData::list(cells.iter().map(|cell| text(cell)).collect()).unwrap()
    }

    fn operation(key: &str) -> &'static Operation {
        all().find(|operation| operation.key == key).unwrap()
    }

    fn api() -> ServiceEndpoint {
        ServiceEndpoint::at("https://sheets.googleapis.com/v4/").unwrap()
    }

    /// Adding rows names the tab before `:append`, keeps the tab's space
    /// escaped, and sends the rows as Google reads them.
    #[test]
    fn adding_rows_appends_under_the_tab() {
        let given = arguments(vec![
            ("spreadsheet", text("sheet-of-orders")),
            ("sheet", text("Q3 sales")),
            (
                "rows",
                FlowData::list(vec![row(&["Ann", "3"]), row(&["Bo", "5"])]).unwrap(),
            ),
            ("input", text("RAW")),
            ("insert", text("INSERT_ROWS")),
        ]);

        let made = call(operation("append-rows"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://sheets.googleapis.com/v4/spreadsheets/sheet-of-orders/values/Q3%20sales:append\
             ?valueInputOption=RAW&insertDataOption=INSERT_ROWS"
        );
        assert_eq!(
            made.body,
            Some(json!({ "values": [["Ann", "3"], ["Bo", "5"]] }))
        );
    }

    /// Reading cells keeps the range's `!` and `:` as Google writes them.
    #[test]
    fn reading_cells_keeps_the_range_as_written() {
        let given = arguments(vec![
            ("spreadsheet", text("sheet-of-orders")),
            ("range", text("Sheet1!A1:C10")),
            ("rendering", text("UNFORMATTED_VALUE")),
        ]);

        let made = call(operation("read-range"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://sheets.googleapis.com/v4/spreadsheets/sheet-of-orders/values/Sheet1!A1:C10\
             ?valueRenderOption=UNFORMATTED_VALUE"
        );
        assert_eq!(made.body, None);
    }

    /// Writing several ranges sends each range with its rows, and how they
    /// are read, in the body.
    #[test]
    fn writing_several_ranges_sends_them_in_the_body() {
        let ranges = FlowData::list(vec![arguments(vec![
            ("range", text("Totals!B2")),
            ("values", FlowData::list(vec![row(&["8"])]).unwrap()),
        ])])
        .unwrap();
        let given = arguments(vec![
            ("spreadsheet", text("sheet-of-orders")),
            ("ranges", ranges),
            ("input", text("USER_ENTERED")),
        ]);

        let made = call(operation("update-ranges"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://sheets.googleapis.com/v4/spreadsheets/sheet-of-orders/values:batchUpdate"
        );
        assert_eq!(
            made.body,
            Some(json!({
                "data": [{ "range": "Totals!B2", "values": [["8"]] }],
                "valueInputOption": "USER_ENTERED"
            }))
        );
    }

    /// Clearing cells posts an empty request to the range's `:clear`, and is
    /// counted as removing for good.
    #[test]
    fn clearing_cells_is_a_removal_with_an_empty_request() {
        let given = arguments(vec![
            ("spreadsheet", text("sheet-of-orders")),
            ("range", text("Sheet1!A2:C")),
        ]);
        let clear = operation("clear-range");

        let made = call(clear, &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://sheets.googleapis.com/v4/spreadsheets/sheet-of-orders/values/Sheet1!A2:C:clear"
        );
        assert_eq!(made.body, Some(json!({})));
        assert_eq!(clear.effect, DeclaredAction::Declared(ActionClass::Delete));
    }

    /// Creating a spreadsheet nests its title where Google reads it.
    #[test]
    fn creating_a_spreadsheet_nests_its_title() {
        let given = arguments(vec![
            ("title", text("Orders 2026")),
            ("time_zone", text("Europe/Berlin")),
        ]);

        let made = call(operation("create-spreadsheet"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://sheets.googleapis.com/v4/spreadsheets"
        );
        assert_eq!(
            made.body,
            Some(json!({ "properties": { "title": "Orders 2026", "timeZone": "Europe/Berlin" } }))
        );
    }

    /// Updating rows without an input mode and reading a range named `..`
    /// each fail request construction.
    #[test]
    fn unread_rows_or_a_crooked_range_builds_no_call() {
        let unsaid = arguments(vec![
            ("spreadsheet", text("sheet-of-orders")),
            ("range", text("Sheet1!A1")),
            ("rows", FlowData::list(vec![row(&["Ann"])]).unwrap()),
        ]);
        let climbing = arguments(vec![
            ("spreadsheet", text("sheet-of-orders")),
            ("range", text("..")),
        ]);

        assert!(call(operation("update-range"), &api(), &unsaid).is_err());
        assert!(call(operation("read-range"), &api(), &climbing).is_err());
    }

    /// The tab rows are added to is picked from the chosen spreadsheet's
    /// tabs, which listing them gives back.
    #[test]
    fn the_tab_is_picked_from_the_spreadsheets_tabs() {
        let guide = operation("append-rows").guide(None).unwrap();
        let sheet = FieldName::new("sheet").unwrap();
        let picker = guide
            .input(&sheet)
            .unwrap()
            .form()
            .block()
            .picker()
            .unwrap();
        let filler = operation(picker.filled_by().as_str());

        let spec = filler
            .spec(
                &IntegrationKey::new("google-sheets").unwrap(),
                DataClassLevel::Internal,
            )
            .unwrap();

        assert_eq!(
            picker.depends_on().map(FieldName::as_str),
            Some("spreadsheet")
        );
        assert_eq!(spec.effect(), DeclaredAction::Declared(ActionClass::Read));
        assert!(
            filler
                .outputs
                .iter()
                .any(|(path, _)| *path == picker.items_at().to_string())
        );
    }
}
