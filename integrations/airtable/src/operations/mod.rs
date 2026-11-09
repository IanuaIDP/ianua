//! Every operation the Airtable integration offers: listing the bases and
//! tables a token reaches, which the forms' pickers offer, and finding,
//! reading, adding, changing and deleting records, each described once
//! with the SDK's [`Operation`].

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

/// The bases the token reaches, picked by id and shown by name.
const BASES: PickerText = PickerText {
    filled_by: "list-bases",
    items_at: "json.bases",
    value_at: "id",
    label_at: "name",
    depends_on: None,
};

/// The chosen base's tables, picked by id and shown by name.
const TABLES: PickerText = PickerText {
    filled_by: "list-tables",
    items_at: "json.tables",
    value_at: "id",
    label_at: "name",
    depends_on: Some("base"),
};

/// The base a step acts in, in the path.
const BASE: Field = Field::required(
    "base",
    Kind::Text,
    Place::Path,
    "The base, by its id, such as appXXXXXXXXXXXXXX.",
)
.asked_with(Ask::Picker(BASES));

/// The table a step acts in, in the path.
const TABLE: Field = Field::required(
    "table",
    Kind::Text,
    Place::Path,
    "The table, by its id or its name.",
)
.asked_with(Ask::Picker(TABLES));

/// The record a step acts on, in the path.
const RECORD: Field = Field::required(
    "record",
    Kind::Text,
    Place::Path,
    "The record's id, such as recXXXXXXXXXXXXXX or an earlier step's json.id.",
);

/// A record's fields, in the body.
const FIELDS: Field = Field::required(
    "fields",
    Kind::Values,
    Place::Body,
    "The fields, by name, such as {\"Name\": \"Ann\", \"Orders\": 3}.",
)
.asked_with(Ask::LongText);

/// Whether text is read into the field's own type, such as a choice made
/// from its name, in the body.
const TYPECAST: Field = Field::optional(
    "convert",
    Kind::Flag,
    Place::Body,
    "Whether text is read into each field's own type, such as a choice made from its name; false when not given.",
)
.sent_as("typecast")
.more_options();

/// The address of one table's records.
const RECORDS: &[Segment] = &[Segment::Input("base"), Segment::Input("table")];

/// The address of one record.
const ONE: &[Segment] = &[
    Segment::Input("base"),
    Segment::Input("table"),
    Segment::Input("record"),
];

/// Every operation.
const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-bases",
        title: "List bases",
        description: "Lists the bases the token reaches.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("meta"), Segment::Fixed("bases")],
        fields: &[],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.bases", "The bases, each with its id and name."),
            ("status", "The status Airtable answered with."),
        ],
    },
    Operation {
        key: "list-tables",
        title: "List tables",
        description: "Lists a base's tables with their fields.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("meta"),
            Segment::Fixed("bases"),
            Segment::Input("base"),
            Segment::Fixed("tables"),
        ],
        fields: &[BASE],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.tables", "The tables, each with its id, name and fields."),
            ("status", "The status Airtable answered with."),
        ],
    },
    Operation {
        key: "list-records",
        title: "Find records",
        description: "Finds a table's records, those a formula keeps, or those of a view, in its order.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: RECORDS,
        fields: &[
            BASE,
            TABLE,
            Field::optional(
                "formula",
                Kind::Text,
                Place::Query,
                "Which records, as an Airtable formula, such as {Status} = 'Open'; every record when not given.",
            )
            .sent_as("filterByFormula"),
            Field::optional(
                "view",
                Kind::Text,
                Place::Query,
                "A view, by name or id, whose records and order are taken.",
            )
            .more_options(),
            Field::optional(
                "limit",
                Kind::Count,
                Place::Query,
                "How many records to give back at most; 100 when not given.",
            )
            .sent_as("pageSize")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.records", "The records, each with its id and fields."),
            ("json.offset", "Where the next page starts, when there is one."),
            ("status", "The status Airtable answered with."),
        ],
    },
    Operation {
        key: "get-record",
        title: "Read a record",
        description: "Reads one record's fields.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE,
        fields: &[BASE, TABLE, RECORD],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The record's id."),
            ("json.fields", "Its fields, by name."),
            ("status", "The status Airtable answered with; 404 when there is no such record."),
        ],
    },
    Operation {
        key: "create-record",
        title: "Add a record",
        description: "Adds a record to a table with the fields given.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: RECORDS,
        fields: &[BASE, TABLE, FIELDS, TYPECAST],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The new record's id, which later steps name."),
            ("json.fields", "Its fields."),
            ("status", "The status Airtable answered with."),
        ],
    },
    Operation {
        key: "update-record",
        title: "Change a record",
        description: "Changes the fields given and leaves the others as they are.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: ONE,
        fields: &[BASE, TABLE, RECORD, FIELDS, TYPECAST],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.fields", "Its fields now."),
            ("status", "The status Airtable answered with."),
        ],
    },
    Operation {
        key: "delete-record",
        title: "Delete a record",
        description: "Deletes a record for good.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE,
        fields: &[BASE, TABLE, RECORD],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.deleted", "True once it is deleted."),
            ("status", "The status Airtable answered with."),
        ],
    },
];

/// Every operation.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    OPERATIONS.iter()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::data::{FieldName, FlowData};
    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_integration::ServiceEndpoint;
    use ianua_integration::answer::flow_of;
    use ianua_integration::rest::checks::misdescribed;
    use ianua_integration::rest::request::call;
    use serde_json::json;

    use super::*;

    /// Every operation keeps the SDK's rules.
    #[test]
    fn every_operation_keeps_the_rules() {
        let wrong = misdescribed(&IntegrationKey::new("airtable").unwrap(), all());

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

    fn operation(key: &str) -> &'static Operation {
        all().find(|operation| operation.key == key).unwrap()
    }

    fn api() -> ServiceEndpoint {
        ServiceEndpoint::at("https://api.airtable.com/v0/").unwrap()
    }

    /// Finding open orders names the table by its name, its space escaped,
    /// with the formula in the query under Airtable's name.
    #[test]
    fn finding_records_sends_the_formula() {
        let given = arguments(vec![
            ("base", text("appOrders")),
            ("table", text("Open orders")),
            ("formula", text("{Status} = 'Open'")),
        ]);

        let made = call(operation("list-records"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.airtable.com/v0/appOrders/Open%20orders\
             ?filterByFormula=%7BStatus%7D+%3D+%27Open%27"
        );
    }

    /// Adding a record sends its fields as they are, and how text is read.
    #[test]
    fn adding_a_record_sends_its_fields() {
        let fields = json!({ "Name": "Ann", "Orders": 3 });
        let given = arguments(vec![
            ("base", text("appOrders")),
            ("table", text("tblPeople")),
            ("fields", flow_of(&fields).unwrap()),
            ("convert", FlowData::bool(true)),
        ]);

        let made = call(operation("create-record"), &api(), &given).unwrap();

        assert_eq!(
            made.body,
            Some(json!({ "fields": fields, "typecast": true }))
        );
    }

    /// Missing creation fields and a record identifier of `..` each
    /// prevent request construction.
    #[test]
    fn no_fields_or_a_crooked_record_builds_no_call() {
        let empty = arguments(vec![
            ("base", text("appOrders")),
            ("table", text("tblPeople")),
        ]);
        let climbing = arguments(vec![
            ("base", text("appOrders")),
            ("table", text("tblPeople")),
            ("record", text("..")),
        ]);

        assert!(call(operation("create-record"), &api(), &empty).is_err());
        assert!(call(operation("get-record"), &api(), &climbing).is_err());
    }

    /// The table is picked from the chosen base's tables, which listing
    /// them gives back.
    #[test]
    fn the_table_is_picked_from_the_bases_tables() {
        let guide = operation("create-record").guide(None).unwrap();
        let table = FieldName::new("table").unwrap();
        let picker = guide
            .input(&table)
            .unwrap()
            .form()
            .block()
            .picker()
            .unwrap();
        let filler = operation(picker.filled_by().as_str());

        let spec = filler
            .spec(
                &IntegrationKey::new("airtable").unwrap(),
                DataClassLevel::Internal,
            )
            .unwrap();

        assert_eq!(picker.depends_on().map(FieldName::as_str), Some("base"));
        assert_eq!(spec.effect(), DeclaredAction::Declared(ActionClass::Read));
    }
}
