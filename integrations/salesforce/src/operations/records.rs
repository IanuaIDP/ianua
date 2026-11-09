//! Records of any kind of object: finding them with SOQL, reading,
//! adding, changing and deleting one, and listing the kinds of object the
//! forms' pickers offer.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{
    Field, Kind, Operation, Place, SPREAD, Segment, Shape, Verb,
};

/// The kinds of object the org has, picked and shown by name.
const OBJECTS: PickerText = PickerText {
    filled_by: "list-objects",
    items_at: "json.sobjects",
    value_at: "name",
    label_at: "label",
    depends_on: None,
};

/// The kind of object a step acts on, in the path.
const OBJECT: Field = Field::required(
    "object",
    Kind::Text,
    Place::Path,
    "The kind of object, by its API name, such as Account, Contact or Invoice__c.",
)
.asked_with(Ask::Picker(OBJECTS));

/// The record a step acts on, in the path.
const RECORD: Field = Field::required(
    "record",
    Kind::Text,
    Place::Path,
    "The record's id, such as 001xx000003DGb2AAG or an earlier step's json.id.",
);

/// A record's fields, laid over the body itself.
const FIELDS: Field = Field::required(
    "fields",
    Kind::Values,
    Place::Body,
    "The fields, by API name, such as {\"Name\": \"Acme\", \"Industry\": \"Retail\"}.",
)
.sent_as(SPREAD)
.asked_with(Ask::LongText);

/// The address of a kind of object's records.
const OF_OBJECT: &[Segment] = &[Segment::Fixed("sobjects"), Segment::Input("object")];

/// The address of one record.
const ONE: &[Segment] = &[
    Segment::Fixed("sobjects"),
    Segment::Input("object"),
    Segment::Input("record"),
];

/// Every record operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "query",
        title: "Find records",
        description: "Finds records with a SOQL query, such as SELECT Id, Name FROM Account WHERE Industry = 'Retail'.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("query")],
        fields: &[
            Field::required("soql", Kind::Text, Place::Query, "The SOQL query.")
                .sent_as("q")
                .asked_with(Ask::LongText)
                .example("SELECT Id, Name FROM Account WHERE Industry = 'Retail'"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.records",
                "The records found, with the fields asked for.",
            ),
            ("json.totalSize", "How many records match."),
            ("json.done", "Whether every record was given back."),
            ("status", "The status Salesforce answered with."),
        ],
    },
    Operation {
        key: "get-record",
        title: "Read a record",
        description: "Reads one record's fields, all of them or those named.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: ONE,
        fields: &[
            OBJECT,
            RECORD,
            Field::optional(
                "only",
                Kind::TextList,
                Place::Query,
                "Which fields to give back, by API name; every field when not given.",
            )
            .sent_as("fields")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.Id", "The record's id."),
            ("json", "Its fields, by API name."),
            (
                "status",
                "The status Salesforce answered with; 404 when there is no such record.",
            ),
        ],
    },
    Operation {
        key: "create-record",
        title: "Add a record",
        description: "Adds a record of any kind of object with the fields given.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: OF_OBJECT,
        fields: &[OBJECT, FIELDS],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The new record's id, which later steps name."),
            ("json.success", "Whether it was added."),
            ("status", "The status Salesforce answered with."),
        ],
    },
    Operation {
        key: "update-record",
        title: "Change a record",
        description: "Changes the fields given and leaves the others as they are.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: ONE,
        fields: &[OBJECT, RECORD, FIELDS],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Salesforce answered with, 204 when it was changed.",
        )],
    },
    Operation {
        key: "delete-record",
        title: "Delete a record",
        description: "Moves a record to Salesforce's recycle bin, from which an administrator may restore it for 15 days.",
        effect: DeclaredAction::Declared(ActionClass::Delete),
        verb: Verb::Delete,
        path: ONE,
        fields: &[OBJECT, RECORD],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[(
            "status",
            "The status Salesforce answered with, 204 when it was deleted.",
        )],
    },
    Operation {
        key: "list-objects",
        title: "List kinds of object",
        description: "Lists the kinds of object the org has, standard and custom.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("sobjects")],
        fields: &[],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.sobjects",
                "The kinds of object, each with its API name and label.",
            ),
            ("status", "The status Salesforce answered with."),
        ],
    },
];
