//! Every operation the HubSpot integration offers: finding, reading,
//! adding and changing contacts, companies and deals in HubSpot's CRM, and
//! listing the account's owners, each described once with the SDK's
//! [`Operation`]. Records are found and changed the same way for each kind
//! of object, so each step table is made from one kind.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, PickerText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

/// The account's owners, picked by id and shown by email.
const OWNERS: PickerText = PickerText {
    filled_by: "list-owners",
    items_at: "json.results",
    value_at: "id",
    label_at: "email",
    depends_on: None,
};

/// A record's properties, in the body.
const PROPERTIES: Field = Field::required(
    "properties",
    Kind::Values,
    Place::Body,
    "The properties, by their internal names, such as {\"email\": \"ann@acme.test\", \"firstname\": \"Ann\"}.",
)
.asked_with(Ask::LongText);

/// The properties a read gives back, in the query.
const WANTED: Field = Field::optional(
    "properties",
    Kind::TextList,
    Place::Query,
    "Which properties to give back, by internal name; HubSpot's few defaults when not given.",
)
.more_options();

/// Words to search for, in the body.
const WORDS: Field = Field::required(
    "words",
    Kind::Text,
    Place::Body,
    "What to look for in the records' default searchable properties, such as a name or an email address.",
)
.sent_as("query");

/// How many a search gives at most, in the body.
const LIMIT: Field = Field::optional(
    "limit",
    Kind::Count,
    Place::Body,
    "How many to give back, at most 200; 10 when not given.",
)
.more_options();

/// The path of a kind of object: `crm/v3/objects/{kind}`.
macro_rules! objects {
    ($kind:literal $(, $rest:expr)*) => {
        &[
            Segment::Fixed("crm"),
            Segment::Fixed("v3"),
            Segment::Fixed("objects"),
            Segment::Fixed($kind),
            $($rest,)*
        ]
    };
}

/// Every operation.
const OPERATIONS: &[Operation] = &[
    Operation {
        key: "search-contacts",
        title: "Find contacts",
        description: "Finds contacts whose name, email address or phone number holds the words given.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: objects!("contacts", Segment::Fixed("search")),
        fields: &[WORDS, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.results",
                "The contacts found, each with its id and properties.",
            ),
            ("json.total", "How many match."),
            ("status", "The status HubSpot answered with."),
        ],
    },
    Operation {
        key: "get-contact",
        title: "Read a contact",
        description: "Reads a contact's properties.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: objects!("contacts", Segment::Input("contact")),
        fields: &[
            Field::required("contact", Kind::Text, Place::Path, "The contact's id."),
            WANTED,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The contact's id."),
            ("json.properties", "Its properties, by internal name."),
            (
                "status",
                "The status HubSpot answered with; 404 when there is no such contact.",
            ),
        ],
    },
    Operation {
        key: "create-contact",
        title: "Add a contact",
        description: "Adds a contact with the properties given.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: objects!("contacts"),
        fields: &[PROPERTIES],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The new contact's id, which later steps name."),
            (
                "status",
                "The status HubSpot answered with; 409 when a contact has that email address.",
            ),
        ],
    },
    Operation {
        key: "update-contact",
        title: "Change a contact",
        description: "Changes the properties given and leaves the others as they are.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: objects!("contacts", Segment::Input("contact")),
        fields: &[
            Field::required("contact", Kind::Text, Place::Path, "The contact's id."),
            PROPERTIES,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.properties", "Its properties now."),
            ("status", "The status HubSpot answered with."),
        ],
    },
    Operation {
        key: "search-companies",
        title: "Find companies",
        description: "Finds companies whose name, domain or phone number holds the words given.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: objects!("companies", Segment::Fixed("search")),
        fields: &[WORDS, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.results",
                "The companies found, each with its id and properties.",
            ),
            ("json.total", "How many match."),
            ("status", "The status HubSpot answered with."),
        ],
    },
    Operation {
        key: "create-company",
        title: "Add a company",
        description: "Adds a company with the properties given, such as its name and domain.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: objects!("companies"),
        fields: &[PROPERTIES],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The new company's id, which later steps name."),
            ("status", "The status HubSpot answered with."),
        ],
    },
    Operation {
        key: "search-deals",
        title: "Find deals",
        description: "Finds deals whose name holds the words given.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Post,
        path: objects!("deals", Segment::Fixed("search")),
        fields: &[WORDS, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.results",
                "The deals found, each with its id and properties.",
            ),
            ("json.total", "How many match."),
            ("status", "The status HubSpot answered with."),
        ],
    },
    Operation {
        key: "create-deal",
        title: "Add a deal",
        description: "Adds a deal with the properties given, such as its name, amount, pipeline and stage.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: objects!("deals"),
        fields: &[PROPERTIES],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.id", "The new deal's id, which later steps name."),
            ("status", "The status HubSpot answered with."),
        ],
    },
    Operation {
        key: "update-deal",
        title: "Change a deal",
        description: "Changes the properties given, such as its stage or owner, and leaves the others as they are.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Patch,
        path: objects!("deals", Segment::Input("deal")),
        fields: &[
            Field::required("deal", Kind::Text, Place::Path, "The deal's id."),
            PROPERTIES,
            Field::optional(
                "owner",
                Kind::Text,
                Place::Body,
                "The owner it is handed to, by id.",
            )
            .sent_as("properties.hubspot_owner_id")
            .asked_with(Ask::Picker(OWNERS)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            ("json.properties", "Its properties now."),
            ("status", "The status HubSpot answered with."),
        ],
    },
    Operation {
        key: "list-owners",
        title: "List owners",
        description: "Lists the people records can be handed to.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[
            Segment::Fixed("crm"),
            Segment::Fixed("v3"),
            Segment::Fixed("owners"),
        ],
        fields: &[Field::optional(
            "email",
            Kind::Text,
            Place::Query,
            "Only the owner with this email address.",
        )],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.results",
                "The owners, each with its id, email and name.",
            ),
            ("status", "The status HubSpot answered with."),
        ],
    },
];

/// Every operation.
pub(crate) fn all() -> impl Iterator<Item = &'static Operation> {
    OPERATIONS.iter()
}

#[cfg(test)]
mod tests {
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
        let wrong = misdescribed(&IntegrationKey::new("hubspot").unwrap(), all());

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
        ServiceEndpoint::at("https://api.hubapi.com/").unwrap()
    }

    /// Finding a contact posts the words as HubSpot's query.
    #[test]
    fn finding_contacts_posts_the_words() {
        let given = arguments(vec![("words", text("ann@acme.test"))]);

        let made = call(operation("search-contacts"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.hubapi.com/crm/v3/objects/contacts/search"
        );
        assert_eq!(made.body, Some(json!({ "query": "ann@acme.test" })));
    }

    /// Handing a deal to an owner nests the owner among its properties.
    #[test]
    fn a_deal_is_handed_to_its_owner_among_its_properties() {
        let given = arguments(vec![
            ("deal", text("42")),
            (
                "properties",
                flow_of(&json!({ "dealstage": "closedwon" })).unwrap(),
            ),
            ("owner", text("7")),
        ]);

        let made = call(operation("update-deal"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.hubapi.com/crm/v3/objects/deals/42"
        );
        assert_eq!(
            made.body,
            Some(json!({ "properties": { "dealstage": "closedwon", "hubspot_owner_id": "7" } }))
        );
    }

    /// Reading a contact asks for the properties named, joined as HubSpot
    /// reads them.
    #[test]
    fn reading_a_contact_names_its_properties() {
        let wanted = FlowData::list(vec![text("email"), text("lifecyclestage")]).unwrap();
        let given = arguments(vec![("contact", text("51")), ("properties", wanted)]);

        let made = call(operation("get-contact"), &api(), &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.hubapi.com/crm/v3/objects/contacts/51?properties=email%2Clifecyclestage"
        );
    }

    /// A contact without properties and a deal identifier of `..` each
    /// prevent request construction.
    #[test]
    fn no_properties_or_a_crooked_deal_builds_no_call() {
        let empty = arguments(vec![]);
        let climbing = arguments(vec![
            ("deal", text("..")),
            ("properties", flow_of(&json!({})).unwrap()),
        ]);

        assert!(call(operation("create-contact"), &api(), &empty).is_err());
        assert!(call(operation("update-deal"), &api(), &climbing).is_err());
    }
}
