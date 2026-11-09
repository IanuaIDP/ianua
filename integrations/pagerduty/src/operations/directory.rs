//! The account's directory: its services, escalation policies and people,
//! which fill the pickers, and who is on call now.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{ESCALATION_POLICIES, LIMIT, SEARCH, user_filter};

/// Every directory operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-services",
        title: "List services",
        description: "Lists the account's services by name, optionally only those whose name holds some words.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("services")],
        fields: &[SEARCH, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.services",
                "The services, each with its id, name, status and html_url.",
            ),
            ("status", "The status PagerDuty answered with."),
        ],
    },
    Operation {
        key: "list-escalation-policies",
        title: "List escalation policies",
        description: "Lists the account's escalation policies, which say who is paged and in what order, optionally only those whose name holds some words.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("escalation_policies")],
        fields: &[SEARCH, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.escalation_policies",
                "The escalation policies, each with its id, name and html_url.",
            ),
            ("status", "The status PagerDuty answered with."),
        ],
    },
    Operation {
        key: "list-users",
        title: "List people",
        description: "Lists the account's people, optionally only those whose name or email holds some words.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("users")],
        fields: &[
            Field::optional(
                "search",
                Kind::Text,
                Place::Query,
                "Only people whose name or email holds these words.",
            )
            .sent_as("query"),
            LIMIT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: &[
            (
                "json.users",
                "The people, each with their id, name, email and role.",
            ),
            ("status", "The status PagerDuty answered with."),
        ],
    },
    Operation {
        key: "list-on-call",
        title: "List who is on call",
        description: "Lists who is on call now, at which level of which escalation policy, optionally for one policy or one person.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("oncalls")],
        fields: &[
            Field::optional(
                "escalation_policies",
                Kind::RepeatedList,
                Place::Query,
                "Only those on call for these escalation policies, by id.",
            )
            .sent_as("escalation_policy_ids[]")
            .asked_with(Ask::Picker(ESCALATION_POLICIES)),
            user_filter("Only these people's turns on call, by id."),
            LIMIT,
        ],
        fixed: &[],
        query: &[("earliest", "true")],
        shape: Shape::Object,
        outputs: &[
            (
                "json.oncalls",
                "Who is on call, each with the user, the escalation_policy, the escalation_level and when the turn starts and ends.",
            ),
            ("status", "The status PagerDuty answered with."),
        ],
    },
];
