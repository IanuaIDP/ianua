//! The records a workflow adds most often, each with its own inputs: a
//! lead, a task for someone, and a support case.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

/// What adding a record gives back.
const ADDED: &[(&str, &str)] = &[
    ("json.id", "The new record's id, which later steps name."),
    ("json.success", "Whether it was added."),
    ("status", "The status Salesforce answered with."),
];

/// Every sales operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "create-lead",
        title: "Add a lead",
        description: "Adds a lead: a person at a company who may become a customer.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("sobjects"), Segment::Fixed("Lead")],
        fields: &[
            Field::required(
                "last_name",
                Kind::Text,
                Place::Body,
                "The person's last name.",
            )
            .sent_as("LastName"),
            Field::required(
                "company",
                Kind::Text,
                Place::Body,
                "The company they are at.",
            )
            .sent_as("Company"),
            Field::optional(
                "first_name",
                Kind::Text,
                Place::Body,
                "The person's first name.",
            )
            .sent_as("FirstName"),
            Field::optional("email", Kind::Text, Place::Body, "Their email address.")
                .sent_as("Email"),
            Field::optional("phone", Kind::Text, Place::Body, "Their phone number.")
                .sent_as("Phone")
                .more_options(),
            Field::optional(
                "source",
                Kind::Text,
                Place::Body,
                "Where the lead came from, such as Web or Partner Referral.",
            )
            .sent_as("LeadSource")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: ADDED,
    },
    Operation {
        key: "create-task",
        title: "Add a task",
        description: "Adds a task for someone, about a person or a record, such as a call to make.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("sobjects"), Segment::Fixed("Task")],
        fields: &[
            Field::required(
                "subject",
                Kind::Text,
                Place::Body,
                "What the task is, such as Call back.",
            )
            .sent_as("Subject"),
            Field::optional(
                "owner",
                Kind::Text,
                Place::Body,
                "Who the task is for, by user id; whoever connected the account when not given.",
            )
            .sent_as("OwnerId"),
            Field::optional(
                "person",
                Kind::Text,
                Place::Body,
                "The lead or contact it is about, by id.",
            )
            .sent_as("WhoId"),
            Field::optional(
                "about",
                Kind::Text,
                Place::Body,
                "The account, opportunity or other record it is about, by id.",
            )
            .sent_as("WhatId"),
            Field::optional(
                "due",
                Kind::Text,
                Place::Body,
                "The day it is due, such as 2026-11-20.",
            )
            .sent_as("ActivityDate"),
            Field::optional("notes", Kind::Text, Place::Body, "What else to know.")
                .sent_as("Description")
                .asked_with(Ask::LongText)
                .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: ADDED,
    },
    Operation {
        key: "create-case",
        title: "Open a case",
        description: "Opens a support case, optionally for a contact.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[Segment::Fixed("sobjects"), Segment::Fixed("Case")],
        fields: &[
            Field::required(
                "subject",
                Kind::Text,
                Place::Body,
                "What the case is about.",
            )
            .sent_as("Subject"),
            Field::optional("description", Kind::Text, Place::Body, "What happened.")
                .sent_as("Description")
                .asked_with(Ask::LongText),
            Field::optional(
                "contact",
                Kind::Text,
                Place::Body,
                "The contact it is for, by id.",
            )
            .sent_as("ContactId"),
            Field::optional(
                "priority",
                Kind::Text,
                Place::Body,
                "How urgent it is, such as High, Medium or Low.",
            )
            .sent_as("Priority")
            .more_options(),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Object,
        outputs: ADDED,
    },
];
