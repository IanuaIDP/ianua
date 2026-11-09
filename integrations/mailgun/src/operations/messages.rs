//! Messages: sending an email from one of the account's domains, and
//! reading what happened to the mail it sent.

use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::Ask;
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::DOMAIN;

/// Every message operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "send-message",
        title: "Send an email",
        description: "Sends an email from one of the account's domains, written out or from a stored template.",
        effect: DeclaredAction::Declared(ActionClass::Communicate),
        verb: Verb::Post,
        path: &[Segment::Fixed("v3"), Segment::Input("domain"), Segment::Fixed("messages")],
        fields: &[
            DOMAIN,
            Field::required("from", Kind::Text, Place::Body, "Who it is from, an address on the domain, such as Ops <ops@mail.acme.test>."),
            Field::required("to", Kind::TextList, Place::Body, "Who it goes to, one address or more."),
            Field::optional("cc", Kind::TextList, Place::Body, "Who gets a copy."),
            Field::optional("bcc", Kind::TextList, Place::Body, "Who gets a hidden copy."),
            Field::required("subject", Kind::Text, Place::Body, "The subject line."),
            Field::optional("text", Kind::Text, Place::Body, "The email as plain text.")
                .asked_with(Ask::LongText),
            Field::optional("html", Kind::Text, Place::Body, "The email as HTML.")
                .asked_with(Ask::LongText)
                .more_options(),
            Field::optional("template", Kind::Text, Place::Body, "The name of a stored template to write the email from."),
            Field::optional("template_values", Kind::Values, Place::Body, "The values the template fills in, such as {\"name\": \"Ann\"}.")
                .sent_as("t:variables"),
            Field::optional("tags", Kind::TextList, Place::Body, "Tags to find the email by in events and reports.")
                .sent_as("o:tag"),
            Field::optional("deliver_at", Kind::Text, Place::Body, "When to deliver it, such as Tue, 03 Nov 2026 09:00:00 +0000; up to three days ahead.")
                .sent_as("o:deliverytime"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.id", "The email's message id, which its events name."),
            ("json.message", "Mailgun's word that it was queued."),
            ("status", "The status Mailgun answered with, 200 when it took the email."),
        ],
    },
    Operation {
        key: "list-events",
        title: "List email events",
        description: "Lists what happened to a domain's mail, newest first: delivered, failed, opened, clicked, unsubscribed or complained.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("v3"), Segment::Input("domain"), Segment::Fixed("events")],
        fields: &[
            DOMAIN,
            Field::optional("event", Kind::Text, Place::Query, "Only this kind of event, such as failed or delivered."),
            Field::optional("recipient", Kind::Text, Place::Query, "Only events for mail to this address."),
            Field::optional("message", Kind::Text, Place::Query, "Only events for this message id, such as an earlier step's json.id.")
                .sent_as("message-id"),
            Field::optional("since", Kind::Text, Place::Query, "Only events after this time, such as Mon, 02 Nov 2026 00:00:00 +0000.")
                .sent_as("begin"),
            Field::optional("most", Kind::Count, Place::Query, "How many to give at most, up to 300.")
                .sent_as("limit"),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.items", "The events, each with its event, recipient, timestamp and message headers."),
            ("json.paging", "Where the next page of events is."),
        ],
    },
];
