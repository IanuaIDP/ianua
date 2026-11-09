//! Payments, refunds, invoices and subscriptions. Every step that moves
//! money or changes what a customer is billed is financial, so a workflow
//! is only published with an approval right before it.

use ianua_domain::domains::workflows::integration::form::Tone;
use ianua_domain::types::{ActionClass, DeclaredAction};
use ianua_integration::form::{Ask, ChoiceText};
use ianua_integration::rest::operation::{Field, Kind, Operation, Place, Segment, Shape, Verb};

use crate::operations::{CUSTOMERS, LIMIT};

/// Only those of one customer, in the query.
const OF_CUSTOMER: Field = Field::optional(
    "customer",
    Kind::Text,
    Place::Query,
    "Only those of this customer, by id.",
)
.asked_with(Ask::Picker(CUSTOMERS));

/// Why a payment is refunded.
const REASONS: &[ChoiceText] = &[
    ChoiceText {
        value: "requested_by_customer",
        label: "The customer asked",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "duplicate",
        label: "Charged twice",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "fraudulent",
        label: "Fraud",
        tone: Tone::Warning,
    },
];

/// Every billing operation.
pub(crate) const OPERATIONS: &[Operation] = &[
    Operation {
        key: "list-payments",
        title: "List payments",
        description: "Lists payments, newest first, or one customer's.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("payment_intents")],
        fields: &[OF_CUSTOMER, LIMIT],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.data",
                "The payments, each with its id, amount, currency and status.",
            ),
            ("json.has_more", "Whether there are more than were given."),
            ("status", "The status Stripe answered with."),
        ],
    },
    Operation {
        key: "get-payment",
        title: "Read a payment",
        description: "Reads a payment's amount, currency, status and customer.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("payment_intents"), Segment::Input("payment")],
        fields: &[Field::required(
            "payment",
            Kind::Text,
            Place::Path,
            "The payment's id, such as pi_3Mt...",
        )],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.id", "The payment's id."),
            (
                "json.amount",
                "Its amount, in the smallest unit of the currency.",
            ),
            ("json.currency", "Its currency, such as eur."),
            ("json.status", "Where it stands, such as succeeded."),
            ("json.customer", "The customer who paid."),
            ("status", "The status Stripe answered with."),
        ],
    },
    Operation {
        key: "refund-payment",
        title: "Refund a payment",
        description: "Gives a payment's money back, all of it or the amount given.",
        effect: DeclaredAction::Declared(ActionClass::Financial),
        verb: Verb::Post,
        path: &[Segment::Fixed("refunds")],
        fields: &[
            Field::required(
                "payment",
                Kind::Text,
                Place::Body,
                "The payment to refund, by id.",
            )
            .sent_as("payment_intent"),
            Field::optional(
                "amount",
                Kind::Count,
                Place::Body,
                "How much to give back, in the smallest unit of the currency, such as 500 for 5.00; all of it when not given.",
            ),
            Field::optional("reason", Kind::Text, Place::Body, "Why it is refunded.")
                .asked_with(Ask::Choices(REASONS)),
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.id", "The refund's id."),
            ("json.amount", "How much is given back."),
            (
                "json.status",
                "Where it stands, such as succeeded or pending.",
            ),
            ("status", "The status Stripe answered with."),
        ],
    },
    Operation {
        key: "list-invoices",
        title: "List invoices",
        description: "Lists invoices, newest first, or one customer's, or those in one state.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("invoices")],
        fields: &[
            OF_CUSTOMER,
            Field::optional(
                "state",
                Kind::Text,
                Place::Query,
                "Only those in this state: draft, open, paid, uncollectible or void.",
            )
            .sent_as("status"),
            LIMIT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.data",
                "The invoices, each with its id, amount due, status and hosted_invoice_url.",
            ),
            ("status", "The status Stripe answered with."),
        ],
    },
    Operation {
        key: "send-invoice",
        title: "Send an invoice",
        description: "Emails an open invoice to its customer, asking them to pay it.",
        effect: DeclaredAction::Declared(ActionClass::Financial),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("invoices"),
            Segment::Input("invoice"),
            Segment::Fixed("send"),
        ],
        fields: &[Field::required(
            "invoice",
            Kind::Text,
            Place::Path,
            "The invoice, by id.",
        )],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.status", "Where the invoice stands now."),
            (
                "json.hosted_invoice_url",
                "The page the customer pays it on.",
            ),
            ("status", "The status Stripe answered with."),
        ],
    },
    Operation {
        key: "list-subscriptions",
        title: "List subscriptions",
        description: "Lists subscriptions, or one customer's, or those in one state.",
        effect: DeclaredAction::Declared(ActionClass::Read),
        verb: Verb::Get,
        path: &[Segment::Fixed("subscriptions")],
        fields: &[
            OF_CUSTOMER,
            Field::optional(
                "state",
                Kind::Text,
                Place::Query,
                "Only those in this state, such as active, past_due or canceled.",
            )
            .sent_as("status"),
            LIMIT,
        ],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            (
                "json.data",
                "The subscriptions, each with its id, status and current_period_end.",
            ),
            ("status", "The status Stripe answered with."),
        ],
    },
    Operation {
        key: "cancel-subscription",
        title: "Cancel a subscription",
        description: "Ends a subscription at once, so the customer is billed for it no more.",
        effect: DeclaredAction::Declared(ActionClass::Financial),
        verb: Verb::Delete,
        path: &[
            Segment::Fixed("subscriptions"),
            Segment::Input("subscription"),
        ],
        fields: &[Field::required(
            "subscription",
            Kind::Text,
            Place::Path,
            "The subscription, by id.",
        )],
        fixed: &[],
        query: &[],
        shape: Shape::Form,
        outputs: &[
            ("json.status", "canceled, once it is."),
            ("status", "The status Stripe answered with."),
        ],
    },
];
