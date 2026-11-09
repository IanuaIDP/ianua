//! How the company steps' inputs are asked for in a workflow's builder:
//! what each means, its label, how it is filled, and where the form shows
//! it.

use ianua_domain::domains::workflows::integration::company::{
    ACTION_INPUT, AGENT_INPUT, APP_INPUT, DATA_INPUT, DECISION_INPUT, EMAIL_INPUT, EVERY_INPUT,
    FIELD_INPUT, FORMAT_INPUT, GROUP_INPUT, HOURS_INPUT, KEY_INPUT, LEVEL_INPUT, MESSAGE_INPUT,
    MINUTES_INPUT, NAME_INPUT, OBJECT_INPUT, PERMISSIONS_INPUT, PERSON_INPUT, REASON_INPUT,
    REQUEST_INPUT, RESOURCE_INPUT, REVIEW_INPUT, REVIEWERS_INPUT, ROLE_INPUT, RUN_INPUT,
    SHARED_INPUT, SIGNAL_INPUT, SINCE_INPUT, SUGGESTIONS_INPUT, TITLE_INPUT, WHAT_INPUT,
};
use ianua_domain::domains::workflows::integration::form::{FormGroup, Tone};
use ianua_domain::shared::errors::DomainError;
use ianua_integration::describe::InputText;
use ianua_integration::form::{Ask, ChoiceText, FormText, Suggested};

/// The formats an audit pack may be written in.
const FORMATS: &[ChoiceText] = &[
    ChoiceText {
        value: "csv",
        label: "CSV",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "json",
        label: "JSON",
        tone: Tone::Neutral,
    },
];

/// The choices a request's decision offers.
const DECISIONS: &[ChoiceText] = &[
    ChoiceText {
        value: "approve",
        label: "Approve",
        tone: Tone::Success,
    },
    ChoiceText {
        value: "deny",
        label: "Deny",
        tone: Tone::Danger,
    },
];

/// The signals a person may be reported with.
const SIGNALS: &[ChoiceText] = &[
    ChoiceText {
        value: "risk_low",
        label: "Risk is low",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "risk_medium",
        label: "Risk is medium",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "risk_high",
        label: "Risk is high",
        tone: Tone::Danger,
    },
    ChoiceText {
        value: "password_compromised",
        label: "Password compromised",
        tone: Tone::Danger,
    },
    ChoiceText {
        value: "device_compromised",
        label: "Device compromised",
        tone: Tone::Danger,
    },
];

/// The choices how far back a reading step looks offers.
const SPANS: &[ChoiceText] = &[
    ChoiceText {
        value: "hour",
        label: "The last hour",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "day",
        label: "The last day",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "week",
        label: "The last week",
        tone: Tone::Neutral,
    },
    ChoiceText {
        value: "month",
        label: "The last 30 days",
        tone: Tone::Neutral,
    },
];

/// How one input is asked for: what it means, its label and how it is
/// filled.
struct InputWords {
    name: &'static str,
    meaning: &'static str,
    label: &'static str,
    ask: Ask,
}

/// How every company step's inputs are asked for.
const INPUT_WORDS: &[InputWords] = &[
    InputWords {
        name: PERSON_INPUT,
        meaning: "A person: their address or their user id.",
        label: "Person",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: GROUP_INPUT,
        meaning: "A group, by its id.",
        label: "Group",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: HOURS_INPUT,
        meaning: "For how many hours, from 1 to 720.",
        label: "For how many hours",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: REQUEST_INPUT,
        meaning: "An access request, by its id.",
        label: "Request",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: DECISION_INPUT,
        meaning: "approve or deny.",
        label: "Decision",
        ask: Ask::Choices(DECISIONS),
    },
    InputWords {
        name: REVIEWERS_INPUT,
        meaning: "The reviewers: addresses or user ids, as a list or separated by commas.",
        label: "Reviewers",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: AGENT_INPUT,
        meaning: "An agent, by its id.",
        label: "Agent",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: RUN_INPUT,
        meaning: "One of the agent's runs, by its id.",
        label: "Run",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: APP_INPUT,
        meaning: "An app, by its route's id.",
        label: "App",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: SINCE_INPUT,
        meaning: "How far back to look: hour, day, week or month; a day when left out.",
        label: "Since",
        ask: Ask::Choices(SPANS),
    },
    InputWords {
        name: WHAT_INPUT,
        meaning: "The kind of record, such as identity.user_status_changed; every kind when left out.",
        label: "Kind of record",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: FORMAT_INPUT,
        meaning: "The file's format: csv or json; csv when left out.",
        label: "Format",
        ask: Ask::Choices(FORMATS),
    },
    InputWords {
        name: FIELD_INPUT,
        meaning: "The field, such as orders.card_last4.",
        label: "Field",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: EMAIL_INPUT,
        meaning: "The address to invite.",
        label: "Email",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: NAME_INPUT,
        meaning: "The name the new account gets.",
        label: "Name",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: ROLE_INPUT,
        meaning: "The role accepting gives, by its id.",
        label: "Role",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: ACTION_INPUT,
        meaning: "The action asked about, such as read.",
        label: "Action",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: RESOURCE_INPUT,
        meaning: "The kind of thing asked about, such as invoices.",
        label: "Resource",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: OBJECT_INPUT,
        meaning: "One of them, by its key, such as inv-2026-0031; any of them when left out.",
        label: "Object",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: PERMISSIONS_INPUT,
        meaning: "The rights it gives, such as users:manage or invoices:approve, as a list or separated by commas.",
        label: "Rights",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: MINUTES_INPUT,
        meaning: "For how many minutes: break glass from 1 to the deployment's own limit, attack mode from 5 to 1440.",
        label: "For how many minutes",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: REASON_INPUT,
        meaning: "Why it is needed, kept on the audit trail.",
        label: "Reason",
        ask: Ask::LongText,
    },
    InputWords {
        name: DATA_INPUT,
        meaning: "The data to work on, such as an earlier step's answer; field paths are read from its root.",
        label: "Data",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: REVIEW_INPUT,
        meaning: "An access review, by its id.",
        label: "Review",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: SUGGESTIONS_INPUT,
        meaning: "A list of suggestions, each naming a person (address or user id) or an agent (its id), keep or remove as its suggest, and its reason.",
        label: "Suggestions",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: SIGNAL_INPUT,
        meaning: "What to tell: risk_low, risk_medium, risk_high, password_compromised or device_compromised.",
        label: "Signal",
        ask: Ask::Choices(SIGNALS),
    },
    InputWords {
        name: KEY_INPUT,
        meaning: "The API key, by its id.",
        label: "API key",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: EVERY_INPUT,
        meaning: "How many hours apart reminders go out, from 1 to 168.",
        label: "Every how many hours",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: SHARED_INPUT,
        meaning: "What the agent was given to reach, such as calendar:abc123.",
        label: "Given",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: TITLE_INPUT,
        meaning: "What the notice says in short, up to 200 characters.",
        label: "Title",
        ask: Ask::AsSuggested,
    },
    InputWords {
        name: MESSAGE_INPUT,
        meaning: "What else it says, up to 500 characters; nothing more when left out.",
        label: "Message",
        ask: Ask::LongText,
    },
    InputWords {
        name: LEVEL_INPUT,
        meaning: "How sensitive it is: internal, confidential or restricted.",
        label: "Level",
        ask: Ask::AsSuggested,
    },
];

/// How the input `name` is asked for, or why it cannot be: an input with no
/// words here, which a change here would cause.
pub(super) fn input_text(name: &'static str) -> Result<InputText<'static>, DomainError> {
    let words = INPUT_WORDS
        .iter()
        .find(|words| words.name == name)
        .ok_or_else(|| DomainError::infra_msg("a company step's input has no words"))?;
    let group = match name {
        SINCE_INPUT | WHAT_INPUT | OBJECT_INPUT | FORMAT_INPUT => FormGroup::MoreOptions,
        _ => FormGroup::Main,
    };
    let suggested = match name {
        HOURS_INPUT | MINUTES_INPUT | EVERY_INPUT => Suggested::Number,
        _ => Suggested::Text,
    };
    Ok(InputText {
        name,
        meaning: words.meaning,
        suggested,
        form: FormText {
            label: Some(words.label),
            ask: words.ask,
            group,
            ..FormText::plain()
        },
    })
}
