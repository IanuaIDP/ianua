//! How the Redis integration explains each of its operations to a
//! workflow's builder: what each input means and how it is asked for, and
//! what a call gives back.

use ianua_domain::domains::workflows::integration::ROUTE_INPUT;
use ianua_domain::domains::workflows::integration::form::{FormGroup, InputStyle};
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::shared::errors::DomainError;
use ianua_integration::describe::{GuideText, InputText, guide};
use ianua_integration::form::{Ask, FormText, Suggested};

use crate::command::Kind;

/// What every command gives back.
const OUTPUTS: &[(&str, &str)] = &[(
    "result",
    "What Redis answered: a text, a number, a list, or nothing when the key is missing.",
)];

/// The protected stream route used to reach Redis.
const ROUTE: InputText<'static> = InputText {
    name: ROUTE_INPUT,
    meaning: "The Redis's stream route, one the company opened to workflows.",
    suggested: Suggested::Text,
    form: FormText {
        label: Some("Redis"),
        ask: Ask::DataPicker,
        ..FormText::plain()
    },
};

/// Values sent after the Redis command's name, in the given order.
const ARGUMENTS: InputText<'static> = InputText {
    name: "arguments",
    meaning: "The command's arguments, in order, such as the key and a value.",
    suggested: Suggested::Text,
    form: FormText::plain(),
};

/// An optional Redis database number within the connected server.
const DATABASE: InputText<'static> = InputText {
    name: "database",
    meaning: "The database number; 0 when left out.",
    suggested: Suggested::Text,
    form: FormText {
        group: FormGroup::MoreOptions,
        ..FormText::plain()
    },
};

/// How every operation is explained: one per kind.
pub(super) fn guides_of() -> Result<Vec<OperationGuide>, DomainError> {
    [Kind::Read, Kind::Write]
        .into_iter()
        .map(guide_for)
        .collect()
}

/// How `kind` is explained.
fn guide_for(kind: Kind) -> Result<OperationGuide, DomainError> {
    let (title, description, example) = match kind {
        Kind::Read => (
            "Read from a protected Redis",
            "Runs one command that only reads, such as GET or HGETALL, on a company's Redis as the person the run acts for.",
            "HGETALL",
        ),
        Kind::Write => (
            "Change a protected Redis",
            "Runs one command on a company's Redis as the person the run acts for, with the login its stream route keeps. What it may change is what that login may.",
            "SET",
        ),
    };
    let inputs = [ROUTE, command_input(example), ARGUMENTS, DATABASE];
    guide(&GuideText {
        operation: kind.name(),
        title,
        description,
        inputs: &inputs,
        outputs: OUTPUTS,
        preview: None,
    })
}

/// Describes the command name with an example appropriate to its read or write kind.
fn command_input(example: &'static str) -> InputText<'static> {
    InputText {
        name: "command",
        meaning: "The command's name, such as GET.",
        suggested: Suggested::Text,
        form: FormText {
            label: Some("Command"),
            example: Some(example),
            style: InputStyle::Monospace,
            ..FormText::plain()
        },
    }
}
