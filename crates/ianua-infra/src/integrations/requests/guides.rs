//! How the HTTP request integration explains each of its operations to a
//! workflow's builder: what each input means and how it is asked for, and
//! what every call gives back.

use ianua_domain::domains::workflows::integration::form::{FormGroup, InputStyle};
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::shared::errors::DomainError;
use ianua_integration::describe::{GuideText, InputText, guide};
use ianua_integration::form::{FormText, Suggested};

use crate::integrations::requests::{Access, Body, Method};

/// What every call gives back.
const OUTPUTS: &[(&str, &str)] = &[
    (
        "status",
        "The status the address answered with, such as 200.",
    ),
    ("body", "The answer's body as text."),
    (
        "json",
        "The answer's body as values when it is JSON a workflow can hold, else null.",
    ),
];

/// How every operation is explained: each method, bare and with an
/// account.
pub(super) fn guides_of() -> Result<Vec<OperationGuide>, DomainError> {
    Method::ALL
        .into_iter()
        .flat_map(|method| Access::ALL.into_iter().map(move |access| (method, access)))
        .map(|(method, access)| guide_for(method, access))
        .collect()
}

/// How the call with `method`, gone out as `access` says, is explained.
fn guide_for(method: Method, access: Access) -> Result<OperationGuide, DomainError> {
    let verb = method.name().to_ascii_uppercase();
    let operation = access.operation(method);
    let (title, how) = match access {
        Access::Open => (format!("{verb} request"), "with no credential".to_owned()),
        Access::WithAccount => (
            format!("{verb} request with an account"),
            "with the account's token, sent only to the origin the account is bound to".to_owned(),
        ),
    };
    let description = format!("Sends one {verb} request to the address the step names, {how}.");
    let inputs = inputs_for(method);
    guide(&GuideText {
        operation: &operation,
        title: &title,
        description: &description,
        inputs: &inputs,
        outputs: OUTPUTS,
        preview: None,
    })
}

/// The destination, headers and optional JSON body the builder asks for.
fn inputs_for(method: Method) -> Vec<InputText<'static>> {
    let mut inputs = vec![
        address_input(),
        InputText {
            name: "headers",
            meaning: "Named header values to send; the integration sets authorization and framing itself.",
            suggested: Suggested::KeyValues,
            form: FormText {
                group: FormGroup::MoreOptions,
                ..FormText::plain()
            },
        },
    ];
    if method.body() == Body::Json {
        inputs.push(InputText {
            name: "body",
            meaning: "The values sent as the JSON body.",
            suggested: Suggested::KeyValues,
            form: FormText::plain(),
        });
    }
    inputs
}

/// The address field shows the expected HTTP URL syntax.
fn address_input() -> InputText<'static> {
    InputText {
        name: "url",
        meaning: "The http or https address to call.",
        suggested: Suggested::Text,
        form: FormText {
            label: Some("Address"),
            example: Some("https://api.example.com/orders"),
            style: InputStyle::Monospace,
            ..FormText::plain()
        },
    }
}
