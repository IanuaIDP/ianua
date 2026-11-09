//! How the Protected apps integration explains each of its operations to a
//! workflow's builder: what each input means and how it is asked for, and
//! what every call gives back.

use ianua_domain::domains::workflows::integration::ROUTE_INPUT;
use ianua_domain::domains::workflows::integration::form::{FormGroup, InputStyle};
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::shared::errors::DomainError;
use ianua_integration::describe::{GuideText, InputText, guide};
use ianua_integration::form::{Ask, FormText, Suggested};

use crate::integrations::requests::{Body, Method};

/// What every call gives back.
const OUTPUTS: &[(&str, &str)] = &[
    ("status", "The status the app answered with, such as 200."),
    ("body", "The answer's body as text."),
    (
        "json",
        "The answer's body as values when it is JSON a workflow can hold, else null.",
    ),
];

/// How every operation is explained: one per method.
pub(super) fn guides_of() -> Result<Vec<OperationGuide>, DomainError> {
    Method::ALL.into_iter().map(guide_for).collect()
}

/// How the call with `method` is explained.
fn guide_for(method: Method) -> Result<OperationGuide, DomainError> {
    let verb = method.name().to_ascii_uppercase();
    let title = format!("{verb} on a protected app");
    let description = format!(
        "Sends one {verb} request to an app behind the gateway as the person the run acts for. The app's own rules decide whether they may."
    );
    let inputs = inputs_for(method);
    guide(&GuideText {
        operation: method.name(),
        title: &title,
        description: &description,
        inputs: &inputs,
        outputs: OUTPUTS,
        preview: None,
    })
}

/// The app destination, headers and optional JSON body the builder asks for.
fn inputs_for(method: Method) -> Vec<InputText<'static>> {
    let mut inputs = vec![
        app_input(),
        path_input(),
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

/// The route picker limits the destination to apps opened to workflows.
fn app_input() -> InputText<'static> {
    InputText {
        name: ROUTE_INPUT,
        meaning: "The app's route, one the company opened to workflows.",
        suggested: Suggested::Text,
        form: FormText {
            label: Some("App"),
            ask: Ask::AppPicker,
            ..FormText::plain()
        },
    }
}

/// The path field names the resource under the selected app's route.
fn path_input() -> InputText<'static> {
    InputText {
        name: "path",
        meaning: "The path on the app to call, starting with /.",
        suggested: Suggested::Text,
        form: FormText {
            label: Some("Path"),
            example: Some("/orders/7"),
            style: InputStyle::Monospace,
            ..FormText::plain()
        },
    }
}
