//! How one operation of a REST service is described: once, as data, from
//! which the workflow domain's spec, the builder's guide and the request
//! itself are all made, so the three can never disagree.
//!
//! An operation names the HTTP verb and the path under the service's API,
//! each of its inputs with where it goes (the path, the query or the
//! body) and what kind of value it takes, the values it always sends, what
//! kind of action it is, and what it gives back.

use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::workflows::data::FieldName;
use ianua_domain::domains::workflows::integration::form::FormGroup;
use ianua_domain::domains::workflows::integration::guide::OperationGuide;
use ianua_domain::domains::workflows::integration::{
    AccountNeed, InputNeed, InputSpec, IntegrationKey, OperationKey, OperationSpec,
    OperationSpecParams,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::validation::distinct::first_repeat;
use ianua_domain::types::DeclaredAction;

use crate::describe::{GuideText, InputText, guide};
use crate::form::{Ask, FormText, PreviewText, Suggested};

/// The HTTP verb an operation calls with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Retrieves a resource without sending a request body.
    Get,
    /// Submits a payload for the service to process.
    Post,
    /// Submits partial changes to a resource.
    Patch,
    /// Supplies a replacement representation for a resource.
    Put,
    /// Requests removal of the addressed resource.
    Delete,
}

impl Verb {
    /// The verb as the client sends it.
    #[must_use]
    pub fn method(self) -> reqwest::Method {
        match self {
            Self::Get => reqwest::Method::GET,
            Self::Post => reqwest::Method::POST,
            Self::Patch => reqwest::Method::PATCH,
            Self::Put => reqwest::Method::PUT,
            Self::Delete => reqwest::Method::DELETE,
        }
    }

    /// The verb as an API description names it, such as `get`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
            Self::Patch => "patch",
            Self::Put => "put",
            Self::Delete => "delete",
        }
    }

    /// Whether a call with it sends a JSON body.
    #[must_use]
    pub fn sends_body(self) -> bool {
        match self {
            Self::Post | Self::Patch | Self::Put => true,
            Self::Get | Self::Delete => false,
        }
    }
}

/// A value an operation's body always carries. An input sent under the
/// same name takes its place when the step gives one, so a fixed value
/// may stand as the safe default, as Discord's no mentions does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fixed {
    /// Text, such as `closed`.
    Text(&'static str),
    /// True or false.
    Flag(bool),
    /// An empty list, such as Discord's `allowed_mentions.parse` pinging
    /// no one.
    NoItems,
}

/// How an operation's body is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// A JSON object, each body input and fixed value under its name.
    Object,
    /// A JSON Patch: a list of `add` changes, each body input and fixed
    /// value at the path its name gives, such as `/fields/System.Title`,
    /// sent as `application/json-patch+json`.
    JsonPatch,
    /// A form, each body input and fixed value under its name, a list as
    /// the name repeated and any other values as JSON text, sent as
    /// `application/x-www-form-urlencoded`, as Twilio and Mailgun take it.
    Form,
    /// A whole mail message in a JSON object's `raw`, base64url, as Gmail
    /// takes it: each body input named with a capital a header, such as
    /// `To`, refused when it holds a line break; the input named `text`
    /// the plain-text body; any other body input beside `raw`.
    Mail,
}

impl Shape {
    /// The content type a body of this shape is sent as.
    #[must_use]
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Object | Self::Mail => "application/json",
            Self::JsonPatch => "application/json-patch+json",
            Self::Form => "application/x-www-form-urlencoded",
        }
    }
}

/// One part of an operation's path under the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    /// A fixed part, such as `issues`.
    Fixed(&'static str),
    /// The input of this name written as two parts, `first/second`, such as
    /// a GitHub repository's `owner/name`, placed as two parts.
    Pair(&'static str),
    /// The input of this name, as one part.
    Input(&'static str),
    /// The input `input` as one part, after the fixed `prefix`, as Azure
    /// DevOps writes a work item's type as `$Bug`.
    Prefixed {
        /// What goes before the value.
        prefix: &'static str,
        /// The input whose value follows.
        input: &'static str,
    },
    /// The input `input` as one part, before the fixed `suffix`, as Twilio
    /// names a message `{sid}.json`.
    Suffixed {
        /// The input whose value goes first.
        input: &'static str,
        /// What follows the value.
        suffix: &'static str,
    },
    /// The input of this name, a path of its own such as a file's or a
    /// branch's, each of its parts checked and escaped on its own.
    Slashed(&'static str),
}

/// Where an input goes in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// In the path, through a [`Segment`].
    Path,
    /// In the query string.
    Query,
    /// Encoded in the payload according to the operation's shape.
    Body,
    /// Asked in the form only, to narrow another input's picker, and never
    /// sent: Trello's board, whose lists the list picker offers when a card
    /// is created on a list alone.
    Form,
}

/// What kind of value an input takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A string value supplied by the workflow step.
    Text,
    /// A whole number above zero, such as an issue's number.
    Count,
    /// A list of text, such as labels. In the query it is joined with
    /// commas.
    TextList,
    /// A list of text sent in the query with its name once per item, as
    /// PagerDuty takes `statuses[]=triggered&statuses[]=acknowledged`.
    RepeatedList,
    /// A list of whole numbers above zero, such as ClickUp's people's ids.
    CountList,
    /// True or false.
    Flag,
    /// Any values, handed on as they are.
    Values,
}

/// The service name of an object input whose own names are laid over a
/// JSON object body itself, rather than under a name of their own.
pub const SPREAD: &str = ".";

/// What ends a part of a service name that is a list holding one object:
/// `requests[].addSheet.properties.title` sets
/// `{"requests": [{"addSheet": {"properties": {"title": ..}}}]}`, as Google
/// Sheets takes the one change of a batch update.
pub const ONE_ITEM: &str = "[]";

/// One input of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Its name in the workflow.
    pub name: &'static str,
    /// Its name in the service's request, usually the same. In a JSON
    /// object body each dot opens an object inside, as `fields.summary`
    /// does, and [`SPREAD`] lays an object's own names over the body
    /// itself, as Salesforce takes a record's fields; in a JSON Patch body
    /// it is the path changed, such as `/fields/System.Title`.
    pub wire: &'static str,
    /// Whether the operation runs without it.
    pub need: InputNeed,
    /// Where it goes.
    pub place: Place,
    /// What kind of value it takes.
    pub kind: Kind,
    /// What it means, for the builder.
    pub meaning: &'static str,
    /// How the builder asks for it.
    pub form: FormText,
}

impl Field {
    /// An input the operation does not run without.
    #[must_use]
    pub const fn required(
        name: &'static str,
        kind: Kind,
        place: Place,
        meaning: &'static str,
    ) -> Self {
        Self {
            name,
            wire: name,
            need: InputNeed::Required,
            place,
            kind,
            meaning,
            form: FormText::plain(),
        }
    }

    /// An input the operation runs without.
    #[must_use]
    pub const fn optional(
        name: &'static str,
        kind: Kind,
        place: Place,
        meaning: &'static str,
    ) -> Self {
        Self {
            need: InputNeed::Optional,
            ..Self::required(name, kind, place, meaning)
        }
    }

    /// The same input, named `wire` in the service's request.
    #[must_use]
    pub const fn sent_as(self, wire: &'static str) -> Self {
        Self { wire, ..self }
    }

    /// The same input, asked for as `form` says.
    #[must_use]
    pub const fn asked(self, form: FormText) -> Self {
        Self { form, ..self }
    }

    /// The same input, asked for with `ask`.
    #[must_use]
    pub const fn asked_with(self, ask: Ask) -> Self {
        let form = FormText { ask, ..self.form };
        Self { form, ..self }
    }

    /// The same input, showing `example` while its box is empty.
    #[must_use]
    pub const fn example(self, example: &'static str) -> Self {
        let form = FormText {
            example: Some(example),
            ..self.form
        };
        Self { form, ..self }
    }

    /// The same input, kept folded under more options.
    #[must_use]
    pub const fn more_options(self) -> Self {
        let form = FormText {
            group: FormGroup::MoreOptions,
            ..self.form
        };
        Self { form, ..self }
    }

    /// The block its kind suggests.
    #[must_use]
    pub const fn suggested(&self) -> Suggested {
        match self.kind {
            Kind::Text | Kind::TextList | Kind::RepeatedList | Kind::CountList => Suggested::Text,
            Kind::Count => Suggested::Number,
            Kind::Flag => Suggested::Switch,
            Kind::Values => Suggested::KeyValues,
        }
    }
}

/// One operation a service offers a workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operation {
    /// Its key, such as `create-issue`.
    pub key: &'static str,
    /// Its name for people.
    pub title: &'static str,
    /// What it does.
    pub description: &'static str,
    /// What kind of action it is.
    pub effect: DeclaredAction,
    /// The verb it calls with.
    pub verb: Verb,
    /// Its path under the API.
    pub path: &'static [Segment],
    /// Its inputs.
    pub fields: &'static [Field],
    /// Values its body always carries, such as `state: closed`.
    pub fixed: &'static [(&'static str, Fixed)],
    /// Values its query always carries, such as `api-version: 7.1`.
    pub query: &'static [(&'static str, &'static str)],
    /// How its body is written.
    pub shape: Shape,
    /// What it gives back: each value's path in the output and what it is.
    pub outputs: &'static [(&'static str, &'static str)],
}

impl Operation {
    /// How the operation is described to workflows: acting through an
    /// account, handed data up to `ceiling`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when a name breaks its rules.
    pub fn spec(
        &self,
        integration: &IntegrationKey,
        ceiling: DataClassLevel,
    ) -> Result<OperationSpec, DomainError> {
        let inputs = self
            .fields
            .iter()
            .map(|field| Ok(InputSpec::new(FieldName::new(field.name)?, field.need)))
            .collect::<Result<Vec<_>, DomainError>>()?;
        OperationSpec::new(OperationSpecParams {
            integration: integration.clone(),
            operation: OperationKey::new(self.key)?,
            inputs,
            effect: self.effect,
            account: AccountNeed::Account,
            ceiling,
        })
    }

    /// How the operation is explained to the people building workflows.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when a text breaks its rules.
    pub fn guide(&self, preview: Option<&PreviewText>) -> Result<OperationGuide, DomainError> {
        let inputs: Vec<InputText<'_>> = self
            .fields
            .iter()
            .map(|field| InputText {
                name: field.name,
                meaning: field.meaning,
                suggested: field.suggested(),
                form: field.form,
            })
            .collect();
        guide(&GuideText {
            operation: self.key,
            title: self.title,
            description: self.description,
            inputs: &inputs,
            outputs: self.outputs,
            preview,
        })
    }
}

/// What a set of operations tells the workflow domain and its builders.
pub struct Described {
    /// One spec per operation, in order.
    pub specs: Vec<OperationSpec>,
    /// One guide per operation, in order.
    pub guides: Vec<OperationGuide>,
}

/// What `described` makes guides from: the operations, and how some of
/// their steps are previewed.
pub struct Offered<'a> {
    /// The operations, in order.
    pub operations: &'a [&'static Operation],
    /// How some of them are previewed, each naming its operation.
    pub previews: &'a [PreviewText],
}

/// Every spec and guide of `offered`, as `integration` offers them with
/// data up to `ceiling`.
///
/// # Errors
///
/// - `DomainError::Validation` when a name or text breaks its rules.
/// - `DomainError::Infrastructure` when a preview names an operation not
///   offered, or one twice.
pub fn described(
    offered: &Offered<'_>,
    integration: &IntegrationKey,
    ceiling: DataClassLevel,
) -> Result<Described, DomainError> {
    ensure_previews_offered(offered)?;
    let mut specs = Vec::new();
    let mut guides = Vec::new();
    for operation in offered.operations {
        let preview = offered
            .previews
            .iter()
            .find(|preview| preview.operation == operation.key);
        specs.push(operation.spec(integration, ceiling)?);
        guides.push(operation.guide(preview)?);
    }
    Ok(Described { specs, guides })
}

/// Refuses previews naming an operation not offered, or one twice.
fn ensure_previews_offered(offered: &Offered<'_>) -> Result<(), DomainError> {
    let stray = offered.previews.iter().find(|preview| {
        !offered
            .operations
            .iter()
            .any(|operation| operation.key == preview.operation)
    });
    if let Some(stray) = stray {
        return Err(DomainError::infra_msg(format!(
            "{} is previewed but not offered",
            stray.operation
        )));
    }
    if first_repeat(offered.previews.iter().map(|preview| preview.operation)).is_some() {
        return Err(DomainError::infra_msg("an operation is previewed twice"));
    }
    Ok(())
}
