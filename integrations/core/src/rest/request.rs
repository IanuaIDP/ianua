//! A step's call built from its operation and its arguments: the address
//! with every part checked and escaped, the query, and the body.

use ianua_domain::domains::workflows::data::FlowData;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_domain::domains::workflows::integration::InputNeed;
use serde_json::{Map, Value, json};

use crate::ServiceEndpoint;
use crate::answer::failed;
use crate::arguments::{
    argument, count_list, optional_flag, optional_text, optional_values, required_count, text_list,
};
use crate::rest::mail::mail;
use crate::rest::names::{pair, slashed};
use crate::rest::operation::{
    Field, Fixed, Kind, ONE_ITEM, Operation, Place, SPREAD, Segment, Shape,
};

/// The call a step makes.
#[derive(Debug, PartialEq)]
pub struct Call {
    /// The address, query included.
    pub url: url::Url,
    /// The body's values, for a verb that sends one: a form's as a flat
    /// object, each list one name repeated.
    pub body: Option<Value>,
    /// How the body is written.
    pub shape: Shape,
}

impl Call {
    /// The body as sent, in its shape.
    #[must_use]
    pub fn payload(&self) -> Option<String> {
        let body = self.body.as_ref()?;
        Some(match self.shape {
            Shape::Object | Shape::JsonPatch | Shape::Mail => body.to_string(),
            Shape::Form => form(body),
        })
    }
}

/// A step's call with every input checked and placed, waiting only for the
/// address the account reaches.
#[derive(Debug)]
pub struct Prepared {
    parts: Vec<String>,
    query: Vec<(String, String)>,
    body: Option<Value>,
    shape: Shape,
}

impl Prepared {
    /// The call under `endpoint`.
    ///
    /// # Errors
    ///
    /// A failed outcome when a part of the path cannot be placed in the
    /// address.
    pub fn at(self, endpoint: &ServiceEndpoint) -> Result<Call, ActionOutcome> {
        let segments: Vec<&str> = self.parts.iter().map(String::as_str).collect();
        let mut url = endpoint.url(&segments)?;
        for (name, value) in &self.query {
            url.query_pairs_mut().append_pair(name, value);
        }
        Ok(Call {
            url,
            body: self.body,
            shape: self.shape,
        })
    }
}

/// The call `operation` makes with `arguments`, checked before the account
/// is reached, so a step that cannot be sent never uses its credential.
///
/// # Errors
///
/// A failed outcome when a required input is missing, an input is not the
/// kind of value it takes, or a name cannot be placed in the address.
pub fn prepare(operation: &Operation, arguments: &FlowData) -> Result<Prepared, ActionOutcome> {
    let parts = path(operation, arguments)?;
    if parts
        .iter()
        .any(|part| matches!(part.as_str(), "" | "." | ".."))
    {
        return Err(failed(
            "a name the step gave cannot be placed in the service's address",
        ));
    }
    let body = match operation.verb.sends_body() {
        true => Some(body(operation, arguments)?),
        false => None,
    };
    Ok(Prepared {
        parts,
        query: query(operation, arguments)?,
        body,
        shape: operation.shape,
    })
}

/// The call `operation` makes with `arguments`, under `endpoint`.
///
/// # Errors
///
/// A failed outcome when a required input is missing, an input is not the
/// kind of value it takes, or a name cannot be placed in the address.
pub fn call(
    operation: &Operation,
    endpoint: &ServiceEndpoint,
    arguments: &FlowData,
) -> Result<Call, ActionOutcome> {
    prepare(operation, arguments)?.at(endpoint)
}

/// The parts of the path, each to be escaped on its own.
fn path(operation: &Operation, arguments: &FlowData) -> Result<Vec<String>, ActionOutcome> {
    let mut parts = Vec::new();
    for segment in operation.path {
        match segment {
            Segment::Fixed(part) => parts.push((*part).to_owned()),
            Segment::Pair(name) => {
                let written = required(arguments, name)?;
                let (first, second) = pair(name, &written)?;
                parts.extend([first.to_owned(), second.to_owned()]);
            }
            Segment::Input(name) => parts.push(path_value(operation, arguments, name)?),
            Segment::Prefixed { prefix, input } => {
                parts.push(format!(
                    "{prefix}{}",
                    path_value(operation, arguments, input)?
                ));
            }
            Segment::Suffixed { input, suffix } => {
                parts.push(format!(
                    "{}{suffix}",
                    path_value(operation, arguments, input)?
                ));
            }
            Segment::Slashed(name) => {
                let written = required(arguments, name)?;
                parts.extend(slashed(name, &written)?.into_iter().map(str::to_owned));
            }
        }
    }
    Ok(parts)
}

/// The value of the path input `name`, as text: a count as its digits.
fn path_value(
    operation: &Operation,
    arguments: &FlowData,
    name: &str,
) -> Result<String, ActionOutcome> {
    let counted = operation
        .fields
        .iter()
        .any(|field| field.name == name && field.kind == Kind::Count);
    match counted {
        true => Ok(required_count(arguments, name)?.to_string()),
        false => required(arguments, name),
    }
}

/// The required text argument `name`.
fn required(arguments: &FlowData, name: &str) -> Result<String, ActionOutcome> {
    optional_text(arguments, name)?
        .filter(|text| !text.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| failed(&format!("the {name} is missing")))
}

/// The operation's fixed query values and every query input the step gave.
fn query(
    operation: &Operation,
    arguments: &FlowData,
) -> Result<Vec<(String, String)>, ActionOutcome> {
    let mut pairs: Vec<(String, String)> = operation
        .query
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    for field in fields_at(operation, Place::Query) {
        let Some(value) = value_of(field, arguments)? else {
            continue;
        };
        match (field.kind, value) {
            (Kind::RepeatedList, Value::Array(items)) => pairs.extend(
                items
                    .iter()
                    .map(|item| (field.wire.to_owned(), query_text(item))),
            ),
            (_, value) => pairs.push((field.wire.to_owned(), query_text(&value))),
        }
    }
    Ok(pairs)
}

/// A query value as a service reads it: text as it is, a list joined by
/// commas.
fn query_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

/// The JSON body, in the operation's shape: every body input the step
/// gave, and the operation's fixed values.
fn body(operation: &Operation, arguments: &FlowData) -> Result<Value, ActionOutcome> {
    let entries = body_entries(operation, arguments)?;
    let entries = with_fixed(entries, operation.fixed);
    shape_body(entries, operation.shape)
}

/// Reads supplied body fields and checks that a spread value is an object.
fn body_entries(
    operation: &Operation,
    arguments: &FlowData,
) -> Result<Vec<(&'static str, Value)>, ActionOutcome> {
    let mut entries: Vec<(&str, Value)> = Vec::new();
    for field in fields_at(operation, Place::Body) {
        let Some(value) = value_of(field, arguments)? else {
            continue;
        };
        if field.wire == SPREAD && !value.is_object() {
            return Err(failed(&format!(
                "{} must be an object of names",
                field.name
            )));
        }
        entries.push((field.wire, value));
    }
    Ok(entries)
}

/// Adds fixed body fields only when the caller supplied no value for that wire name.
fn with_fixed<'a>(
    mut entries: Vec<(&'a str, Value)>,
    fixed: &[(&'a str, Fixed)],
) -> Vec<(&'a str, Value)> {
    for (name, value) in fixed {
        if entries.iter().any(|(given, _)| given == name) {
            continue;
        }
        let value = match value {
            Fixed::Text(text) => json!(text),
            Fixed::Flag(flag) => json!(flag),
            Fixed::NoItems => json!([]),
        };
        entries.push((name, value));
    }
    entries
}

/// Encodes validated body entries in the service's declared payload shape.
fn shape_body(entries: Vec<(&str, Value)>, shape: Shape) -> Result<Value, ActionOutcome> {
    Ok(match shape {
        Shape::Object => {
            let mut object = Map::new();
            for (name, value) in entries {
                nest(&mut object, name, value);
            }
            Value::Object(object)
        }
        Shape::Form => Value::Object(
            entries
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        ),
        Shape::JsonPatch => Value::Array(
            entries
                .into_iter()
                .map(|(path, value)| json!({ "op": "add", "path": path, "value": value }))
                .collect(),
        ),
        Shape::Mail => mail(entries)?,
    })
}

/// `value` placed in `object` at `name`, where each dot opens an object
/// inside: `fields.project.key` sets `{"fields": {"project": {"key": ..}}}`,
/// beside whatever else those objects hold, and a part ending in
/// [`ONE_ITEM`] opens the one object of a list. At [`SPREAD`], an object's
/// own names are laid over `object` itself.
fn nest(object: &mut Map<String, Value>, name: &str, value: Value) {
    let value = match (name, value) {
        (SPREAD, Value::Object(entries)) => {
            object.extend(entries);
            return;
        }
        (_, value) => value,
    };
    let Some((first, rest)) = name.split_once('.') else {
        object.insert(name.to_owned(), value);
        return;
    };
    if let Some(inner) = opened(object, first) {
        nest(inner, rest, value);
    }
}

/// The object `part` of `object` opens: the one object of a list when the
/// part ends in [`ONE_ITEM`], or else an object under the part's name.
fn opened<'a>(
    object: &'a mut Map<String, Value>,
    part: &str,
) -> Option<&'a mut Map<String, Value>> {
    match part.strip_suffix(ONE_ITEM) {
        Some(list) => only_item(object, list),
        None => inner_object(object, part),
    }
}

/// The object under `name` in `object`, made when there is none.
fn inner_object<'a>(
    object: &'a mut Map<String, Value>,
    name: &str,
) -> Option<&'a mut Map<String, Value>> {
    let inner = object
        .entry(name.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if !inner.is_object() {
        *inner = Value::Object(Map::new());
    }
    inner.as_object_mut()
}

/// The one object of the list under `name` in `object`, made when there is
/// none, so every input under the same list fills the same item.
fn only_item<'a>(
    object: &'a mut Map<String, Value>,
    name: &str,
) -> Option<&'a mut Map<String, Value>> {
    let list = object.entry(name.to_owned()).or_insert_with(|| json!([{}]));
    let holds_one_object = list
        .as_array()
        .is_some_and(|items| items.len() == 1 && items.first().is_some_and(Value::is_object));
    if !holds_one_object {
        *list = json!([{}]);
    }
    list.as_array_mut()?.first_mut()?.as_object_mut()
}

/// The flat object `body` written as a form: a list as its name repeated
/// once per item, text as it is, and any other value as JSON text.
fn form(body: &Value) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in body.as_object().into_iter().flatten() {
        match value {
            Value::Array(items) => {
                for item in items {
                    form.append_pair(name, &form_text(item));
                }
            }
            other => {
                form.append_pair(name, &form_text(other));
            }
        }
    }
    form.finish()
}

/// One form value as text: text as it is, anything else as JSON.
fn form_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The operation's inputs that go at `place`.
fn fields_at(operation: &Operation, place: Place) -> impl Iterator<Item = &Field> {
    operation
        .fields
        .iter()
        .filter(move |field| field.place == place)
}

/// The value the step gave `field`, as JSON, or none for an optional input
/// it left out.
///
/// # Errors
///
/// A failed outcome when a required input is missing or the value is not
/// the kind the input takes.
fn value_of(field: &Field, arguments: &FlowData) -> Result<Option<Value>, ActionOutcome> {
    let given = match field.kind {
        Kind::Text => optional_text(arguments, field.name)?.map(|text| json!(text)),
        Kind::Count => match argument(arguments, field.name) {
            Some(_) => Some(json!(required_count(arguments, field.name)?)),
            None => None,
        },
        Kind::TextList | Kind::RepeatedList => {
            let items = text_list(arguments, field.name)?;
            (!items.is_empty()).then(|| json!(items))
        }
        Kind::CountList => {
            let items = count_list(arguments, field.name)?;
            (!items.is_empty()).then(|| json!(items))
        }
        Kind::Flag => optional_flag(arguments, field.name)?.map(Value::Bool),
        Kind::Values => optional_values(arguments, field.name)?,
    };
    match (given, field.need) {
        (Some(Value::String(text)), InputNeed::Required) if text.trim().is_empty() => {
            Err(failed(&format!("the {} is missing", field.name)))
        }
        (Some(value), _) => Ok(Some(value)),
        (None, InputNeed::Optional) => Ok(None),
        (None, InputNeed::Required) => Err(failed(&format!("the {} is missing", field.name))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::data::FieldName;
    use ianua_domain::types::{ActionClass, DeclaredAction};

    use super::*;
    use crate::rest::operation::Verb;

    /// A sample operation using every kind of segment, place and value.
    const SAMPLE: Operation = Operation {
        key: "sample",
        title: "Sample",
        description: "Uses every part of a description.",
        effect: DeclaredAction::Declared(ActionClass::Write),
        verb: Verb::Post,
        path: &[
            Segment::Fixed("spaces"),
            Segment::Pair("space"),
            Segment::Input("item"),
            Segment::Slashed("file"),
        ],
        fields: &[
            Field::required("space", Kind::Text, Place::Path, "The space, as a/b."),
            Field::required("item", Kind::Count, Place::Path, "The item's number."),
            Field::required("file", Kind::Text, Place::Path, "A file's path."),
            Field::optional("tags", Kind::TextList, Place::Query, "Tags."),
            Field::required("title", Kind::Text, Place::Body, "A title."),
            Field::optional("draft", Kind::Flag, Place::Body, "Draft or not."),
            Field::optional("extra", Kind::Values, Place::Body, "Anything.").sent_as("data"),
        ],
        fixed: &[
            ("state", Fixed::Text("open")),
            ("notify", Fixed::Flag(true)),
        ],
        query: &[("api-version", "7.1")],
        shape: Shape::Object,
        outputs: &[("status", "The status.")],
    };

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

    fn complete() -> Vec<(&'static str, FlowData)> {
        vec![
            ("space", text("acme/web")),
            ("item", FlowData::number(7.0).unwrap()),
            ("file", text("docs/README.md")),
            ("tags", FlowData::list(vec![text("a"), text("b")]).unwrap()),
            ("title", text("Hello")),
            ("draft", FlowData::bool(false)),
            ("extra", arguments(vec![("k", text("v"))])),
        ]
    }

    fn made(given: Vec<(&str, FlowData)>) -> Result<Call, ActionOutcome> {
        let api = ServiceEndpoint::at("https://api.example.test/v1/").unwrap();
        call(&SAMPLE, &api, &arguments(given))
    }

    /// Every input lands where its description says: the pair and the
    /// slashed path as parts of the address, the list joined in the query,
    /// the body under the service's names, with the fixed values.
    #[test]
    fn every_input_lands_where_its_description_says() {
        let made = made(complete()).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.example.test/v1/spaces/acme/web/7/docs/README.md?api-version=7.1&tags=a%2Cb"
        );
        assert_eq!(
            made.body,
            Some(json!({
                "title": "Hello",
                "draft": false,
                "data": { "k": "v" },
                "state": "open",
                "notify": true
            }))
        );
    }

    /// Dotted names build objects inside the body, side by side, as Jira's
    /// `fields` holds a project, a summary and a type.
    #[test]
    fn dotted_names_build_objects_inside_the_body() {
        const NESTED: Operation = Operation {
            path: &[Segment::Fixed("issue")],
            fields: &[
                Field::required("project", Kind::Text, Place::Body, "The project.")
                    .sent_as("fields.project.key"),
                Field::required("summary", Kind::Text, Place::Body, "The summary.")
                    .sent_as("fields.summary"),
            ],
            fixed: &[("fields.issuetype.name", Fixed::Text("Task"))],
            query: &[],
            ..SAMPLE
        };
        let api = ServiceEndpoint::at("https://api.example.test/").unwrap();
        let given = arguments(vec![
            ("project", text("OPS")),
            ("summary", text("Disk full")),
        ]);

        let made = call(&NESTED, &api, &given).unwrap();

        assert_eq!(
            made.body,
            Some(json!({ "fields": {
                "project": { "key": "OPS" },
                "summary": "Disk full",
                "issuetype": { "name": "Task" }
            } }))
        );
    }

    /// A name part ending in `[]` is a list holding one object, which every
    /// input under it fills together, as Google Sheets takes the one change
    /// of a batch update.
    #[test]
    fn a_list_part_holds_one_object_the_inputs_share() {
        const BATCHED: Operation = Operation {
            path: &[Segment::Fixed("batch")],
            fields: &[
                Field::required("title", Kind::Text, Place::Body, "The tab's name.")
                    .sent_as("requests[].addSheet.properties.title"),
                Field::optional("place", Kind::Count, Place::Body, "Where it goes.")
                    .sent_as("requests[].addSheet.properties.index"),
            ],
            fixed: &[],
            query: &[],
            ..SAMPLE
        };
        let api = ServiceEndpoint::at("https://api.example.test/").unwrap();
        let given = arguments(vec![
            ("title", text("March")),
            ("place", FlowData::number(2.0).unwrap()),
        ]);

        let made = call(&BATCHED, &api, &given).unwrap();

        assert_eq!(
            made.body,
            Some(json!({ "requests": [
                { "addSheet": { "properties": { "title": "March", "index": 2 } } }
            ] }))
        );
    }

    /// A record's fields are laid over the body itself, beside the other
    /// inputs, as Salesforce takes them; anything but an object there
    /// builds no call.
    #[test]
    fn a_spread_object_is_laid_over_the_body() {
        const SPREAD_OUT: Operation = Operation {
            path: &[Segment::Fixed("record")],
            fields: &[
                Field::required("fields", Kind::Values, Place::Body, "The fields.").sent_as(SPREAD),
                Field::optional("owner", Kind::Text, Place::Body, "The owner.").sent_as("OwnerId"),
            ],
            fixed: &[],
            query: &[],
            ..SAMPLE
        };
        let api = ServiceEndpoint::at("https://api.example.test/").unwrap();
        let record = FlowData::map(vec![
            (FieldName::new("Name").unwrap(), text("Acme")),
            (FieldName::new("Industry").unwrap(), text("Retail")),
        ])
        .unwrap();
        let given = arguments(vec![("fields", record), ("owner", text("005A"))]);
        let crooked = arguments(vec![("fields", text("Acme"))]);

        let made = call(&SPREAD_OUT, &api, &given).unwrap();

        assert_eq!(
            made.body,
            Some(json!({ "Name": "Acme", "Industry": "Retail", "OwnerId": "005A" }))
        );
        assert!(call(&SPREAD_OUT, &api, &crooked).is_err());
    }

    /// A JSON Patch body lists one `add` per value, sent as its own content
    /// type, and a prefixed input carries its prefix, as Azure DevOps opens
    /// a work item of type `$Bug`.
    #[test]
    fn a_json_patch_body_lists_each_change() {
        const PATCH: Operation = Operation {
            path: &[
                Segment::Fixed("workitems"),
                Segment::Prefixed {
                    prefix: "$",
                    input: "type",
                },
            ],
            fields: &[
                Field::required("type", Kind::Text, Place::Path, "The type."),
                Field::required("title", Kind::Text, Place::Body, "The title.")
                    .sent_as("/fields/System.Title"),
            ],
            fixed: &[],
            query: &[],
            shape: Shape::JsonPatch,
            ..SAMPLE
        };
        let api = ServiceEndpoint::at("https://dev.example.test/acme/").unwrap();
        let given = arguments(vec![("type", text("Bug")), ("title", text("Crash"))]);

        let made = call(&PATCH, &api, &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://dev.example.test/acme/workitems/$Bug"
        );
        assert_eq!(made.shape.content_type(), "application/json-patch+json");
        assert_eq!(
            made.body,
            Some(json!([{ "op": "add", "path": "/fields/System.Title", "value": "Crash" }]))
        );
    }

    /// A message update whose form repeats media and keeps a dotted name flat.
    const FORM: Operation = Operation {
        path: &[
            Segment::Fixed("Messages"),
            Segment::Suffixed {
                input: "message",
                suffix: ".json",
            },
        ],
        fields: &[
            Field::required("message", Kind::Text, Place::Path, "The message."),
            Field::required("media", Kind::TextList, Place::Body, "Media.").sent_as("MediaUrl"),
            Field::optional("variables", Kind::Values, Place::Body, "Values.")
                .sent_as("content.variables"),
        ],
        fixed: &[("Status", Fixed::Text("canceled"))],
        query: &[],
        shape: Shape::Form,
        ..SAMPLE
    };

    /// A form names each value flat, repeats a list's name once per item and
    /// writes other values as JSON text, and a suffixed input carries its
    /// suffix, as Twilio sends a message to `Messages/{sid}.json`.
    #[test]
    fn a_form_body_repeats_lists_and_writes_values_as_text() {
        let api = ServiceEndpoint::at("https://api.example.test/Accounts/AC1").unwrap();
        let given = arguments(vec![
            ("message", text("SM1")),
            (
                "media",
                FlowData::list(vec![text("a b"), text("c&d")]).unwrap(),
            ),
            ("variables", arguments(vec![("1", text("Ann"))])),
        ]);

        let made = call(&FORM, &api, &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.example.test/Accounts/AC1/Messages/SM1.json"
        );
        assert_eq!(
            made.shape.content_type(),
            "application/x-www-form-urlencoded"
        );
        let payload = made.payload().unwrap();
        let mut pairs: Vec<&str> = payload.split('&').collect();
        pairs.sort_unstable();
        assert_eq!(
            pairs,
            [
                "MediaUrl=a+b",
                "MediaUrl=c%26d",
                "Status=canceled",
                "content.variables=%7B%221%22%3A%22Ann%22%7D"
            ]
        );
    }

    /// A missing title, traversal path or nonnumeric item identifier
    /// prevents request construction.
    #[test]
    fn a_missing_input_a_crooked_path_or_a_wrong_kind_builds_no_call() {
        let without_title: Vec<_> = complete()
            .into_iter()
            .filter(|(name, _)| *name != "title")
            .collect();
        let climbing: Vec<_> = complete()
            .into_iter()
            .map(|(name, value)| match name {
                "file" => (name, text("../../etc/passwd")),
                _ => (name, value),
            })
            .collect();
        let worded: Vec<_> = complete()
            .into_iter()
            .map(|(name, value)| match name {
                "item" => (name, text("seven")),
                _ => (name, value),
            })
            .collect();

        for refused in [without_title, climbing, worded] {
            assert!(matches!(made(refused), Err(ActionOutcome::Failed(_))));
        }
    }

    /// An item operation combining repeated query states with numeric body values.
    const LISTS: Operation = Operation {
        path: &[Segment::Fixed("items")],
        fields: &[
            Field::optional("states", Kind::RepeatedList, Place::Query, "States.")
                .sent_as("statuses[]"),
            Field::optional("people", Kind::CountList, Place::Body, "People."),
        ],
        fixed: &[],
        query: &[],
        ..SAMPLE
    };

    /// Builds validated numeric input values for list serialization checks.
    fn numbers(items: &[f64]) -> FlowData {
        FlowData::list(
            items
                .iter()
                .map(|n| FlowData::number(*n).unwrap())
                .collect(),
        )
        .unwrap()
    }

    /// PagerDuty's statuses are sent with their name once per item, and
    /// ClickUp's people as numbers; a person named with a word builds no
    /// call.
    #[test]
    fn repeated_lists_and_number_lists_are_sent_as_the_service_reads_them() {
        let api = ServiceEndpoint::at("https://api.example.test/").unwrap();
        let given = arguments(vec![
            (
                "states",
                FlowData::list(vec![text("triggered"), text("acknowledged")]).unwrap(),
            ),
            ("people", numbers(&[7.0, 9.0])),
        ]);
        let worded = arguments(vec![("people", FlowData::list(vec![text("ann")]).unwrap())]);

        let made = call(&LISTS, &api, &given).unwrap();

        assert_eq!(
            made.url.as_str(),
            "https://api.example.test/items?statuses%5B%5D=triggered&statuses%5B%5D=acknowledged"
        );
        assert_eq!(made.body, Some(json!({ "people": [7, 9] })));
        assert!(call(&LISTS, &api, &worded).is_err());
    }

    /// A required title containing only spaces fails request construction.
    #[test]
    fn a_blank_required_body_input_builds_no_call() {
        let blank: Vec<_> = complete()
            .into_iter()
            .map(|(name, value)| match name {
                "title" => (name, text("   ")),
                _ => (name, value),
            })
            .collect();

        assert!(matches!(made(blank), Err(ActionOutcome::Failed(_))));
    }
}
