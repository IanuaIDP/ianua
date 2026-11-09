//! Checking a service's operations against the service's own published
//! API description (OpenAPI 3 or Swagger 2), for its tests: every
//! operation calls an endpoint the service describes, with only parameters
//! and body properties it knows, always sending those it requires,
//! promising only outputs its answer carries and a success status it
//! answers with.
//!
//! A full description is large, so each service keeps an extract of the
//! endpoints its operations use beside its manifest. Setting the service's
//! refresh variable to a downloaded full description rewrites the extract
//! before the check, and `git diff` on it shows what the service changed.

mod paths;

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use ianua_domain::domains::workflows::integration::InputNeed;
use ianua_domain::shared::errors::DomainError;
use serde_json::{Map, Value, json};

use self::paths::{Fit, fills, matches, our_parts, parts};
use crate::rest::operation::{ONE_ITEM, Operation, Place, SPREAD, Shape};

/// How deep a body's nested names are kept. A schema that refers to itself
/// stops here, and what lies below is taken as known.
const DEEPEST_BODY_PATH: usize = 6;

/// The last part of a kept path whose object does not name what it holds.
const ANY_NAME: &str = "*";

/// A service's description, as its tests check against it.
pub struct Description {
    /// Where the extract is kept, usually beside the crate's manifest.
    pub kept: PathBuf,
    /// The variable naming a full description to refresh the extract from.
    pub setting: &'static str,
    /// The parts of every path template the account's API address already
    /// holds, such as `["rest", "api", "3"]` for Jira or `["{}"]` for
    /// Azure DevOps' organization; a placeholder is written `{}`.
    pub lead: &'static [&'static str],
}

impl Description {
    /// The extract, refreshed first from the full description the setting
    /// names, when it names one.
    ///
    /// # Errors
    ///
    /// Infrastructure failure when the description cannot be read, parsed or
    /// saved, or a full description does not contain a paths object.
    pub fn extract<'a>(
        &self,
        operations: impl IntoIterator<Item = &'a Operation>,
    ) -> Result<Value, DomainError> {
        if let Ok(source) = std::env::var(self.setting) {
            let full = read_description(&PathBuf::from(source))?;
            let fresh = self.extracted(&full, operations)?;
            let written = serde_json::to_string_pretty(&fresh).map_err(DomainError::infra)?;
            std::fs::write(&self.kept, format!("{written}\n")).map_err(DomainError::infra)?;
            return Ok(fresh);
        }
        read_description(&self.kept)
    }

    /// Every way `operations` do not fit `extract`, each named; empty when
    /// they all fit.
    #[must_use]
    pub fn misfits<'a>(
        &self,
        operations: impl IntoIterator<Item = &'a Operation>,
        extract: &Value,
    ) -> Vec<String> {
        operations
            .into_iter()
            .flat_map(|operation| self.misfits_of(operation, extract))
            .collect()
    }

    /// How many endpoints the extract keeps.
    #[must_use]
    pub fn kept_endpoints(extract: &Value) -> usize {
        extract["endpoints"].as_object().map_or(0, Map::len)
    }

    /// How many distinct endpoints `operations` call.
    #[must_use]
    pub fn called_endpoints<'a>(operations: impl IntoIterator<Item = &'a Operation>) -> usize {
        let mut called: Vec<String> = operations
            .into_iter()
            .map(|operation| format!("{} {:?}", operation.verb.name(), our_parts(operation.path)))
            .collect();
        called.sort();
        called.dedup();
        called.len()
    }

    /// Our path with the lead before it, ready to match a template.
    fn ours(&self, operation: &Operation) -> Vec<String> {
        self.lead
            .iter()
            .map(|part| (*part).to_owned())
            .chain(our_parts(operation.path))
            .collect()
    }

    /// What the operations use of `full`.
    fn extracted<'a>(
        &self,
        full: &Value,
        operations: impl IntoIterator<Item = &'a Operation>,
    ) -> Result<Value, DomainError> {
        let paths = description_paths(full)?;
        let operations: Vec<&Operation> = operations.into_iter().collect();
        let nested = nested_tops(&operations);
        let mut endpoints = BTreeMap::new();
        for operation in operations {
            let ours = self.ours(operation);
            let offered = |(template, item): &(&String, &Value), fit: Fit| {
                item.get(operation.verb.name()).is_some() && fit(&ours, &parts(template))
            };
            let found = paths
                .iter()
                .find(|entry| offered(entry, matches))
                .or_else(|| paths.iter().find(|entry| offered(entry, fills)));
            let Some((template, item)) = found else {
                continue;
            };
            endpoints.insert(
                format!("{} {template}", operation.verb.name()),
                endpoint(full, item, &item[operation.verb.name()], &nested),
            );
        }
        Ok(json!({
            "version": full["info"]["version"],
            "endpoints": endpoints,
        }))
    }

    /// Why `operation` does not fit `extract`.
    fn misfits_of(&self, operation: &Operation, extract: &Value) -> Vec<String> {
        let ours = self.ours(operation);
        let kept = |(key, _): &(&String, &Value), fit: Fit| {
            key.split_once(' ').is_some_and(|(verb, template)| {
                verb == operation.verb.name() && fit(&ours, &parts(template))
            })
        };
        let found = extract["endpoints"].as_object().and_then(|endpoints| {
            endpoints
                .iter()
                .find(|entry| kept(entry, matches))
                .or_else(|| endpoints.iter().find(|entry| kept(entry, fills)))
        });
        let Some((_, endpoint)) = found else {
            return vec![format!(
                "{}: the service has no such endpoint",
                operation.key
            )];
        };
        let mut wrong = Vec::new();
        wrong.extend(query_misfits(operation, endpoint));
        if matches!(operation.shape, Shape::Object | Shape::Form) {
            wrong.extend(body_misfits(operation, endpoint));
        }
        wrong.extend(output_misfits(operation, endpoint));
        wrong
    }
}

/// Reads a JSON description while preserving the underlying I/O or parse failure.
fn read_description(path: &std::path::Path) -> Result<Value, DomainError> {
    let written = std::fs::read_to_string(path).map_err(DomainError::infra)?;
    serde_json::from_str(&written).map_err(DomainError::infra)
}

/// Requires the paths object used to locate operations in a full description.
fn description_paths(full: &Value) -> Result<&Map<String, Value>, DomainError> {
    full["paths"].as_object().ok_or_else(|| {
        DomainError::infra(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the description has paths",
        ))
    })
}

/// The query inputs and fixed query values the endpoint does not take.
fn query_misfits(operation: &Operation, endpoint: &Value) -> Vec<String> {
    operation
        .fields
        .iter()
        .filter(|field| field.place == Place::Query)
        .map(|field| field.wire)
        .chain(operation.query.iter().map(|(name, _)| *name))
        .filter(|name| endpoint["query"].get(*name).is_none())
        .map(|name| {
            format!(
                "{}: the service takes no query parameter {name}",
                operation.key
            )
        })
        .collect()
}

/// Body names the endpoint does not know, and required ones not always
/// sent. A nested name is checked by its first part here, and part by part
/// by [`nested_misfits`] where the extract keeps the body's nested names.
fn body_misfits(operation: &Operation, endpoint: &Value) -> Vec<String> {
    let known = names(endpoint.get("body"));
    let mut sent = body_names(operation, InputNeed::Optional);
    sent.sort_unstable();
    sent.dedup();
    let always = body_names(operation, InputNeed::Required);
    let sent = sent.into_iter();
    let mut wrong: Vec<String> = sent
        .filter(|name| !known.iter().any(|known| known == name))
        .map(|name| format!("{}: the service's body has no {name}", operation.key))
        .collect();
    wrong.extend(
        names(endpoint.get("body_required"))
            .into_iter()
            .filter(|needed| !always.contains(&needed.as_str()))
            .map(|needed| {
                format!(
                    "{}: the service requires {needed}, which is not always sent",
                    operation.key
                )
            }),
    );
    wrong.extend(nested_misfits(operation, endpoint));
    wrong
}

/// Nested body names the endpoint does not know, part by part. Nothing
/// when the extract keeps no nested names for it.
fn nested_misfits(operation: &Operation, endpoint: &Value) -> Vec<String> {
    let Some(kept) = endpoint.get("body_paths") else {
        return Vec::new();
    };
    let kept = names(Some(kept));
    body_wires(operation)
        .filter(|wire| is_nested(wire) && !path_known(&kept, wire))
        .map(|wire| format!("{}: the service's body has no {wire}", operation.key))
        .collect()
}

/// Every name `operation` puts in its body, as the service reads it.
fn body_wires(operation: &Operation) -> impl Iterator<Item = &'static str> + '_ {
    operation
        .fields
        .iter()
        .filter(|field| field.place == Place::Body)
        .map(|field| field.wire)
        .chain(operation.fixed.iter().map(|(name, _)| *name))
}

/// Whether `wire` opens an object inside the body: not a JSON Patch path,
/// and not a record's fields laid over the body.
fn is_nested(wire: &str) -> bool {
    wire != SPREAD && !wire.starts_with('/') && wire.contains('.')
}

/// The first part of every nested name `operations` send, which are the
/// only properties whose nested names the extract needs to keep.
fn nested_tops(operations: &[&Operation]) -> HashSet<String> {
    operations
        .iter()
        .flat_map(|operation| body_wires(operation))
        .filter(|wire| is_nested(wire))
        .filter_map(|wire| wire.split('.').next())
        .map(|first| first.strip_suffix(ONE_ITEM).unwrap_or(first).to_owned())
        .collect()
}

/// Whether `kept` knows `wire`, or an object above it that does not name
/// what it holds.
fn path_known(kept: &[String], wire: &str) -> bool {
    let parts: Vec<&str> = wire
        .split('.')
        .map(|part| part.strip_suffix(ONE_ITEM).unwrap_or(part))
        .collect();
    let holds = |path: String| kept.contains(&path);
    holds(parts.join("."))
        || (0..parts.len()).any(|len| holds(joined(&parts[..len].join("."), ANY_NAME)))
}

/// `name` under the path `at`, which is empty at the body's own level.
fn joined(at: &str, name: &str) -> String {
    match at {
        "" => name.to_owned(),
        _ => format!("{at}.{name}"),
    }
}

/// Top-level body names, including fixed values and the requested field requirements.
fn body_names(operation: &Operation, need: InputNeed) -> Vec<&'static str> {
    let top = |name: &'static str| {
        let first = name.split('.').next().unwrap_or(name);
        first.strip_suffix(ONE_ITEM).unwrap_or(first)
    };
    operation
        .fields
        .iter()
        .filter(|field| {
            field.place == Place::Body
                && (need == InputNeed::Optional || field.need == InputNeed::Required)
        })
        .map(|field| top(field.wire))
        .chain(operation.fixed.iter().map(|(name, _)| top(name)))
        .collect()
}

/// Outputs the answer does not carry, and promised statuses it never
/// answers with.
fn output_misfits(operation: &Operation, endpoint: &Value) -> Vec<String> {
    let answer = names(endpoint.get("answer"));
    let statuses = names(endpoint.get("statuses"));
    operation
        .outputs
        .iter()
        .filter_map(|(path, meaning)| {
            match path
                .strip_prefix("json.")
                .and_then(|rest| rest.split('.').next())
            {
                Some(first) => (!answer.iter().any(|known| known == first))
                    .then(|| format!("{}: the service's answer has no {first}", operation.key)),
                None => unanswered_status(operation, path, meaning, &statuses),
            }
        })
        .collect()
}

/// Why the status output at `path` promises a success status the service
/// never answers with, if it does.
fn unanswered_status(
    operation: &Operation,
    path: &str,
    meaning: &str,
    statuses: &[String],
) -> Option<String> {
    let promised = (path == "status")
        .then(|| promised_status(meaning))
        .flatten()?;
    (!statuses.iter().any(|status| status == promised)).then(|| {
        format!(
            "{}: the service answers {}, never {promised}",
            operation.key,
            statuses.join(" or ")
        )
    })
}

/// `value` with every `$ref` into the description followed.
fn resolved<'a>(root: &'a Value, mut value: &'a Value) -> &'a Value {
    while let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        let Some(found) = reference
            .strip_prefix('#')
            .and_then(|pointer| root.pointer(pointer))
        else {
            break;
        };
        value = found;
    }
    value
}

/// The properties `schema` names, through `allOf`, `oneOf` and `anyOf`,
/// and of its items when it is a list.
fn properties(root: &Value, schema: &Value, into: &mut Vec<String>) {
    let schema = resolved(root, schema);
    if let Some(items) = schema.get("items") {
        properties(root, items, into);
    }
    if let Some(own) = schema.get("properties").and_then(Value::as_object) {
        into.extend(own.keys().cloned());
    }
    for combined in ["allOf", "oneOf", "anyOf"] {
        for part in schema
            .get(combined)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            properties(root, part, into);
        }
    }
}

/// One walk over a request body's schema, gathering its nested names into
/// `found` and resolving references against the description at `root`.
struct PathWalk<'a> {
    found: &'a mut Vec<String>,
    root: &'a Value,
}

impl PathWalk<'_> {
    /// Gathers every nested name `schema` holds or requires under `at`,
    /// through `allOf`, `oneOf`, `anyOf` and lists, to `depth` more levels:
    /// PagerDuty's description requires an incident body's `type` without
    /// listing it. An object that does not name what it holds, or anything
    /// below the last level, is kept as `at.*`.
    fn walk(&mut self, schema: &Value, at: &str, depth: usize) {
        if depth == 0 {
            self.found.push(joined(at, ANY_NAME));
            return;
        }
        let root = self.root;
        let schema = resolved(root, schema);
        if let Some(items) = schema.get("items") {
            self.walk(items, at, depth);
        }
        for (name, property) in schema
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let path = joined(at, name);
            self.walk(property, &path, depth.saturating_sub(1));
            self.found.push(path);
        }
        let required = names(schema.get("required"));
        self.found
            .extend(required.iter().map(|name| joined(at, name)));
        self.alternatives(schema, at, depth);
        if holds_unnamed(schema) {
            self.found.push(joined(at, ANY_NAME));
        }
    }

    fn alternatives(&mut self, schema: &Value, at: &str, depth: usize) {
        for combined in ["allOf", "oneOf", "anyOf"] {
            for part in schema
                .get(combined)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                self.walk(part, at, depth);
            }
        }
    }
}

/// Whether `schema` is an object that does not name all it may hold.
fn holds_unnamed(schema: &Value) -> bool {
    let open = schema
        .get("additionalProperties")
        .is_some_and(|extra| *extra != Value::Bool(false));
    let unnamed = ["properties", "items", "allOf", "oneOf", "anyOf"]
        .iter()
        .all(|shape| schema.get(*shape).is_none());
    let object = matches!(
        schema.get("type").and_then(Value::as_str),
        None | Some("object")
    );
    open || (unnamed && object)
}

/// The properties `schema` requires: its own, those of every `allOf` part,
/// and those every object alternative of a `oneOf` or `anyOf` requires.
fn required(root: &Value, schema: &Value) -> Vec<String> {
    let schema = resolved(root, schema);
    let mut needed: Vec<String> = names(schema.get("required"));
    for part in schema
        .get("allOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        needed.extend(required(root, part));
    }
    for combined in ["oneOf", "anyOf"] {
        needed.extend(required_by_alternatives(root, schema.get(combined)));
    }
    needed.sort();
    needed.dedup();
    needed
}

/// Names required by every object alternative, keeping the first alternative's order.
fn required_by_alternatives(root: &Value, combined: Option<&Value>) -> Vec<String> {
    let alternatives: Vec<Vec<String>> = combined
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|part| resolved(root, part))
        .filter(|part| part.get("properties").is_some())
        .map(|part| required(root, part))
        .collect();
    let Some((first, rest)) = alternatives.split_first() else {
        return Vec::new();
    };
    first
        .iter()
        .filter(|name| rest.iter().all(|other| other.contains(name)))
        .cloned()
        .collect()
}

/// The text values of a JSON list.
fn names(list: Option<&Value>) -> Vec<String> {
    list.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// One endpoint as the extract keeps it: its query parameters, its body's
/// properties and required ones, its success statuses and the properties
/// of those answers. Parameters are read from the path item and the
/// operation; a Swagger 2 body from its `formData` or `body` parameters.
fn endpoint(root: &Value, item: &Value, described: &Value, nested: &HashSet<String>) -> Value {
    let mut fields = EndpointFields {
        nested: Some(nested.clone()),
        ..EndpointFields::default()
    };
    let parameters = item["parameters"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(described["parameters"].as_array().into_iter().flatten());
    for parameter in parameters {
        fields.read_parameter(root, parameter);
    }
    let content = &resolved(root, &described["requestBody"])["content"];
    for schema in content
        .as_object()
        .into_iter()
        .flatten()
        .map(|(_, written)| &written["schema"])
        .filter(|schema| !schema.is_null())
    {
        fields.read_body(root, schema);
    }
    fields.finish(root, described)
}

/// Query and body fields accumulated from Swagger parameters and OpenAPI bodies.
#[derive(Default)]
struct EndpointFields {
    query: BTreeMap<String, bool>,
    body: Vec<String>,
    body_required: Vec<String>,
    body_paths: Vec<String>,
    nested: Option<HashSet<String>>,
}

impl EndpointFields {
    /// Reads one resolved Swagger parameter without changing its wire name.
    fn read_parameter(&mut self, root: &Value, parameter: &Value) {
        let parameter = resolved(root, parameter);
        let name = parameter["name"].as_str().unwrap_or_default().to_owned();
        let needed = parameter["required"].as_bool().unwrap_or(false);
        match parameter["in"].as_str() {
            Some("query") => {
                self.query.insert(name, needed);
            }
            Some("formData") => {
                if needed {
                    self.body_required.push(name.clone());
                }
                self.body.push(name);
            }
            Some("body") => self.read_body(root, &parameter["schema"]),
            _ => {}
        }
    }

    /// Adds a body's declared properties and requirements across schema alternatives.
    fn read_body(&mut self, root: &Value, schema: &Value) {
        properties(root, schema, &mut self.body);
        self.body_required.extend(required(root, schema));
        let mut paths = PathWalk {
            found: &mut self.body_paths,
            root,
        };
        paths.walk(schema, "", DEEPEST_BODY_PATH);
    }

    /// Deduplicates body names and joins the endpoint's successful response description.
    fn finish(mut self, root: &Value, described: &Value) -> Value {
        self.body.sort();
        self.body.dedup();
        self.body_required.sort();
        self.body_required.dedup();
        let (statuses, answered) = answers(root, described);
        let mut written = json!({
            "query": self.query,
            "body": self.body,
            "body_required": self.body_required,
            "statuses": statuses,
            "answer": answered,
        });
        let paths = self.kept_paths();
        if !paths.is_empty() {
            written["body_paths"] = json!(paths);
        }
        written
    }

    /// The nested names under a property some step sends a nested name of,
    /// so an extract holds no more than the checks read.
    fn kept_paths(&self) -> Vec<String> {
        let Some(nested) = &self.nested else {
            return Vec::new();
        };
        let mut paths: Vec<String> = self
            .body_paths
            .iter()
            .filter(|path| {
                path.split('.')
                    .next()
                    .is_some_and(|first| nested.contains(first))
            })
            .cloned()
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }
}

/// Every success status `described` answers with, and the properties of
/// those answers, in OpenAPI 3's `content` or Swagger 2's `schema`.
fn answers(root: &Value, described: &Value) -> (Vec<String>, Vec<String>) {
    let mut statuses = Vec::new();
    let mut answered = Vec::new();
    for (status, response) in described["responses"].as_object().into_iter().flatten() {
        if !status.starts_with('2') {
            continue;
        }
        statuses.push(status.clone());
        let response = resolved(root, response);
        let schema = response
            .get("content")
            .and_then(|content| content.get("application/json"))
            .and_then(|json| json.get("schema"))
            .or_else(|| response.get("schema"));
        if let Some(schema) = schema {
            properties(root, schema, &mut answered);
        }
    }
    answered.sort();
    answered.dedup();
    (statuses, answered)
}

/// The success status a status output's description promises, such as
/// `201` in "201 when the issue was opened".
fn promised_status(description: &str) -> Option<&str> {
    description
        .split(|c: char| !c.is_ascii_digit())
        .find(|word| word.len() == 3 && word.starts_with('2'))
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::DeclaredAction;

    use super::*;
    use crate::rest::operation::{Field, Kind, Segment, Verb};

    /// A slashed input may fill a template's last placeholder, taking the
    /// fixed parts before it; a fixed part never matches a placeholder.
    #[test]
    fn a_slashed_input_may_fill_the_last_placeholder() {
        let delete = ["repos", "{}", "{}", "git", "refs", "heads", "{..}"];

        assert!(matches(
            &delete,
            &parts("/repos/{owner}/{repo}/git/refs/{ref}")
        ));
        assert!(!matches(
            &delete,
            &parts("/repos/{owner}/{repo}/git/{ref}/heads/{x}")
        ));
        assert!(!matches(
            &["repos", "{}", "{}", "issues"],
            &parts("/repos/{owner}/{repo}/pulls")
        ));
    }

    /// Gmail's `{userId}` takes the fixed `me` a step always sends, but only
    /// as a whole placeholder: `{id}.json` takes no fixed part.
    #[test]
    fn a_fixed_part_may_fill_a_whole_placeholder() {
        let ours = ["gmail", "v1", "users", "me", "labels"].map(str::to_owned);

        assert!(!matches(&ours, &parts("/gmail/v1/users/{userId}/labels")));
        assert!(fills(&ours, &parts("/gmail/v1/users/{userId}/labels")));
        assert!(!fills(
            &ours,
            &parts("/gmail/v1/users/{userId}.json/labels")
        ));
    }

    /// A small description: opening an item needs a `title` and answers
    /// `201` with its `number`; listing takes a `state` query.
    fn sample_description() -> Value {
        json!({
            "info": { "version": "1" },
            "paths": {
                "/items": {
                    "post": {
                        "requestBody": { "content": { "application/json": { "schema": {
                            "type": "object",
                            "properties": { "title": {}, "labels": {} },
                            "required": ["title"]
                        } } } },
                        "responses": { "201": { "content": { "application/json": { "schema": {
                            "$ref": "#/components/schemas/item"
                        } } } } }
                    },
                    "get": {
                        "parameters": [{ "name": "state", "in": "query" }],
                        "responses": { "200": { "description": "the items" } }
                    }
                }
            },
            "components": { "schemas": { "item": { "properties": { "number": {} } } } }
        })
    }

    fn sample() -> Description {
        Description {
            kept: PathBuf::from("unused"),
            setting: "UNUSED",
            lead: &[],
        }
    }

    const PLANTED_FIELDS: &[Field] = &[
        Field::optional("title", Kind::Text, Place::Body, "Sometimes sent."),
        Field::optional("labelz", Kind::TextList, Place::Body, "Misspelt."),
        Field::optional("colour", Kind::Text, Place::Query, "Not taken."),
    ];

    const PLANTED: Operation = Operation {
        key: "planted",
        title: "Planted",
        description: "A step with every mistake.",
        effect: DeclaredAction::Undeclared,
        verb: Verb::Post,
        path: &[Segment::Fixed("items")],
        fields: PLANTED_FIELDS,
        fixed: &[],
        query: &[("api-version", "9")],
        shape: Shape::Object,
        outputs: &[
            ("json.count", "Not in the answer."),
            ("status", "The status, 204 when done."),
        ],
    };

    /// A deliberately mismatched step produces diagnostics for unknown
    /// body and query fields, an optional required title, unsupported
    /// output and status, and a path absent from the service description.
    #[test]
    fn a_planted_step_with_every_mistake_is_caught() {
        let nowhere = Operation {
            path: &[Segment::Fixed("teleport")],
            ..PLANTED
        };
        let extract = sample()
            .extracted(&sample_description(), [&PLANTED])
            .unwrap();

        let caught = sample().misfits([&PLANTED], &extract).join("\n");
        let lost = sample().misfits([&nowhere], &extract);

        for mistake in [
            "labelz",
            "colour",
            "api-version",
            "requires title",
            "count",
            "never 204",
        ] {
            assert!(
                caught.contains(mistake),
                "{mistake} was not caught in:\n{caught}"
            );
        }
        assert!(lost[0].contains("no such endpoint"));
    }

    /// A body described three levels deep, with one object that does not
    /// name what it holds.
    fn nested_description() -> Value {
        json!({
            "info": { "version": "1" },
            "paths": { "/things": { "post": {
                "requestBody": { "content": { "application/json": { "schema": {
                    "type": "object",
                    "properties": { "data": { "type": "object", "properties": {
                        "name": { "type": "string" },
                        "notes": { "type": "array", "items": {
                            "type": "object",
                            "properties": { "text": { "type": "string" } }
                        } },
                        "extras": { "type": "object", "additionalProperties": true }
                    } } }
                } } } },
                "responses": { "201": { "description": "made" } }
            } } }
        })
    }

    fn sending(fields: &'static [Field]) -> Operation {
        Operation {
            key: "make-thing",
            title: "Make a thing",
            description: "Makes a thing.",
            effect: DeclaredAction::Undeclared,
            verb: Verb::Post,
            path: &[Segment::Fixed("things")],
            fields,
            fixed: &[],
            query: &[],
            shape: Shape::Object,
            outputs: &[("status", "The status, 201.")],
        }
    }

    /// Asana's body wraps everything in `data`. A misspelt name inside it
    /// is caught, though `data` itself is a name the service knows.
    #[test]
    fn a_wrong_name_inside_a_known_object_is_caught() {
        const FIELDS: &[Field] =
            &[Field::required("name", Kind::Text, Place::Body, "Its name.").sent_as("data.nmae")];
        let wrong = sending(FIELDS);
        let extract = sample().extracted(&nested_description(), [&wrong]).unwrap();

        let caught = sample().misfits([&wrong], &extract).join("\n");

        assert!(caught.contains("has no data.nmae"), "{caught}");
    }

    /// Names that are there pass: through a list's one item, and anywhere
    /// inside an object that does not name what it holds.
    #[test]
    fn names_the_service_knows_pass_at_every_depth() {
        const FIELDS: &[Field] = &[
            Field::required("name", Kind::Text, Place::Body, "Its name.").sent_as("data.name"),
            Field::optional("note", Kind::Text, Place::Body, "A note.")
                .sent_as("data.notes[].text"),
            Field::optional("colour", Kind::Text, Place::Body, "Its colour.")
                .sent_as("data.extras.colour"),
        ];
        let right = sending(FIELDS);
        let extract = sample().extracted(&nested_description(), [&right]).unwrap();

        assert!(sample().misfits([&right], &extract).is_empty());
    }

    /// An extract refreshed before nested names were kept still works: its
    /// nested names are checked by their first part alone.
    #[test]
    fn an_extract_without_nested_names_checks_the_first_part() {
        const FIELDS: &[Field] =
            &[Field::required("name", Kind::Text, Place::Body, "Its name.").sent_as("data.nmae")];
        let step = sending(FIELDS);
        let mut extract = sample().extracted(&nested_description(), [&step]).unwrap();
        extract["endpoints"]["post /things"]
            .as_object_mut()
            .unwrap()
            .remove("body_paths");

        assert!(sample().misfits([&step], &extract).is_empty());
    }

    /// A step keeping to the description has nothing said against it.
    #[test]
    fn a_step_keeping_to_the_description_passes() {
        const OPEN: Operation = Operation {
            key: "open-item",
            fields: &[
                Field::required("title", Kind::Text, Place::Body, "Its title."),
                Field::optional("labels", Kind::TextList, Place::Body, "Its labels."),
            ],
            query: &[],
            outputs: &[
                ("json.number", "Its number."),
                ("status", "The status, 201 when opened."),
            ],
            ..PLANTED
        };
        let extract = sample().extracted(&sample_description(), [&OPEN]).unwrap();

        assert!(sample().misfits([&OPEN], &extract).is_empty());
    }

    /// Azure DevOps writes a placeholder as `${type}` and Twilio as
    /// `{Sid}.json`: each matches an input with the same fixed text around
    /// it, and nothing else.
    #[test]
    fn a_placeholder_keeps_the_fixed_text_around_it() {
        assert!(matches(
            &["{}", "{}", "_apis", "wit", "workitems", "${}"],
            &parts("/{organization}/{project}/_apis/wit/workitems/${type}")
        ));
        assert!(matches(
            &["Accounts", "{}", "Messages", "{}.json"],
            &parts("/Accounts/{AccountSid}/Messages/{Sid}.json")
        ));
        assert!(!matches(
            &["Accounts", "{}", "Messages", "{}"],
            &parts("/Accounts/{AccountSid}/Messages/{Sid}.json")
        ));
        assert!(!matches(
            &["Accounts", "{}", "Messages.json"],
            &parts("/Accounts/{AccountSid}/{Resource}.json")
        ));
    }
}
