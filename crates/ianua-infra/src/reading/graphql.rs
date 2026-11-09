//! A GraphQL request body read into the depth, cost and fingerprint the
//! gateway's rules work on.
//!
//! A GraphQL request over HTTP is a JSON object carrying `query`, and
//! optionally `operationName` and `variables`. Anything else, a batch
//! included, is refused: costing is the whole control, and a body the
//! gateway cannot cost must not pass uncosted.
//!
//! Fragments are followed. A document that defines a fragment and spreads it
//! ten levels down is exactly as deep as one writing those levels out.
//! Following them is bounded twice: a fragment already being followed is
//! not followed again, so a cycle ends, and the walk stops once it has done
//! more work than any tenant's limit allows, so fragments spreading each
//! other twice over cannot make it run for ever. A walk cut short reports
//! the most cost there is, which every limit refuses.
//!
//! The body, its query and how deeply its brackets nest are bounded before
//! anything is parsed, so the parser never recurses past what the stack
//! holds.

use std::collections::{HashMap, HashSet};

use async_graphql_parser::types::{
    DocumentOperations, ExecutableDocument, FragmentDefinition, OperationType, Selection,
    SelectionSet,
};
use ianua_app::ports::proxy::GraphQlAnalyzer;
use ianua_domain::domains::proxy::request::graphql::{
    GraphQlOperation, MAX_ALLOWED_COMPLEXITY, MAX_ALLOWED_DEPTH, OperationKind,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::reading::messages::canonical;

/// The longest body read: a query with its variables.
const LARGEST_BODY: usize = 512 * 1024;

/// The longest query read.
const LONGEST_QUERY: usize = 128 * 1024;

/// How deeply brackets of any kind may nest in the query. Selections nest
/// at most [`MAX_ALLOWED_DEPTH`], and arguments inside them a little more.
const DEEPEST_NESTING: u32 = 128;

/// The most selections the walk visits before it stops counting.
const MOST_STEPS: u32 = 200_000;

/// Reads GraphQL request bodies.
#[derive(Debug, Default, Clone, Copy)]
pub struct DocumentGraphQlAnalyzer;

impl GraphQlAnalyzer for DocumentGraphQlAnalyzer {
    fn analyze(&self, body: &[u8]) -> Result<GraphQlOperation, DomainError> {
        let request = request_in(body)?;
        let document = async_graphql_parser::parse_query(&request.query).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-query-is-not-a-graphql",
                "the query is not a GraphQL document"
            ))
        })?;
        let (kind, selections) = operation_of(&document, request.operation_name.as_deref())?;
        let mut walk = Walk::over(&document);
        walk.selections(selections, 1);
        Ok(GraphQlOperation {
            kind,
            name: request.operation_name.clone(),
            depth: walk.depth,
            complexity: walk.cost(),
            fingerprint: fingerprint(&request),
        })
    }
}

/// A GraphQL request as it arrives over HTTP.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphQlRequest {
    query: String,
    #[serde(default, rename = "operationName")]
    operation_name: Option<String>,
    #[serde(default)]
    variables: Option<serde_json::Value>,
    /// Taken so a request carrying extensions is not refused, and never
    /// read: nothing here acts on them.
    #[serde(default, rename = "extensions")]
    _extensions: Option<serde::de::IgnoredAny>,
}

/// The request `body` holds, refused when it is too long, not one request,
/// or nests deeper than the parser may recurse.
fn request_in(body: &[u8]) -> Result<GraphQlRequest, DomainError> {
    if body.len() > LARGEST_BODY {
        return Err(DomainError::invalid(message!(
            "infra-the-graphql-request-is-too-long",
            "the GraphQL request is too long"
        )));
    }
    let request: GraphQlRequest = serde_json::from_slice(body).map_err(|_| {
        DomainError::invalid(message!(
            "infra-the-body-is-not-one-graphql",
            "the body is not one GraphQL request"
        ))
    })?;
    if request.query.len() > LONGEST_QUERY {
        return Err(DomainError::invalid(message!(
            "infra-the-graphql-query-is-too-long",
            "the GraphQL query is too long"
        )));
    }
    if nesting_of(&request.query) > DEEPEST_NESTING {
        return Err(DomainError::invalid(message!(
            "infra-the-graphql-query-nests-too-deeply",
            "the GraphQL query nests too deeply"
        )));
    }
    Ok(request)
}

/// The quotes a block string opens and closes with.
const BLOCK_QUOTE: &[u8] = b"\"\"\"";

/// A block string's closing quotes written out inside it.
const ESCAPED_BLOCK_QUOTE: &[u8] = b"\\\"\"\"";

/// Where the scanner is in the query's text.
#[derive(Clone, Copy)]
enum Lexing {
    /// In the document itself, where brackets count.
    Code,
    /// Inside a string.
    Text,
    /// Just after a backslash inside a string.
    Escaped,
    /// Inside a block string, up to its closing quotes.
    Block,
    /// Inside a comment, up to the end of the line.
    Comment,
}

/// How deeply brackets of any kind nest in `query`, outside strings, block
/// strings and comments.
fn nesting_of(query: &str) -> u32 {
    let bytes = query.as_bytes();
    let mut lexing = Lexing::Code;
    let mut depth: u32 = 0;
    let mut deepest: u32 = 0;
    let mut at: usize = 0;
    while let Some(rest) = bytes.get(at..).filter(|rest| !rest.is_empty()) {
        let (next, deeper, taken) = scanned(lexing, depth, rest);
        lexing = next;
        depth = deeper;
        deepest = deepest.max(depth);
        at = at.saturating_add(taken);
    }
    deepest
}

/// The scanner's place and the depth after reading the start of `rest`,
/// and how many bytes it read. A block string is read by its quotes, so a
/// lone quote inside one never throws the scanner out of step with the
/// parser and hides the brackets after it.
fn scanned(lexing: Lexing, depth: u32, rest: &[u8]) -> (Lexing, u32, usize) {
    match lexing {
        Lexing::Block if rest.starts_with(ESCAPED_BLOCK_QUOTE) => {
            (Lexing::Block, depth, ESCAPED_BLOCK_QUOTE.len())
        }
        Lexing::Block if rest.starts_with(BLOCK_QUOTE) => (Lexing::Code, depth, BLOCK_QUOTE.len()),
        Lexing::Block => (Lexing::Block, depth, 1),
        Lexing::Code if rest.starts_with(BLOCK_QUOTE) => (Lexing::Block, depth, BLOCK_QUOTE.len()),
        Lexing::Code | Lexing::Text | Lexing::Escaped | Lexing::Comment => {
            let Some(&byte) = rest.first() else {
                return (lexing, depth, 1);
            };
            let (next, deeper) = step(lexing, depth, byte);
            (next, deeper, 1)
        }
    }
}

/// The scanner's place and the depth after reading `byte` outside a block
/// string.
fn step(lexing: Lexing, depth: u32, byte: u8) -> (Lexing, u32) {
    match (lexing, byte) {
        (Lexing::Code, b'{' | b'(' | b'[') => (Lexing::Code, depth.saturating_add(1)),
        (Lexing::Code, b'}' | b')' | b']') => (Lexing::Code, depth.saturating_sub(1)),
        (Lexing::Code, b'"') => (Lexing::Text, depth),
        (Lexing::Code, b'#') => (Lexing::Comment, depth),
        (Lexing::Text, b'\\') => (Lexing::Escaped, depth),
        (Lexing::Text, b'"') | (Lexing::Comment, b'\n' | b'\r') => (Lexing::Code, depth),
        (Lexing::Escaped, _) => (Lexing::Text, depth),
        (Lexing::Code | Lexing::Text | Lexing::Block | Lexing::Comment, _) => (lexing, depth),
    }
}

/// The operation this request runs, and what it selects.
///
/// A document may define several. Without a name to pick by, only a
/// document defining exactly one is unambiguous: guessing would cost the
/// wrong operation, and could cost a query while a mutation runs.
fn operation_of<'d>(
    document: &'d ExecutableDocument,
    requested: Option<&str>,
) -> Result<(OperationKind, &'d SelectionSet), DomainError> {
    let definition = match (&document.operations, requested) {
        (DocumentOperations::Single(operation), None) => operation,
        (DocumentOperations::Single(_), Some(_)) => {
            return Err(DomainError::invalid(message!(
                "infra-the-request-names-an-operation-the",
                "the request names an operation the document leaves unnamed"
            )));
        }
        (DocumentOperations::Multiple(operations), Some(name)) => operations
            .iter()
            .find(|(defined, _)| defined.as_str() == name)
            .map(|(_, operation)| operation)
            .ok_or_else(|| {
                DomainError::invalid(message!(
                    "infra-the-document-defines-no-operation-of",
                    "the document defines no operation of that name"
                ))
            })?,
        (DocumentOperations::Multiple(operations), None) => only_one(operations.values())?,
    };
    let kind = match definition.node.ty {
        OperationType::Query => OperationKind::Query,
        OperationType::Mutation => OperationKind::Mutation,
        OperationType::Subscription => OperationKind::Subscription,
    };
    Ok((kind, &definition.node.selection_set.node))
}

/// The single item of `items`, refused when there are none or several.
fn only_one<T>(mut items: impl Iterator<Item = T>) -> Result<T, DomainError> {
    let first = items.next().ok_or_else(|| {
        DomainError::invalid(message!(
            "infra-the-document-defines-no-operation-to",
            "the document defines no operation to run"
        ))
    })?;
    if items.next().is_some() {
        return Err(DomainError::invalid(message!(
            "infra-the-document-defines-several-operations-name",
            "the document defines several operations; name the one to run"
        )));
    }
    Ok(first)
}

/// One walk over an operation's selections, following fragments.
struct Walk<'d> {
    fragments: HashMap<&'d str, &'d FragmentDefinition>,
    following: HashSet<&'d str>,
    depth: u32,
    fields: u32,
    steps: u32,
}

impl<'d> Walk<'d> {
    /// A walk over `document`'s fragments, nothing counted yet.
    fn over(document: &'d ExecutableDocument) -> Self {
        Self {
            fragments: document
                .fragments
                .iter()
                .map(|(name, fragment)| (name.as_str(), &fragment.node))
                .collect(),
            following: HashSet::new(),
            depth: 0,
            fields: 0,
            steps: 0,
        }
    }

    /// Whether the walk did more than any limit allows, so counting on
    /// changes nothing.
    fn past_every_limit(&self, level: u32) -> bool {
        level > MAX_ALLOWED_DEPTH || self.fields > MAX_ALLOWED_COMPLEXITY || self.steps > MOST_STEPS
    }

    /// What the operation costs: its fields, or the most there is when the
    /// walk stopped early.
    fn cost(&self) -> u32 {
        if self.steps > MOST_STEPS {
            return u32::MAX;
        }
        self.fields
    }

    /// Walks `set`, whose selections sit at `level`.
    fn selections(&mut self, set: &'d SelectionSet, level: u32) {
        self.depth = self.depth.max(level);
        for selection in &set.items {
            if self.past_every_limit(level) {
                return;
            }
            self.steps = self.steps.saturating_add(1);
            self.selection(&selection.node, level);
        }
    }

    /// Walks one selection at `level`. An inline fragment is a condition,
    /// not a level, so what it selects sits where it does.
    fn selection(&mut self, selection: &'d Selection, level: u32) {
        match selection {
            Selection::Field(field) => {
                self.fields = self.fields.saturating_add(1);
                let below = &field.node.selection_set.node;
                if !below.items.is_empty() {
                    self.selections(below, level.saturating_add(1));
                }
            }
            Selection::InlineFragment(inline) => {
                self.selections(&inline.node.selection_set.node, level);
            }
            Selection::FragmentSpread(spread) => {
                self.spread(spread.node.fragment_name.node.as_str(), level);
            }
        }
    }

    /// Follows the fragment `name` at `level`, unless it is already being
    /// followed or the document does not define it.
    fn spread(&mut self, name: &'d str, level: u32) {
        let Some(fragment) = self.fragments.get(name).copied() else {
            return;
        };
        if !self.following.insert(name) {
            return;
        }
        self.selections(&fragment.selection_set.node, level);
        self.following.remove(name);
    }
}

/// A stable identifier for this query and these variables.
///
/// Both, because the same query with another `id` asks another question,
/// and a cache keyed on the query alone would serve one caller's record to
/// another. Hashed rather than kept, so a cache key carries nothing
/// readable: a query and its variables routinely name people. Variables
/// are taken in canonical form, so two clients ordering them differently
/// ask the same question.
fn fingerprint(request: &GraphQlRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.query.as_bytes());
    hasher.update([0]);
    hasher.update(
        request
            .operation_name
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    let variables = request.variables.clone().map(canonical).unwrap_or_default();
    hasher.update(variables.to_string().as_bytes());
    data_encoding::HEXLOWER.encode(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(query: &str) -> Vec<u8> {
        serde_json::json!({ "query": query })
            .to_string()
            .into_bytes()
    }

    fn analyze(query: &str) -> GraphQlOperation {
        DocumentGraphQlAnalyzer.analyze(&body(query)).unwrap()
    }

    fn refused(body: &[u8]) -> bool {
        matches!(
            DocumentGraphQlAnalyzer.analyze(body),
            Err(DomainError::Validation(_))
        )
    }

    /// A flat query is one level deep and costs a field each.
    #[test]
    fn a_flat_query_costs_its_fields() {
        let operation = analyze("{ a b c d e }");

        assert_eq!(operation.kind, OperationKind::Query);
        assert_eq!(operation.depth, 1);
        assert_eq!(operation.complexity, 5);
    }

    /// Nesting is counted level by level.
    #[test]
    fn nesting_is_counted() {
        let operation = analyze("{ user { posts { author { name } } } }");

        assert_eq!(operation.depth, 4);
        assert_eq!(operation.complexity, 4);
    }

    /// A mutation and a subscription are told from a query, which alone
    /// decides whether an answer may be cached.
    #[test]
    fn each_kind_is_recognised() {
        assert_eq!(
            analyze("mutation { deleteUser(id: 1) { ok } }").kind,
            OperationKind::Mutation
        );
        assert_eq!(
            analyze("subscription { messages { body } }").kind,
            OperationKind::Subscription
        );
    }

    /// A fragment's nested fields contribute to depth from the point where it
    /// is spread.
    #[test]
    fn a_fragment_is_as_deep_as_what_it_holds() {
        let operation =
            analyze("{ user { ...deep } } fragment deep on User { posts { author { name } } }");

        assert_eq!(operation.depth, 4);
    }

    /// A self-referencing fragment finishes analysis at the depth reached before
    /// repeating the fragment.
    #[test]
    fn a_fragment_that_spreads_itself_ends() {
        let operation = analyze("{ user { ...loop } } fragment loop on User { me { ...loop } }");

        assert_eq!(operation.depth, 3);
    }

    /// Repeatedly doubled fragment spreads produce a complexity above the
    /// maximum allowed value.
    #[test]
    fn fragments_doubling_each_other_cost_the_most() {
        let mut query = String::from("{ ...f0 }");
        for level in 0..40 {
            let next = level + 1;
            query.push_str(&format!(
                " fragment f{level} on Q {{ ...f{next} ...f{next} }}"
            ));
        }
        query.push_str(" fragment f40 on Q { leaf }");

        let operation = analyze(&query);

        assert!(operation.complexity > MAX_ALLOWED_COMPLEXITY);
    }

    /// A query with 500 nested selections is rejected, while 500 brackets inside
    /// a quoted argument leave the query's depth at one.
    #[test]
    fn a_query_nested_too_deeply_is_refused_before_parsing() {
        let deep = format!("{}{}", "{ a ".repeat(500), "}".repeat(500));
        let quoted = format!("{{ a(text: \"{}\") }}", "{".repeat(500));

        assert!(refused(&body(&deep)));
        assert_eq!(analyze(&quoted).depth, 1);
    }

    /// Deep nesting after a block string containing a lone quote still exceeds
    /// the scanner's bound and fails validation.
    #[test]
    fn brackets_after_a_block_string_are_counted() {
        let hidden = format!(
            "{{ a(t: \"\"\"x\"y\"\"\") {}{} }}",
            "[".repeat(500),
            "]".repeat(500)
        );

        assert!(nesting_of(&hidden) > DEEPEST_NESTING);
        assert!(refused(&body(&hidden)));
    }

    /// Brackets inside a block string, its escaped closing quotes
    /// included, do not count.
    #[test]
    fn brackets_inside_a_block_string_do_not_count() {
        let quoted = format!(
            "{{ a(text: \"\"\"{} \\\"\"\" \" {}\"\"\") }}",
            "{".repeat(500),
            "[".repeat(500)
        );

        assert_eq!(analyze(&quoted).depth, 1);
    }

    /// Non-JSON input, request batches, invalid query syntax, unexpected fields
    /// and an oversized body all fail validation.
    #[test]
    fn a_body_that_cannot_be_costed_is_refused() {
        let batch = br#"[{"query": "{ a }"}, {"query": "{ b }"}]"#;
        let smuggled = br#"{"query": "{ a }", "querry": "mutation { drop }"}"#;
        let endless = body(&format!("{{ {} }}", "a ".repeat(LARGEST_BODY)));

        assert!(refused(b"query { a }"));
        assert!(refused(batch));
        assert!(refused(&body("{ a")));
        assert!(refused(smuggled));
        assert!(refused(&endless));
    }

    /// A document with multiple operations fails without a selected name;
    /// selecting its mutation returns that operation's name, kind and depth.
    #[test]
    fn several_operations_need_a_name() {
        let document = "query small { a } mutation big { b { c } }";
        let unnamed = body(document);
        let named = serde_json::json!({ "query": document, "operationName": "big" }).to_string();

        assert!(refused(&unnamed));
        let operation = DocumentGraphQlAnalyzer.analyze(named.as_bytes()).unwrap();
        assert_eq!(operation.kind, OperationKind::Mutation);
        assert_eq!(operation.name.as_deref(), Some("big"));
        assert_eq!(operation.depth, 2);
    }

    /// The same question asks the same whatever order its variables come
    /// in, and other variables ask another.
    #[test]
    fn the_fingerprint_follows_the_question() {
        let first = br#"{"query": "query($a: Int, $b: Int) { x(a: $a, b: $b) }", "variables": {"a": 1, "b": 2}}"#;
        let reordered = br#"{"query": "query($a: Int, $b: Int) { x(a: $a, b: $b) }", "variables": {"b": 2, "a": 1}}"#;
        let other = br#"{"query": "query($a: Int, $b: Int) { x(a: $a, b: $b) }", "variables": {"a": 1, "b": 3}}"#;

        let print = |raw: &[u8]| DocumentGraphQlAnalyzer.analyze(raw).unwrap().fingerprint;

        assert_eq!(print(first), print(reordered));
        assert_ne!(print(first), print(other));
    }
}
