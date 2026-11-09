//! Request and response transformation: what the gateway changes on the way
//! through.
//!
//! Teams often put a gateway in front of a service because the caller and
//! the backend disagree about the shape of the request. The backend wants a
//! header under another name. The caller should not have to send a version
//! parameter. The backend leaks a debugging header no client should see.
//! Rewriting that is the gateway's job, not the backend's.
//!
//! Two mutations live here, and neither is a stage. A stage decides
//! *whether* to mutate, and these say *what*. [`RequestMutation`] is what the
//! pipeline gathers on the way to the upstream. [`ResponseMutation`] is what
//! a post-response stage applies on the way back.

mod response;

pub use response::*;

use crate::domains::proxy::stages::decision::HeaderEntry;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::shared::web::parameter_key::ParameterKey;
use crate::shared::web::percent;
use crate::types::{FieldPath, HeaderName, HeaderValue};

/// Headers that describe the connection rather than the message.
///
/// Setting one from configuration does not rewrite a request. It breaks the
/// framing the proxy is in the middle of negotiating.
const CONNECTION_HEADERS: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

/// A query-string parameter to set on the forwarded request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "QueryParamWire"))]
pub struct QueryParam {
    name: QueryName,
    value: QueryValue,
}

/// A query parameter as it arrives, before [`QueryParam::new`] has checked
/// it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct QueryParamWire {
    name: String,
    value: String,
}

#[cfg(feature = "serde")]
impl TryFrom<QueryParamWire> for QueryParam {
    type Error = DomainError;

    /// A parameter read from a stored stage or an API body is held to the
    /// same rules as one built in code, so no control character reaches the
    /// forwarded query string.
    fn try_from(wire: QueryParamWire) -> Result<Self, Self::Error> {
        Self::new(wire.name, wire.value)
    }
}

impl QueryParam {
    /// Creates a query parameter.
    ///
    /// The value is stored as written and percent-encoded when the query is
    /// rendered, so a configured `a b` reaches the upstream as `a%20b`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if the name is not a [`QueryName`].
    /// - [`DomainError::Validation`] if the value is not a [`QueryValue`].
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self, DomainError> {
        Ok(Self {
            name: QueryName::new(name)?,
            value: QueryValue::new(value)?,
        })
    }

    /// The parameter name, as written.
    #[must_use]
    pub fn name(&self) -> &QueryName {
        &self.name
    }

    /// The parameter value, as written.
    #[must_use]
    pub fn value(&self) -> &QueryValue {
        &self.value
    }
}

/// What the pipeline changes about the request before it is forwarded.
///
/// Gathered across stages. Each stage that mutates adds one of these, and
/// they are merged in stage order. So a later stage overwrites an earlier
/// one's value for the same header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct RequestMutation {
    set_headers: Vec<HeaderEntry>,
    remove_headers: Vec<HeaderName>,
    set_query: Vec<QueryParam>,
    remove_query: Vec<QueryName>,
}

/// Reads a request mutation through [`RequestMutation::configured`].
///
/// A derived `Deserialize` would let a stage that arrives over HTTP, or
/// comes back out of the stage column, set a header
/// [`is_proxy_owned`](crate::shared::web::proxy_headers::is_proxy_owned)
/// refuses. The constructor's check would then sit off the path the
/// configuration travels.
///
/// So a [`RequestMutation::asserting`] value does not round-trip. It carries
/// exactly the headers this refuses. Nothing deserializes one, since they
/// last only for one request. A stored mutation is always tenant
/// configuration.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for RequestMutation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Wire {
            #[serde(default)]
            set_headers: Vec<HeaderEntry>,
            #[serde(default)]
            remove_headers: Vec<HeaderName>,
            #[serde(default)]
            set_query: Vec<QueryParam>,
            #[serde(default)]
            remove_query: Vec<QueryName>,
        }

        let wire = Wire::deserialize(deserializer)?;

        Self::configured(RequestMutationRules {
            set_headers: wire.set_headers.iter().map(header_pair).collect(),
            remove_headers: wire.remove_headers,
            set_query: wire.set_query,
            remove_query: wire.remove_query,
        })
        .map_err(<D::Error as serde::de::Error>::custom)
    }
}

/// A stored header as the name and value the rules take.
#[cfg(feature = "serde")]
fn header_pair(entry: &HeaderEntry) -> (HeaderName, HeaderValue) {
    (entry.name().clone(), entry.value().clone())
}

/// The rules a tenant configures on a request-transform stage.
#[derive(Debug, Clone, Default)]
pub struct RequestMutationRules {
    /// Headers to add, overwriting any the client sent.
    pub set_headers: Vec<(HeaderName, HeaderValue)>,
    /// Headers to drop before forwarding.
    pub remove_headers: Vec<HeaderName>,
    /// Query parameters to add, overwriting any the client sent.
    pub set_query: Vec<QueryParam>,
    /// Query parameter names to drop before forwarding.
    pub remove_query: Vec<QueryName>,
}

impl RequestMutation {
    /// Headers a platform stage asserts about the caller.
    ///
    /// Infallible and unrestricted. The `TokenExchange`, `DataClassify` and
    /// `RequestSign` stages exist to write the headers
    /// [`is_proxy_owned`](crate::shared::web::proxy_headers::is_proxy_owned)
    /// refuses to a tenant. The upstream trusts these stages, not the
    /// tenant.
    #[must_use]
    pub fn asserting(headers: Vec<HeaderEntry>) -> Self {
        Self {
            set_headers: headers,
            ..Self::default()
        }
    }

    /// A mutation built from tenant configuration.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if a header to set or drop is one the
    ///   proxy asserts itself, by
    ///   [`is_proxy_owned`](crate::shared::web::proxy_headers::is_proxy_owned).
    /// - [`DomainError::Validation`] if a header to set or drop describes the
    ///   connection, not the message.
    ///
    /// Header values, query names and query values are checked when they are
    /// built, by [`HeaderValue`], [`QueryName`] and [`QueryValue`].
    pub fn configured(rules: RequestMutationRules) -> Result<Self, DomainError> {
        for (name, _) in &rules.set_headers {
            validate_configurable(name)?;
        }
        for name in &rules.remove_headers {
            validate_configurable(name)?;
        }

        Ok(Self {
            set_headers: rules
                .set_headers
                .into_iter()
                .map(|(name, value)| HeaderEntry::new(name, value))
                .collect(),
            remove_headers: rules.remove_headers,
            set_query: rules.set_query,
            remove_query: rules.remove_query,
        })
    }

    /// Whether this mutation changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set_headers.is_empty()
            && self.remove_headers.is_empty()
            && self.set_query.is_empty()
            && self.remove_query.is_empty()
    }

    /// A copy with each header value replaced by what `resolved` holds for
    /// the value as configured.
    ///
    /// For configuration that names a credential instead of carrying one.
    /// The caller fetches the values, and the replacement happens here, where
    /// the rules about what a mutation may set already hold. A value with no
    /// entry in `resolved` is kept as written, so a literal stays as it is.
    ///
    /// # Errors
    ///
    /// - [`DomainError`] if a resolved value is not one a header may carry,
    ///   such as a secret store answering with a newline in it.
    pub fn with_resolved_values(
        &self,
        resolved: &std::collections::HashMap<String, String>,
    ) -> Result<Self, DomainError> {
        let mut replaced = self.clone();
        replaced.set_headers = resolve_values(&self.set_headers, resolved)?;
        Ok(replaced)
    }

    /// Headers to add or overwrite on the forwarded request.
    #[must_use]
    pub fn headers_to_set(&self) -> &[HeaderEntry] {
        &self.set_headers
    }

    /// Headers to drop from the forwarded request.
    #[must_use]
    pub fn remove_headers(&self) -> &[HeaderName] {
        &self.remove_headers
    }

    /// Folds a later stage's mutation into this one.
    pub fn merge(&mut self, other: Self) {
        self.set_headers.extend(other.set_headers);
        self.remove_headers.extend(other.remove_headers);
        self.set_query.extend(other.set_query);
        self.remove_query.extend(other.remove_query);
    }

    /// The query string the upstream sees, given the one the client sent.
    ///
    /// A parameter this mutation sets replaces every copy the client sent
    /// under that name, and is appended in configuration order after the
    /// parameters that survive. Returns `None` when nothing is left, so the
    /// forwarded URL carries no trailing `?`.
    ///
    /// A name matches every way a server might read the same name, by the
    /// same folding the parameter rules use. That covers any casing, `+` for
    /// a space, percent-encoding, an array suffix such as `debug[]`, PHP's
    /// `.` and space for `_`, and a `;` that some servers also split on.
    /// Otherwise a client could send `Debug=1` or `debug[]=1` past a rule
    /// removing `debug`, or a second `version[]` past a pinned `version`.
    /// Upstreams that tell names apart by those spellings alone are not
    /// supported for transformed parameters.
    #[must_use]
    pub fn apply_to_query(&self, original: Option<&str>) -> Option<String> {
        let ruled: Vec<ParameterKey> = self
            .remove_query
            .iter()
            .chain(self.set_query.iter().map(|p| &p.name))
            .map(|name| ParameterKey::written(name.as_str()))
            .collect();
        let dropped = |pair: &str| {
            pair.split(';')
                .any(|part| ruled.contains(&ParameterKey::sent_in_query(pair_name(part))))
        };

        let mut pairs: Vec<String> = original
            .unwrap_or_default()
            .split('&')
            .filter(|pair| !pair.is_empty())
            .filter(|pair| !dropped(pair))
            .map(str::to_owned)
            .collect();

        pairs.extend(self.set_query.iter().map(|p| {
            format!(
                "{}={}",
                percent::encode(p.name.as_str()),
                percent::encode(p.value.as_str())
            )
        }));

        (!pairs.is_empty()).then(|| pairs.join("&"))
    }
}

/// What a stage changes inside a JSON response body.
///
/// Unlike the header rules, it applies only when a tenant asks for it. A body
/// has to be read whole before it can be rewritten, so a route that declares
/// one stops streaming its responses. The executor refuses to rewrite a body
/// it only saw part of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BodyTransform {
    #[cfg_attr(feature = "serde", serde(default))]
    remove: Vec<FieldPath>,
    #[cfg_attr(feature = "serde", serde(default))]
    rename: Vec<FieldRename>,
}

/// One field renamed, keeping its value and its position.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "FieldRenameWire"))]
pub struct FieldRename {
    from: FieldPath,
    to: FieldPath,
}

/// A rename as it arrives, before [`FieldRename::new`] has checked it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct FieldRenameWire {
    from: FieldPath,
    to: String,
}

#[cfg(feature = "serde")]
impl TryFrom<FieldRenameWire> for FieldRename {
    type Error = DomainError;

    /// A rename read from a stored stage or an API body is held to the same
    /// rules as one built in code, so a stored rule cannot move a field.
    fn try_from(wire: FieldRenameWire) -> Result<Self, Self::Error> {
        Self::new(wire.from, wire.to)
    }
}

impl FieldRename {
    /// A rename of the field at `from` to the name `to`.
    ///
    /// `to` is a name, not a path. A rename changes what a field is called.
    /// Moving it somewhere else in the document is a different operation with
    /// different ways to fail.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if `to` is not a valid field name.
    /// - [`DomainError::Validation`] if `to` names a nested path.
    pub fn new(from: FieldPath, to: impl Into<String>) -> Result<Self, DomainError> {
        let to = FieldPath::new(to)?;
        if to.depth() != 1 {
            return Err(DomainError::invalid(message!(
                "proxy-a-rename-gives-a-field-a",
                "a rename gives a field a new name, not a new place: the target must not contain a dot"
            )));
        }
        Ok(Self { from, to })
    }

    /// The field as the upstream names it.
    #[must_use]
    pub fn from(&self) -> &FieldPath {
        &self.from
    }

    /// What the client should see it called.
    #[must_use]
    pub fn to(&self) -> &str {
        self.to.as_str()
    }
}

impl BodyTransform {
    /// A rule set dropping the fields at `remove` and renaming `rename`.
    #[must_use]
    pub fn new(remove: Vec<FieldPath>, rename: Vec<FieldRename>) -> Self {
        Self { remove, rename }
    }

    /// Fields to drop, by dot-notation path, such as `error.stack_trace`.
    #[must_use]
    pub fn remove(&self) -> &[FieldPath] {
        &self.remove
    }

    /// Fields to rename, in place.
    #[must_use]
    pub fn rename(&self) -> &[FieldRename] {
        &self.rename
    }

    /// Whether this changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remove.is_empty() && self.rename.is_empty()
    }
}

/// `headers` with each value replaced by what `resolved` holds for it, and
/// every replacement held to the rules of a header value.
fn resolve_values(
    headers: &[HeaderEntry],
    resolved: &std::collections::HashMap<String, String>,
) -> Result<Vec<HeaderEntry>, DomainError> {
    headers
        .iter()
        .map(|entry| {
            let Some(value) = resolved.get(entry.value().as_str()) else {
                return Ok(entry.clone());
            };
            let value = HeaderValue::new(value.as_str())?;
            Ok(HeaderEntry::new(entry.name().clone(), value))
        })
        .collect()
}

/// The name half of a `name=value` pair, still percent-encoded.
fn pair_name(pair: &str) -> &str {
    pair.split_once('=').map_or(pair, |(name, _)| name)
}

text_value! {
    /// The name of a query parameter a transform sets or drops, as written.
    pub struct QueryName;
}

impl TextValue for QueryName {
    const FIELD: &'static str = "query parameter name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .max_bytes(1024)
            .ascii_only()
            .no_control_chars()
    }
}

text_value! {
    /// The value a transform sets on a query parameter, as written.
    ///
    /// It is percent-encoded when the query is rendered.
    pub struct QueryValue;
}

impl TextValue for QueryValue {
    const FIELD: &'static str = "query parameter value";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.max_bytes(1024).ascii_only().no_control_chars()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str) -> HeaderName {
        HeaderName::new(name).unwrap()
    }

    fn value(text: &str) -> HeaderValue {
        HeaderValue::new(text).unwrap()
    }

    fn entry(name: &str, text: &str) -> HeaderEntry {
        HeaderEntry::new(header(name), value(text))
    }

    fn rules(set: &[(&str, &str)], remove: &[&str]) -> RequestMutationRules {
        RequestMutationRules {
            set_headers: set.iter().map(|(n, v)| (header(n), value(v))).collect(),
            remove_headers: remove.iter().map(|n| header(n)).collect(),
            ..RequestMutationRules::default()
        }
    }

    /// A configured request mutation that sets `X-Forwarded-User` fails
    /// validation because the proxy owns that header.
    #[test]
    fn a_tenant_cannot_set_a_header_the_proxy_asserts() {
        let result = RequestMutation::configured(rules(&[("X-Forwarded-User", "admin")], &[]));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A configured request mutation that removes `x-ianua-assertion` fails
    /// validation because the proxy owns that header.
    #[test]
    fn a_tenant_cannot_remove_a_header_the_proxy_asserts() {
        let result = RequestMutation::configured(rules(&[], &["x-ianua-assertion"]));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A platform stage sets `x-forwarded-user: alice` through `asserting`,
    /// and the header is kept. Platform stages are the ones meant to write it.
    #[test]
    fn a_platform_stage_may_assert_a_proxy_owned_header() {
        let mutation = RequestMutation::asserting(vec![entry("x-forwarded-user", "alice")]);

        assert_eq!(mutation.headers_to_set().len(), 1);
    }

    /// A transform that sets `Connection`, `Transfer-Encoding` or
    /// `Content-Length` is refused. Those frame the connection, and setting
    /// one would break the request.
    #[test]
    fn a_connection_header_cannot_be_set() {
        for name in ["Connection", "Transfer-Encoding", "Content-Length"] {
            assert!(
                RequestMutation::configured(rules(&[(name, "x")], &[])).is_err(),
                "{name} should be refused"
            );
        }
    }

    /// Header-value construction rejects a line break followed by an
    /// injected `x-admin` header.
    #[test]
    fn a_header_value_with_a_newline_is_refused() {
        assert!(HeaderValue::new("a\r\nx-admin: 1").is_err());
    }

    /// Setting `X-Api-Version: 2` and dropping `x-debug` is accepted. The
    /// set header's name is kept in lowercase.
    #[test]
    fn an_ordinary_header_rewrite_is_accepted() {
        let mutation =
            RequestMutation::configured(rules(&[("X-Api-Version", "2")], &["x-debug"])).unwrap();

        assert_eq!(
            mutation.headers_to_set()[0].name().as_str(),
            "x-api-version"
        );
        assert_eq!(mutation.remove_headers()[0].as_str(), "x-debug");
    }

    /// A default mutation changes nothing.
    #[test]
    fn a_mutation_with_no_rules_is_empty() {
        assert!(RequestMutation::default().is_empty());
    }

    /// One stage sets `x-one` and a later one sets `x-two`. After merging,
    /// both headers are set.
    #[test]
    fn merge_keeps_both_stages_contributions() {
        let mut first = RequestMutation::asserting(vec![entry("x-one", "1")]);
        first.merge(RequestMutation::asserting(vec![entry("x-two", "2")]));

        assert_eq!(first.headers_to_set().len(), 2);
    }

    fn query_rules(set: &[(&str, &str)], remove: &[&str]) -> RequestMutationRules {
        RequestMutationRules {
            set_query: set
                .iter()
                .map(|(n, v)| QueryParam::new(*n, *v).unwrap())
                .collect(),
            remove_query: remove.iter().map(|n| QueryName::new(*n).unwrap()).collect(),
            ..RequestMutationRules::default()
        }
    }

    /// With no query rules, `page=2&sort=name` reaches the upstream as sent.
    #[test]
    fn an_untouched_query_passes_through_unchanged() {
        let mutation = RequestMutation::default();

        assert_eq!(
            mutation.apply_to_query(Some("page=2&sort=name")).unwrap(),
            "page=2&sort=name"
        );
    }

    /// A rule drops `debug`. From `page=2&debug=1`, only `page=2` reaches the
    /// upstream.
    #[test]
    fn a_removed_parameter_does_not_reach_the_upstream() {
        let mutation = RequestMutation::configured(query_rules(&[], &["debug"])).unwrap();

        assert_eq!(
            mutation.apply_to_query(Some("page=2&debug=1")).unwrap(),
            "page=2"
        );
    }

    /// Removing `debug mode` also removes the tested case, encoding,
    /// array, dot and underscore variants, including one after a semicolon.
    #[test]
    fn a_removed_parameter_cannot_be_sent_under_another_spelling() {
        let mutation = RequestMutation::configured(query_rules(&[], &["debug mode"])).unwrap();

        for sneaked in [
            "Debug+Mode=1",
            "debug%20mode=1",
            "DEBUG%20MODE=1",
            "page=2;debug+mode=1",
            "debug+mode[]=1",
            "debug+mode[x]=1",
            "debug.mode=1",
            "debug_mode=1",
        ] {
            assert!(
                mutation
                    .apply_to_query(Some(sneaked))
                    .is_none_or(|left| left == "page=2"),
                "{sneaked} reached the upstream"
            );
        }
    }

    /// Pinning `version=2` removes the client's `version[]=9` while
    /// retaining `page=2` in the resulting query.
    #[test]
    fn a_pinned_parameter_replaces_its_array_spelling_too() {
        let mutation = RequestMutation::configured(query_rules(&[("version", "2")], &[])).unwrap();

        assert_eq!(
            mutation.apply_to_query(Some("version[]=9&page=2")).unwrap(),
            "page=2&version=2"
        );
    }

    /// Pinning a name containing a literal plus replaces the client's
    /// encoded copy and renders only `a%2Bb=1`.
    #[test]
    fn a_pinned_name_holding_a_plus_drops_the_clients_copy() {
        let mutation = RequestMutation::configured(query_rules(&[("a+b", "1")], &[])).unwrap();

        assert_eq!(
            mutation.apply_to_query(Some("a%2Bb=evil")).unwrap(),
            "a%2Bb=1"
        );
    }

    /// Pinning `version=2` replaces both differently cased client copies
    /// while retaining the unrelated page parameter.
    #[test]
    fn a_pinned_parameter_replaces_every_casing_of_it() {
        let mutation = RequestMutation::configured(query_rules(&[("version", "2")], &[])).unwrap();

        assert_eq!(
            mutation
                .apply_to_query(Some("Version=1&VERSION=9&page=2"))
                .unwrap(),
            "page=2&version=2"
        );
    }

    /// A route sets `version=2`. The client's `version=1` is replaced, and
    /// the pinned value goes after the parameters that remain.
    #[test]
    fn a_set_parameter_replaces_the_one_the_client_sent() {
        let mutation = RequestMutation::configured(query_rules(&[("version", "2")], &[])).unwrap();

        assert_eq!(
            mutation.apply_to_query(Some("version=1&page=2")).unwrap(),
            "page=2&version=2"
        );
    }

    /// A request with no query string gets `version=2` from the route.
    #[test]
    fn a_set_parameter_is_added_when_the_client_sent_none() {
        let mutation = RequestMutation::configured(query_rules(&[("version", "2")], &[])).unwrap();

        assert_eq!(mutation.apply_to_query(None).unwrap(), "version=2");
    }

    /// A rule drops `debug` from `debug=1`. No query is left, so the URL has
    /// no trailing `?`. Some upstreams treat a bare `?` as a different URL.
    #[test]
    fn removing_the_only_parameter_leaves_no_query_at_all() {
        let mutation = RequestMutation::configured(query_rules(&[], &["debug"])).unwrap();

        assert!(mutation.apply_to_query(Some("debug=1")).is_none());
    }

    /// A configured value `a b&c=d` is sent as `a%20b%26c%3Dd`, so its `&`
    /// and `=` do not add parameters.
    #[test]
    fn a_set_value_is_percent_encoded() {
        let mutation = RequestMutation::configured(query_rules(&[("q", "a b&c=d")], &[])).unwrap();

        assert_eq!(mutation.apply_to_query(None).unwrap(), "q=a%20b%26c%3Dd");
    }

    /// A rule drops `a b`. The client's `a%20b=1` decodes to that name and
    /// is dropped.
    #[test]
    fn a_percent_encoded_name_is_matched_when_removed() {
        let mutation = RequestMutation::configured(query_rules(&[], &["a b"])).unwrap();

        assert!(mutation.apply_to_query(Some("a%20b=1")).is_none());
    }

    /// A bare `flag` with no `=` passes through unchanged.
    #[test]
    fn a_valueless_parameter_survives() {
        let mutation = RequestMutation::default();

        assert_eq!(mutation.apply_to_query(Some("flag")).unwrap(), "flag");
    }

    /// A parameter to set with an empty name is refused.
    #[test]
    fn a_query_parameter_name_must_not_be_empty() {
        assert!(QueryParam::new("", "x").is_err());
    }

    /// A parameter value with a line feed is refused, so it cannot reach the
    /// upstream's request line.
    #[test]
    fn a_query_parameter_must_not_carry_a_control_character() {
        assert!(QueryParam::new("q", "a\nb").is_err());
    }

    //
    // A stage arrives as JSON twice: once over HTTP when a tenant configures
    // it, once out of the stage column when the proxy loads the pipeline. The
    // constructor's refusals have to hold on both.

    /// Deserializing a request mutation that sets `x-forwarded-user: admin`
    /// is refused by the configuration validation.
    #[cfg(feature = "serde")]
    #[test]
    fn a_mutation_read_from_json_is_validated() {
        let json = r#"{"set_headers":[{"name":"x-forwarded-user","value":"admin"}]}"#;

        let result = serde_json::from_str::<RequestMutation>(json);

        assert!(result.is_err());
    }

    /// A response mutation in JSON that sets `transfer-encoding` is refused
    /// when read, as it would be when built in code.
    #[cfg(feature = "serde")]
    #[test]
    fn a_response_mutation_read_from_json_is_validated() {
        let json = r#"{"set_headers":[{"name":"transfer-encoding","value":"chunked"}]}"#;

        let result = serde_json::from_str::<ResponseMutation>(json);

        assert!(result.is_err());
    }

    /// A stored parameter with a line feed in its value, or with an empty
    /// name, is refused when read from JSON.
    #[cfg(feature = "serde")]
    #[test]
    fn a_query_parameter_breaking_the_rules_is_refused_on_deserialize() {
        for json in [
            r#"{"name":"q","value":"a\nb"}"#,
            r#"{"name":"","value":"x"}"#,
        ] {
            assert!(
                serde_json::from_str::<QueryParam>(json).is_err(),
                "{json} must be refused"
            );
        }
    }

    /// A mutation that sets and drops a header and a parameter is written to
    /// JSON and read back unchanged.
    #[cfg(feature = "serde")]
    #[test]
    fn an_ordinary_mutation_round_trips_through_json() {
        let mutation = RequestMutation::configured(RequestMutationRules {
            set_headers: vec![(header("x-api-version"), value("2"))],
            remove_headers: vec![header("x-debug")],
            set_query: vec![QueryParam::new("v", "2").unwrap()],
            remove_query: vec![QueryName::new("debug").unwrap()],
        })
        .unwrap();

        let json = serde_json::to_string(&mutation).unwrap();

        assert_eq!(
            serde_json::from_str::<RequestMutation>(&json).unwrap(),
            mutation
        );
    }

    /// The JSON `{}` reads as a mutation that changes nothing.
    #[cfg(feature = "serde")]
    #[test]
    fn an_omitted_rule_list_reads_as_empty() {
        let mutation = serde_json::from_str::<RequestMutation>("{}").unwrap();

        assert!(mutation.is_empty());
    }

    /// A response transform sets `x-cache: MISS` and drops `x-powered-by` and
    /// `server`, hiding what the upstream runs.
    #[test]
    fn a_response_transform_can_drop_an_upstream_header() {
        let mutation = ResponseMutation::configured(ResponseMutationRules {
            set_headers: vec![(header("x-cache"), value("MISS"))],
            remove_headers: vec![header("x-powered-by"), header("server")],
            ..ResponseMutationRules::default()
        })
        .unwrap();

        assert_eq!(mutation.headers_to_set()[0].name().as_str(), "x-cache");
        assert_eq!(mutation.remove_headers().len(), 2);
    }

    /// A response transform may drop `x-ianua-assertion`. On the response
    /// side the proxy adds its own headers later, so a tenant may strip an
    /// upstream copy of one.
    #[test]
    fn a_response_transform_may_touch_a_proxy_owned_name() {
        let mutation = ResponseMutation::configured(ResponseMutationRules {
            set_headers: Vec::new(),
            remove_headers: vec![header("x-ianua-assertion")],
            ..ResponseMutationRules::default()
        });

        assert!(mutation.is_ok());
    }

    /// A response transform with an empty body rule set has no body rule at
    /// all. A body rule stops the response streaming, so an empty one must
    /// not count.
    #[test]
    fn an_empty_body_rule_set_is_dropped() {
        let mutation = ResponseMutation::configured(ResponseMutationRules {
            body: Some(BodyTransform::default()),
            ..ResponseMutationRules::default()
        })
        .unwrap();

        assert!(mutation.body().is_none());
        assert!(mutation.is_empty());
    }

    /// A stored body rule that removes `a..b`, a path with an empty segment,
    /// is refused when read from JSON.
    #[cfg(feature = "serde")]
    #[test]
    fn a_malformed_path_read_from_json_is_refused() {
        let json = r#"{"body":{"remove":["a..b"],"rename":[]}}"#;

        assert!(serde_json::from_str::<ResponseMutation>(json).is_err());
    }

    /// A stored body rule that removes `error.stack_trace` is read back from
    /// JSON with that path.
    #[cfg(feature = "serde")]
    #[test]
    fn body_rules_survive_the_wire() {
        let json = r#"{"body":{"remove":["error.stack_trace"],"rename":[]}}"#;

        let mutation = serde_json::from_str::<ResponseMutation>(json).unwrap();

        assert_eq!(
            mutation.body().unwrap().remove()[0].to_string(),
            "error.stack_trace"
        );
    }

    /// Renaming `user.id` to `identifier` is accepted and keeps both names.
    #[test]
    fn a_rename_to_a_single_name_is_accepted() {
        let rename = FieldRename::new(FieldPath::new("user.id").unwrap(), "identifier").unwrap();

        assert_eq!(rename.from().as_str(), "user.id");
        assert_eq!(rename.to(), "identifier");
    }

    /// Renaming `id` to `user.identifier` is refused. That would move the
    /// field, not rename it.
    #[test]
    fn a_rename_to_a_nested_path_is_refused() {
        let result = FieldRename::new(FieldPath::new("id").unwrap(), "user.identifier");

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A stored rename of `id` to `a.b` is refused when read from JSON, as it
    /// is when built in code.
    #[cfg(feature = "serde")]
    #[test]
    fn a_rename_to_a_nested_path_read_from_json_is_refused() {
        let json = r#"{"body":{"remove":[],"rename":[{"from":"id","to":"a.b"}]}}"#;

        assert!(serde_json::from_str::<ResponseMutation>(json).is_err());
    }

    /// A parameter name to drop may not be empty.
    #[test]
    fn a_query_name_to_drop_must_not_be_empty() {
        assert!(QueryName::new("").is_err());
    }

    /// A parameter name to drop with a line feed in it is refused.
    #[test]
    fn a_query_name_to_drop_must_not_carry_a_control_character() {
        assert!(QueryName::new("de\nbug").is_err());
    }

    /// A response transform that sets `transfer-encoding: chunked` is
    /// refused. It frames the connection, not the message.
    #[test]
    fn a_response_transform_cannot_set_a_connection_header() {
        let result = ResponseMutation::configured(ResponseMutationRules {
            set_headers: vec![(header("transfer-encoding"), value("chunked"))],
            remove_headers: Vec::new(),
            ..ResponseMutationRules::default()
        });

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A parameter built as `tenant` and `acme` reports exactly that name and
    /// value, the two halves written into the forwarded URL.
    #[test]
    fn a_query_parameter_reports_the_name_and_value_it_was_built_from() {
        let param = QueryParam::new("tenant", "acme").unwrap();

        assert_eq!(param.name().as_str(), "tenant");
        assert_eq!(param.value().as_str(), "acme");
    }

    /// A mutation with no rules is empty. One that only sets a header, only
    /// drops a header, only sets a parameter or only drops one is not, so no
    /// configured change is skipped.
    #[test]
    fn a_request_mutation_is_empty_only_when_it_changes_nothing_at_all() {
        assert!(
            RequestMutation::configured(rules(&[], &[]))
                .unwrap()
                .is_empty()
        );

        let changes = [
            RequestMutation::configured(rules(&[("x-note", "1")], &[])).unwrap(),
            RequestMutation::configured(rules(&[], &["x-note"])).unwrap(),
            RequestMutation::configured(query_rules(&[("a", "1")], &[])).unwrap(),
            RequestMutation::configured(query_rules(&[], &["a"])).unwrap(),
        ];

        for mutation in changes {
            assert!(!mutation.is_empty(), "{mutation:?} changes something");
        }
    }

    /// A response mutation with no rules is empty. One that only sets a
    /// header, or only drops one, is not.
    #[test]
    fn a_response_mutation_is_empty_only_when_it_changes_nothing_at_all() {
        let nothing = ResponseMutation::configured(ResponseMutationRules::default()).unwrap();
        assert!(nothing.is_empty());

        let set = ResponseMutation::configured(ResponseMutationRules {
            set_headers: vec![(header("x-note"), value("1"))],
            ..ResponseMutationRules::default()
        })
        .unwrap();
        let removed = ResponseMutation::configured(ResponseMutationRules {
            remove_headers: vec![header("x-note")],
            ..ResponseMutationRules::default()
        })
        .unwrap();

        assert!(!set.is_empty());
        assert!(!removed.is_empty());
    }

    /// The signing stage asserts `x-ianua-signature: abc` on the response.
    /// The mutation keeps that one header with its value.
    #[test]
    fn an_asserted_response_header_is_kept() {
        let mutation = ResponseMutation::asserting(vec![entry("x-ianua-signature", "abc")]);

        assert!(!mutation.is_empty());
        assert_eq!(mutation.headers_to_set().len(), 1);
        assert_eq!(mutation.headers_to_set()[0].value().as_str(), "abc");
    }

    /// One stage sets `x-first` and a later one `x-second`. After merging,
    /// both are set, in stage order.
    #[test]
    fn merging_keeps_what_the_later_stage_asked_for() {
        let mut first = ResponseMutation::asserting(vec![entry("x-first", "1")]);

        first.merge(ResponseMutation::asserting(vec![entry("x-second", "2")]));

        let names: Vec<&str> = first
            .headers_to_set()
            .iter()
            .map(|entry| entry.name().as_str())
            .collect();
        assert_eq!(names, ["x-first", "x-second"]);
    }

    /// A header configured as `vault:upstream-key` gets the fetched value
    /// `s3cret`, on both the request and the response side.
    #[test]
    fn a_resolved_value_replaces_the_name_the_configuration_carried() {
        let resolved = std::collections::HashMap::from([(
            "vault:upstream-key".to_owned(),
            "s3cret".to_owned(),
        )]);

        let request =
            RequestMutation::configured(rules(&[("x-api-key", "vault:upstream-key")], &[]))
                .unwrap()
                .with_resolved_values(&resolved)
                .unwrap();
        assert_eq!(request.headers_to_set()[0].value().as_str(), "s3cret");

        let response = ResponseMutation::configured(ResponseMutationRules {
            set_headers: vec![(header("x-api-key"), value("vault:upstream-key"))],
            ..ResponseMutationRules::default()
        })
        .unwrap()
        .with_resolved_values(&resolved)
        .unwrap();
        assert_eq!(response.headers_to_set()[0].value().as_str(), "s3cret");
    }

    /// A secret store answers with a value holding a line break and
    /// `x-admin: 1`. It is refused, not forwarded as a second header.
    #[test]
    fn a_resolved_value_that_would_split_the_header_block_is_refused() {
        let resolved = std::collections::HashMap::from([(
            "vault:upstream-key".to_owned(),
            "a\r\nx-admin: 1".to_owned(),
        )]);

        let result =
            RequestMutation::configured(rules(&[("x-api-key", "vault:upstream-key")], &[]))
                .unwrap()
                .with_resolved_values(&resolved);

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A header value of 8,192 characters and a query value of 1,024 pass.
    /// One character more is refused in each case.
    #[test]
    fn the_longest_permitted_header_value_and_query_part_are_accepted() {
        assert!(RequestMutation::configured(rules(&[("x-note", &"a".repeat(8192))], &[])).is_ok());
        assert!(HeaderValue::new("a".repeat(8193)).is_err());

        assert!(QueryParam::new("a", "b".repeat(1024)).is_ok());
        assert!(QueryParam::new("a", "b".repeat(1025)).is_err());
    }

    /// A rule drops `session id`. The client's `session%20id=1`, with the
    /// escape in the middle of the name, is dropped.
    #[test]
    fn a_percent_encoded_name_is_matched_wherever_the_escape_sits() {
        let mutation = RequestMutation::configured(query_rules(&[], &["session id"])).unwrap();

        assert!(mutation.apply_to_query(Some("session%20id=1")).is_none());
    }

    /// A truncated escape in `a%2=1` remains unchanged when applying a rule
    /// that removes the unrelated parameter `b`.
    #[test]
    fn a_truncated_escape_is_left_as_written() {
        let mutation = RequestMutation::configured(query_rules(&[], &["b"])).unwrap();

        assert_eq!(
            mutation.apply_to_query(Some("a%2=1")),
            Some("a%2=1".to_owned())
        );
    }

    /// `page` and `session id` are valid parameter names.
    #[test]
    fn a_well_formed_query_name_is_accepted() {
        for value in ["page", "session id"] {
            assert!(QueryName::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// An empty name and one with a line feed are refused.
    #[test]
    fn a_malformed_query_name_is_refused() {
        for value in ["", "a\nb"] {
            assert!(QueryName::new(value).is_err(), "{value:?} was accepted");
        }
    }

    /// An empty value and `a b` are valid parameter values. A value may be
    /// empty, unlike a name.
    #[test]
    fn a_well_formed_query_value_is_accepted() {
        for value in ["", "a b"] {
            assert!(QueryValue::new(value).is_ok(), "{value:?} was refused");
        }
    }

    /// A value with a line feed is refused.
    #[test]
    fn a_malformed_query_value_is_refused() {
        assert!(QueryValue::new("a\nb").is_err());
    }
}
