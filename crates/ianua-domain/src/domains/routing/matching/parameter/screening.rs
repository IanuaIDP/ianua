//! Screening a request's parameters against a route's rules.

use crate::domains::routing::matching::parameter::address::names_an_address;
use crate::domains::routing::matching::parameter::{
    CONSUMED_HEADERS, ParameterLocation, ParameterRule, rule_for,
};
use crate::shared::validation::distinct::first_repeat;
use crate::shared::web::percent;
use crate::types::UntrustedText;

/// Why a request's parameters were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterViolation {
    /// A declared parameter names a host not on its list, or no host.
    HostNotAllowed(UntrustedText),
    /// A value is encoded in a way that could hide what it names.
    OddEncoding(UntrustedText),
    /// A field no rule covers carries a URL or host name. The field's name
    /// comes from the request, so it is kept cleaned for the log it reaches.
    Undeclared(UntrustedText),
    /// An object in the body names the same key twice. Parsers disagree on
    /// which copy wins, so the one checked may not be the one used.
    DuplicateField(UntrustedText),
    /// The body could not be read whole, so its fields could not be checked.
    BodyUnreadable,
}

impl ParameterViolation {
    /// A short reason, naming the parameter but never its value.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::HostNotAllowed(name) => format!("parameter {name} names a host it may not"),
            Self::OddEncoding(name) => format!("parameter {name} is oddly encoded"),
            Self::Undeclared(name) => format!("field {name} carries an address no rule covers"),
            Self::DuplicateField(name) => format!("field {name} names a key twice"),
            Self::BodyUnreadable => "the body could not be checked".to_owned(),
        }
    }
}

/// One value in a request's JSON body, as the proxy read it.
///
/// Nested values are kept, since an address hidden in an array or an inner
/// object is still an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyValue {
    /// A string.
    Text(String),
    /// A number, as it was written.
    Number(String),
    /// `true` or `false`.
    Flag(bool),
    /// An explicit JSON absence, distinct from a missing object member.
    Null,
    /// An array.
    List(Vec<BodyValue>),
    /// An object, its keys in the order sent, duplicates kept.
    Object(Vec<(String, BodyValue)>),
}

impl Drop for BodyValue {
    /// Takes nested values apart one level at a time, so freeing a body
    /// nested deeper than the stack allows cannot crash the proxy.
    fn drop(&mut self) {
        let mut pending = Vec::new();
        take_children(self, &mut pending);
        while let Some(mut value) = pending.pop() {
            take_children(&mut value, &mut pending);
        }
    }
}

/// Moves `value`'s children onto `pending`, leaving it childless.
fn take_children(value: &mut BodyValue, pending: &mut Vec<BodyValue>) {
    match value {
        BodyValue::List(items) => pending.append(items),
        BodyValue::Object(entries) => pending.extend(entries.drain(..).map(|(_, inner)| inner)),
        BodyValue::Text(_) | BodyValue::Number(_) | BodyValue::Flag(_) | BodyValue::Null => {}
    }
}

/// The top-level fields of a request's JSON body, as the proxy read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyFields {
    /// There is no body.
    None,
    /// The body could not be read whole as a JSON object. It is not JSON, it
    /// was cut off at the inspection limit, or it is not an object.
    Unreadable,
    /// Each top-level field and its value, in the order sent, duplicates
    /// kept.
    Fields(Vec<(String, BodyValue)>),
}

/// A request's raw query string, without its `?`, or that it had none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawQuery<'a> {
    /// The URL had no `?`.
    Absent,
    /// The text after the `?`.
    Present(&'a str),
}

/// What a request carries, as the proxy saw it.
#[derive(Debug, Clone, Copy)]
pub struct RequestParameters<'a> {
    /// The raw query string, without its `?`.
    pub query: RawQuery<'a>,
    /// The body's fields.
    pub body: &'a BodyFields,
    /// What the route's pattern captured from the path, by name.
    pub captured: &'a [(String, String)],
    /// The request's headers, as sent.
    pub headers: &'a [(String, String)],
}

/// Checks a request against a route's rules.
///
/// A route with no rules passes everything. One with rules passes only
/// requests every rule admits.
///
/// Every place a request carries values is screened. That is the query, the
/// body, what the path pattern captures and the headers. Ann's rule keeps
/// `url` in the query to one host. Without the other places, Sam sends
/// `/fetch/evil.net/x` or an `X-Target: evil.net` header and reaches any host.
///
/// # Errors
///
/// - The first [`ParameterViolation`] found.
pub fn check(
    rules: &[ParameterRule],
    request: &RequestParameters<'_>,
) -> Result<(), ParameterViolation> {
    if rules.is_empty() {
        return Ok(());
    }
    for (raw_name, raw) in query_pairs(request.query) {
        let name = decoded(raw_name, raw_name)?;
        let value = decoded(&name, raw)?;
        judge(rules, ParameterLocation::Query, &name, &value)?;
    }
    for (name, value) in request.captured {
        judge(rules, ParameterLocation::Path, name, value)?;
    }
    for (name, value) in request
        .headers
        .iter()
        .filter(|(name, _)| !consumed_by_proxy(name))
    {
        judge(rules, ParameterLocation::Header, name, value)?;
    }
    match request.body {
        BodyFields::None => Ok(()),
        BodyFields::Unreadable => Err(ParameterViolation::BodyUnreadable),
        BodyFields::Fields(fields) => {
            ensure_unique_keys("body", fields.iter().map(|(name, _)| name.as_str()))?;
            fields
                .iter()
                .try_for_each(|(name, value)| judge_body(rules, name, value))
        }
    }
}

/// Whether the proxy reads or replaces `header` itself, so the upstream
/// never sees what the client put there.
fn consumed_by_proxy(header: &str) -> bool {
    let lowered = header.to_ascii_lowercase();
    CONSUMED_HEADERS.contains(&lowered.as_str())
        || crate::shared::web::proxy_headers::is_proxy_owned(header)
}

/// Judges one top-level body field.
///
/// A declared field must name an allowed host in every string it holds. It
/// must hold at least one, and no key naming another address. An undeclared
/// field must hold nothing that names an address, however deep, numbers
/// included.
///
/// The field's rule is found under any spelling a binder reads as its name.
/// ASP.NET, for one, binds `{"URL": ..}` to `url`.
fn judge_body(
    rules: &[ParameterRule],
    name: &str,
    value: &BodyValue,
) -> Result<(), ParameterViolation> {
    let rule = rule_for(rules, ParameterLocation::JsonBody, name);
    let field = || UntrustedText::record(name);
    let mut named_a_host = false;
    walk(value, |leaf| match (rule, leaf) {
        (Some(rule), Leaf::Text(text)) if rule.admits(text) => {
            named_a_host = true;
            Ok(())
        }
        (Some(rule), Leaf::Key(key)) if rule.admits(key) || !names_an_address(key) => Ok(()),
        (Some(_), _) => Err(ParameterViolation::HostNotAllowed(field())),
        (None, Leaf::Text(text) | Leaf::Key(text) | Leaf::Number(text))
            if names_an_address(text) =>
        {
            Err(ParameterViolation::Undeclared(field()))
        }
        (None, _) => Ok(()),
    })
    .map_err(|violation| match violation {
        WalkError::Duplicate => ParameterViolation::DuplicateField(field()),
        WalkError::Refused(violation) => violation,
    })?;
    if rule.is_some() && !named_a_host {
        return Err(ParameterViolation::HostNotAllowed(field()));
    }
    Ok(())
}

/// One thing found in a body value.
enum Leaf<'a> {
    /// A string.
    Text(&'a str),
    /// An object's key.
    Key(&'a str),
    /// A number, as it was written. Turned into text, `169.16689662` is an
    /// address to a resolver.
    Number(&'a str),
    /// A flag or null.
    Scalar,
}

/// Why a walk stopped.
enum WalkError {
    /// An object named a key twice.
    Duplicate,
    /// The visitor refused a leaf.
    Refused(ParameterViolation),
}

/// Visits every leaf and key of `value`. It loops instead of recursing, so a
/// deeply nested body cannot exhaust the stack.
fn walk(
    value: &BodyValue,
    mut visit: impl FnMut(Leaf<'_>) -> Result<(), ParameterViolation>,
) -> Result<(), WalkError> {
    let mut pending = vec![value];
    while let Some(current) = pending.pop() {
        match current {
            BodyValue::Text(text) => visit(Leaf::Text(text)).map_err(WalkError::Refused)?,
            BodyValue::Number(written) => {
                visit(Leaf::Number(written)).map_err(WalkError::Refused)?;
            }
            BodyValue::Flag(_) | BodyValue::Null => {
                visit(Leaf::Scalar).map_err(WalkError::Refused)?;
            }
            BodyValue::List(items) => pending.extend(items),
            BodyValue::Object(entries) => {
                ensure_unique_keys("object", entries.iter().map(|(key, _)| key.as_str()))
                    .map_err(|_| WalkError::Duplicate)?;
                for (key, inner) in entries {
                    visit(Leaf::Key(key)).map_err(WalkError::Refused)?;
                    pending.push(inner);
                }
            }
        }
    }
    Ok(())
}

/// Refuses a set of keys that names one twice.
fn ensure_unique_keys<'a>(
    within: &str,
    keys: impl Iterator<Item = &'a str>,
) -> Result<(), ParameterViolation> {
    let Some(key) = first_repeat(keys) else {
        return Ok(());
    };
    Err(ParameterViolation::DuplicateField(UntrustedText::record(
        if within == "body" { key } else { within },
    )))
}

fn judge(
    rules: &[ParameterRule],
    location: ParameterLocation,
    name: &str,
    value: &str,
) -> Result<(), ParameterViolation> {
    match rule_for(rules, location, name) {
        Some(rule) if rule.admits(value) => Ok(()),
        Some(_) => Err(ParameterViolation::HostNotAllowed(UntrustedText::record(
            name,
        ))),
        None if names_an_address(value) => {
            Err(ParameterViolation::Undeclared(UntrustedText::record(name)))
        }
        None => Ok(()),
    }
}

/// Every name and value pair in the query, split on `;` as well as `&`.
/// Servers that split on `;` read `x=1;host=evil.net` as two pairs, so both
/// are judged.
fn query_pairs(query: RawQuery<'_>) -> impl Iterator<Item = (&str, &str)> {
    let text = match query {
        RawQuery::Absent => "",
        RawQuery::Present(text) => text,
    };
    text.split(['&', ';'])
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
}

/// Decodes a query name or value once, as the upstream will. A name left
/// encoded would slip past the rule for it.
///
/// A value still holding `%` after one pass was encoded twice. That is how a
/// host gets past a check that decodes once, so it is refused.
fn decoded(name: &str, raw: &str) -> Result<String, ParameterViolation> {
    let odd = || ParameterViolation::OddEncoding(UntrustedText::record(name));
    let plus_spaced = raw.replace('+', " ");
    let bytes = percent::decode_strict(&plus_spaced).ok_or_else(odd)?;
    let value = String::from_utf8(bytes).map_err(|_| odd())?;
    if value.contains('%') || value.chars().any(char::is_control) || value.contains('\\') {
        return Err(odd());
    }
    Ok(value)
}
