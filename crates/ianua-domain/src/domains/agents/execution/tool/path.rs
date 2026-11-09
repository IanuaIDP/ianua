//! The path a tool calls, and the values a call fills it with.
//!
//! A tool's path is a template, such as `/orders/{id}`. The model fills each
//! `{name}` part from the arguments it sends. Those values are untrusted. A
//! value of `../admin/roles` would send the request somewhere else than the
//! template says. So each value is a [`PathValue`], which can only ever be
//! one plain path segment. And a call's class is worked out from the path it
//! really goes to.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};
use crate::types::CanonicalPath;

/// The longest value one part of a tool's path may take, in characters.
const MAX_PATH_VALUE_CHARS: usize = 256;

text_value! {
    /// The URL path template the tool calls, such as `/orders/{id}`.
    ///
    /// Each `{name}` that is a whole segment is filled from the call's
    /// values. Anything else is kept as written.
    pub struct ToolPath;
}

impl TextValue for ToolPath {
    const FIELD: &'static str = "tool_path";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.url_path(512)
    }
}

impl ToolPath {
    /// The names of the parts a call fills, in order. For `/orders/{id}`
    /// that is `id`.
    #[must_use]
    pub fn placeholders(&self) -> Vec<&str> {
        self.0.split('/').filter_map(placeholder).collect()
    }

    /// The template as routes read it, with each `{name}` kept as written.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when the template has no canonical spelling,
    ///   such as one holding `?` or a `..` segment.
    pub fn as_canonical(&self) -> Result<CanonicalPath, ValidationError> {
        CanonicalPath::new(self.0.as_str())
    }

    /// The path a call goes to: this template, with each part filled from
    /// `values`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `values` has no value for a part.
    /// - [`DomainError::Validation`] when `values` names a part the template
    ///   does not have.
    /// - [`DomainError::Validation`] when the filled path has no canonical
    ///   spelling.
    pub fn resolve(&self, values: &PathValues) -> Result<CanonicalPath, DomainError> {
        values.ensure_only(&self.placeholders())?;
        let segments = self
            .0
            .split('/')
            .map(|segment| filled(segment, values))
            .collect::<Result<Vec<&str>, DomainError>>()?;
        Ok(CanonicalPath::new(segments.join("/"))?)
    }
}

/// The name in a `{name}` segment, or `None` for a plain segment.
fn placeholder(segment: &str) -> Option<&str> {
    segment.strip_prefix('{')?.strip_suffix('}')
}

/// `segment`, or the value that fills it when it is a `{name}`.
fn filled<'a>(segment: &'a str, values: &'a PathValues) -> Result<&'a str, DomainError> {
    let Some(name) = placeholder(segment) else {
        return Ok(segment);
    };
    values.get(name).map(PathValue::as_str).ok_or_else(|| {
        DomainError::invalid(message!(
            "agents-the-call-gives-no-value-for",
            "the call gives no value for a part of the tool's path"
        ))
    })
}

text_value! {
    /// One value a call puts into a tool's path, such as the `42` in
    /// `/orders/42`.
    ///
    /// It is always exactly one plain segment. It never holds `/`, a
    /// backslash, `?`, `#`, `;` or `%`, and is never `.` or `..`. With no
    /// `%` at all, no percent-encoded `/` or `..` can get through either.
    pub struct PathValue;
}

impl TextValue for PathValue {
    const FIELD: &'static str = "path_value";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .char_length(1..=MAX_PATH_VALUE_CHARS)
            .no_control_chars()
            .no_invisible_chars()
            .rule(&OneSegment)
    }
}

/// What a value must be to stay one segment of the path it fills.
struct OneSegment;

impl Rule for OneSegment {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let problem = segment_problem(value)?;
        Some(ValidationError::Custom {
            field,
            code: "invalid_path_value".to_owned(),
            message: message!("agents-message", format!("{field} {problem}.")),
        })
    }
}

fn segment_problem(value: &str) -> Option<&'static str> {
    if matches!(value, "." | "..") {
        return Some("must not be '.' or '..'");
    }
    if value.contains(['/', '\\', '?', '#', ';', '%']) {
        return Some("must not hold '/', a backslash, '?', '#', ';' or '%'");
    }
    let trimmed_by_some_servers = value.ends_with('.')
        || value.starts_with(char::is_whitespace)
        || value.ends_with(char::is_whitespace);
    if trimmed_by_some_servers {
        return Some("must not start or end with a space, or end with '.'");
    }
    None
}

/// The values one call puts into a tool's path, by the name of the part
/// each fills.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathValues(Vec<(String, PathValue)>);

impl PathValues {
    /// No values, for a path with no parts to fill.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// These values, with `value` for the part named `name`. A second value
    /// for the same part replaces the first.
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: PathValue) -> Self {
        let name = name.into();
        self.0.retain(|(held, _)| *held != name);
        self.0.push((name, value));
        self
    }

    /// The value for the part named `name`.
    fn get(&self, name: &str) -> Option<&PathValue> {
        self.0
            .iter()
            .find(|(held, _)| held == name)
            .map(|(_, value)| value)
    }

    /// Refuses a value for a part not in `names`.
    fn ensure_only(&self, names: &[&str]) -> Result<(), DomainError> {
        if self
            .0
            .iter()
            .all(|(held, _)| names.contains(&held.as_str()))
        {
            return Ok(());
        }
        Err(DomainError::invalid(message!(
            "agents-the-call-gives-a-value-for",
            "the call gives a value for a part the tool's path does not have"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> PathValue {
        PathValue::new(text).unwrap()
    }

    /// Dot segments, slashes and backslash traversal are refused as path
    /// values because they could escape the template's single segment.
    #[test]
    fn a_value_that_climbs_out_of_its_segment_is_refused() {
        for hostile in ["../admin/roles", "..", ".", "1/../../admin", "1\\..\\admin"] {
            assert!(PathValue::new(hostile).is_err(), "{hostile}");
        }
    }

    /// Percent-encoded traversal, separators and query characters are
    /// refused, including a doubly encoded dot segment.
    #[test]
    fn a_percent_encoded_value_is_refused() {
        for hostile in ["%2e%2e%2fadmin", "%252e%252e", "%2F", "1%3Fadmin=1"] {
            assert!(PathValue::new(hostile).is_err(), "{hostile}");
        }
    }

    /// Query, fragment and matrix-parameter delimiters cannot enter a path
    /// value and change how the upstream interprets the target.
    #[test]
    fn a_value_carrying_a_query_or_fragment_is_refused() {
        for hostile in ["1?role=admin", "1#x", "1;x"] {
            assert!(PathValue::new(hostile).is_err(), "{hostile}");
        }
    }

    /// Ordinary ids such as `42`, `ord-4472` and `a.b` are taken as written.
    #[test]
    fn an_ordinary_id_is_a_path_value() {
        for id in ["42", "ord-4472", "a.b"] {
            assert_eq!(value(id).as_str(), id);
        }
    }

    /// `/orders/{id}/items/{item}` filled with 42 and 7 goes to
    /// `/orders/42/items/7`.
    #[test]
    fn a_template_is_filled_part_by_part() {
        let path = ToolPath::new("/orders/{id}/items/{item}").unwrap();
        let values = PathValues::new()
            .with("id", value("42"))
            .with("item", value("7"));

        let target = path.resolve(&values).unwrap();

        assert_eq!(target.as_str(), "/orders/42/items/7");
        assert_eq!(path.placeholders(), ["id", "item"]);
    }

    /// A call to `/orders/{id}` gives no `id`. It is refused, not sent to
    /// `/orders/{id}` as written.
    #[test]
    fn a_part_left_unfilled_is_refused() {
        let path = ToolPath::new("/orders/{id}").unwrap();

        assert!(matches!(
            path.resolve(&PathValues::new()),
            Err(DomainError::Validation(_))
        ));
    }

    /// A call to `/orders/{id}` also gives a value for `tenant`, which the
    /// path does not have. It is refused, so a misread template never goes
    /// unnoticed.
    #[test]
    fn a_value_for_a_part_the_path_lacks_is_refused() {
        let path = ToolPath::new("/orders/{id}").unwrap();
        let values = PathValues::new()
            .with("id", value("1"))
            .with("tenant", value("other"));

        assert!(path.resolve(&values).is_err());
    }

    /// Two values for `id` keep only the second, so a path never reads
    /// whichever came first.
    #[test]
    fn a_second_value_for_a_part_replaces_the_first() {
        let path = ToolPath::new("/orders/{id}").unwrap();
        let values = PathValues::new()
            .with("id", value("1"))
            .with("id", value("2"));

        assert_eq!(path.resolve(&values).unwrap().as_str(), "/orders/2");
    }
}
