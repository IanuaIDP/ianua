//! The data a workflow hands from step to step: a small tree of values.
//!
//! The tree has limits on depth and size, so no step can hand the next one
//! more than a workflow may carry. It is the domain's own type, not a JSON
//! value. Adapters turn what they read into it and back. Its rules on depth,
//! size and fields named twice hold wherever it is built.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};

/// The deepest a value may nest, counting each list or map inside another.
pub const MAX_DEPTH: usize = 16;

/// The largest a value may be, in bytes of text plus a small charge for each
/// value it holds.
pub const MAX_SIZE: usize = 1024 * 1024;

/// What each value costs towards [`MAX_SIZE`] besides its text.
const VALUE_COST: usize = 8;

text_value! {
    /// The name of one field of a map value.
    ///
    /// Letters, digits, `-` and `_`, so a [`DataPath`] can name it between
    /// dots without escaping.
    pub struct FieldName;
}

impl TextValue for FieldName {
    const FIELD: &'static str = "field_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=128).charset(
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE,
        )
    }
}

/// One value a step reads or produces.
///
/// It is built only through its constructors, and each checks what it adds.
/// A number is finite. A map names each field once. Nothing nests deeper
/// than [`MAX_DEPTH`] or grows larger than [`MAX_SIZE`].
#[derive(Debug, Clone, PartialEq)]
pub struct FlowData {
    value: Value,
    depth: usize,
    size: usize,
}

#[derive(Debug, Clone)]
enum Value {
    Null,
    Bool(bool),
    Number(f64),
    Text(String),
    List(Vec<FlowData>),
    Map(Vec<(FieldName, FlowData)>),
}

impl PartialEq for Value {
    /// Two values are alike when they hold the same data. A map's fields
    /// are kept in the order they were given, for showing, but that order
    /// carries no meaning: JSON, which data comes and goes as, does not
    /// keep it.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Number(left), Self::Number(right)) => left == right,
            (Self::Text(left), Self::Text(right)) => left == right,
            (Self::List(left), Self::List(right)) => left == right,
            (Self::Map(left), Self::Map(right)) => same_fields(left, right),
            _ => false,
        }
    }
}

/// Whether `left` and `right` name the same fields with alike values,
/// in whatever order. Each names a field once, so matching every field of
/// `left` in an equally long `right` matches them all.
fn same_fields(left: &[(FieldName, FlowData)], right: &[(FieldName, FlowData)]) -> bool {
    left.len() == right.len()
        && left.iter().all(|(name, value)| {
            right
                .iter()
                .any(|(other, kept)| other == name && kept == value)
        })
}

/// A view of one [`FlowData`], to match on.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowValue<'a> {
    /// Nothing.
    Null,
    /// True or false.
    Bool(bool),
    /// A finite number.
    Number(f64),
    /// A borrowed string scalar without copying its contents.
    Text(&'a str),
    /// Values in order.
    List(&'a [FlowData]),
    /// Named values, each field named once, in the order they were given.
    Map(&'a [(FieldName, FlowData)]),
}

impl FlowData {
    /// Nothing at all.
    #[must_use]
    pub fn null() -> Self {
        Self::leaf(Value::Null, 0)
    }

    /// True or false.
    #[must_use]
    pub fn bool(value: bool) -> Self {
        Self::leaf(Value::Bool(value), 0)
    }

    /// A number.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is not finite.
    pub fn number(value: f64) -> Result<Self, DomainError> {
        if !value.is_finite() {
            return Err(DomainError::invalid(message!(
                "api-a-workflow-number-must-be-finite",
                "a workflow number must be finite"
            )));
        }
        Ok(Self::leaf(Value::Number(value), 0))
    }

    /// Text.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is larger than [`MAX_SIZE`].
    pub fn text(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let size = value.len();
        Self::within_limits(Value::Text(value), 0, size)
    }

    /// Values in order.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the list nests deeper than
    ///   [`MAX_DEPTH`].
    /// - [`DomainError::Validation`] when the list is larger than
    ///   [`MAX_SIZE`].
    pub fn list(items: Vec<Self>) -> Result<Self, DomainError> {
        let depth = nested_depth(items.iter().map(|item| item.depth));
        let size = total_size(items.iter().map(|item| item.size));
        Self::within_limits(Value::List(items), depth, size)
    }

    /// Named values, in the order given.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a field is named twice.
    /// - [`DomainError::Validation`] when the map nests deeper than
    ///   [`MAX_DEPTH`].
    /// - [`DomainError::Validation`] when the map is larger than
    ///   [`MAX_SIZE`].
    pub fn map(entries: Vec<(FieldName, Self)>) -> Result<Self, DomainError> {
        if let Some(twice) = first_repeat(entries.iter().map(|(name, _)| name)) {
            return Err(DomainError::invalid(message!(
                "workflows-the-field-is-named-twice",
                format!("the field {twice} is named twice")
            )));
        }
        let depth = nested_depth(entries.iter().map(|(_, value)| value.depth));
        let size = total_size(
            entries
                .iter()
                .map(|(name, value)| name.as_str().len().saturating_add(value.size)),
        );
        Self::within_limits(Value::Map(entries), depth, size)
    }

    fn leaf(value: Value, size: usize) -> Self {
        Self {
            value,
            depth: 0,
            size: size.saturating_add(VALUE_COST),
        }
    }

    fn within_limits(value: Value, depth: usize, size: usize) -> Result<Self, DomainError> {
        let size = size.saturating_add(VALUE_COST);
        if depth > MAX_DEPTH {
            return Err(DomainError::invalid(message!(
                "workflows-workflow-data-may-nest-at-most",
                format!("workflow data may nest at most {MAX_DEPTH} levels deep")
            )));
        }
        if size > MAX_SIZE {
            return Err(DomainError::invalid(message!(
                "workflows-workflow-data-may-be-at-most",
                format!("workflow data may be at most {MAX_SIZE} bytes")
            )));
        }
        Ok(Self { value, depth, size })
    }

    /// The value, to match on.
    #[must_use]
    pub fn value(&self) -> FlowValue<'_> {
        match &self.value {
            Value::Null => FlowValue::Null,
            Value::Bool(value) => FlowValue::Bool(*value),
            Value::Number(value) => FlowValue::Number(*value),
            Value::Text(value) => FlowValue::Text(value),
            Value::List(items) => FlowValue::List(items),
            Value::Map(entries) => FlowValue::Map(entries),
        }
    }

    /// The value at `path`, if there is one.
    #[must_use]
    pub fn at(&self, path: &DataPath) -> Option<&Self> {
        path.steps
            .iter()
            .try_fold(self, |value, step| value.step(step))
    }

    fn step(&self, step: &PathStep) -> Option<&Self> {
        match (&self.value, step) {
            (Value::Map(entries), PathStep::Field(field)) => entries
                .iter()
                .find(|(name, _)| name == field)
                .map(|(_, value)| value),
            (Value::List(items), PathStep::Index(index)) => items.get(*index),
            (Value::Map(_), PathStep::Index(_))
            | (Value::List(_), PathStep::Field(_))
            | (
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::Text(_),
                PathStep::Field(_) | PathStep::Index(_),
            ) => None,
        }
    }

    /// The value of the field `name`, when this is a map holding it.
    #[must_use]
    pub fn field(&self, name: &FieldName) -> Option<&Self> {
        self.step(&PathStep::Field(name.clone()))
    }

    /// Whether it is null.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.value == Value::Null
    }

    /// Whether it holds nothing: null, empty text, an empty list or map.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match &self.value {
            Value::Null => true,
            Value::Text(text) => text.is_empty(),
            Value::List(items) => items.is_empty(),
            Value::Map(entries) => entries.is_empty(),
            Value::Bool(_) | Value::Number(_) => false,
        }
    }

    /// The value as text a model can read, in JSON notation, with fields in
    /// the order they were given.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write_to(&mut out);
        out
    }

    fn write_to(&self, out: &mut String) {
        match &self.value {
            Value::Null => out.push_str("null"),
            Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => out.push_str(&value.to_string()),
            Value::Text(text) => write_quoted(out, text),
            Value::List(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write_to(out);
                }
                out.push(']');
            }
            Value::Map(entries) => {
                out.push('{');
                for (index, (name, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_quoted(out, name.as_str());
                    out.push(':');
                    value.write_to(out);
                }
                out.push('}');
            }
        }
    }

    /// How deeply it nests. Zero for a single value.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// What it counts towards [`MAX_SIZE`].
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }
}

/// How deeply a list or map nests, given how deeply its values nest.
///
/// One level more than the deepest value. An empty one nests one level.
fn nested_depth(depths: impl Iterator<Item = usize>) -> usize {
    depths.max().map_or(1, |deepest| deepest.saturating_add(1))
}

/// The sizes added up, stopping at the largest number instead of wrapping.
fn total_size(sizes: impl Iterator<Item = usize>) -> usize {
    sizes.fold(0, usize::saturating_add)
}

/// `text` between double quotes, with quotes, backslashes and control
/// characters escaped as JSON escapes them.
fn write_quoted(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control.is_control() => {
                out.push_str(&format!("\\u{:04x}", u32::from(control)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// One step of a [`DataPath`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathStep {
    Field(FieldName),
    Index(usize),
}

/// Where to find a value inside another: field names and list positions,
/// written between dots, such as `orders.0.total`.
///
/// A step of digits alone is a list position. Anything else is a field
/// name. So a path cannot reach a field whose name is digits alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPath {
    steps: Vec<PathStep>,
}

/// The most steps a path may take.
const MAX_PATH_STEPS: usize = MAX_DEPTH + 1;

impl DataPath {
    /// Reads a path written as steps between dots.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it is empty or has an empty step.
    /// - [`DomainError::Validation`] when a step is not a field name or a
    ///   position.
    /// - [`DomainError::Validation`] when it has more steps than any value
    ///   can nest.
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let steps = text
            .split('.')
            .map(Self::step)
            .collect::<Result<Vec<_>, _>>()?;
        if steps.len() > MAX_PATH_STEPS {
            return Err(DomainError::invalid(message!(
                "workflows-a-data-path-may-take-at",
                format!("a data path may take at most {MAX_PATH_STEPS} steps")
            )));
        }
        Ok(Self { steps })
    }

    fn step(text: &str) -> Result<PathStep, DomainError> {
        if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
            return text.parse().map(PathStep::Index).map_err(|_| {
                DomainError::invalid(message!(
                    "workflows-a-list-position-in-a-data",
                    "a list position in a data path is too large"
                ))
            });
        }
        Ok(PathStep::Field(FieldName::new(text)?))
    }

    /// The field the path starts at. `None` when it starts at a list
    /// position.
    #[must_use]
    pub fn root(&self) -> Option<&FieldName> {
        match self.steps.first()? {
            PathStep::Field(name) => Some(name),
            PathStep::Index(_) => None,
        }
    }

    /// The path to the field `name` of the value at `base`, or of the root
    /// value when `base` is `None`.
    pub(crate) fn of_field(base: Option<&Self>, name: &FieldName) -> Self {
        Self::extended(base, PathStep::Field(name.clone()))
    }

    /// The path to the item at `index` of the list at `base`, or of the
    /// root list when `base` is `None`.
    pub(crate) fn of_index(base: Option<&Self>, index: usize) -> Self {
        Self::extended(base, PathStep::Index(index))
    }

    fn extended(base: Option<&Self>, step: PathStep) -> Self {
        let mut steps = base.map(|path| path.steps.clone()).unwrap_or_default();
        steps.push(step);
        Self { steps }
    }
}

impl std::fmt::Display for DataPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, step) in self.steps.iter().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            match step {
                PathStep::Field(name) => f.write_str(name.as_str())?,
                PathStep::Index(position) => write!(f, "{position}")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str) -> FieldName {
        FieldName::new(name).unwrap()
    }

    fn order() -> FlowData {
        FlowData::map(vec![
            (field("id"), FlowData::text("o-1").unwrap()),
            (field("total"), FlowData::number(41.5).unwrap()),
            (
                field("lines"),
                FlowData::list(vec![
                    FlowData::text("a").unwrap(),
                    FlowData::text("b").unwrap(),
                ])
                .unwrap(),
            ),
        ])
        .unwrap()
    }

    /// In an order with a total of 41.5 and lines "a" and "b", `total`
    /// finds 41.5 and `lines.1` finds "b". `lines.2` and `total.amount`
    /// find nothing.
    #[test]
    fn a_path_finds_fields_and_list_positions() {
        let data = order();

        assert_eq!(
            data.at(&DataPath::parse("total").unwrap())
                .map(FlowData::value),
            Some(FlowValue::Number(41.5))
        );
        assert_eq!(
            data.at(&DataPath::parse("lines.1").unwrap())
                .map(FlowData::value),
            Some(FlowValue::Text("b"))
        );
        assert_eq!(data.at(&DataPath::parse("lines.2").unwrap()), None);
        assert_eq!(data.at(&DataPath::parse("total.amount").unwrap()), None);
    }

    /// A note of `say "hi"` with a newline renders with the quotes and the
    /// newline escaped. Fields keep the order they were given in.
    #[test]
    fn data_renders_as_json_notation_with_text_escaped() {
        let data = FlowData::map(vec![
            (field("note"), FlowData::text("say \"hi\"\n").unwrap()),
            (field("ok"), FlowData::bool(true)),
            (field("none"), FlowData::null()),
        ])
        .unwrap();

        assert_eq!(
            data.render(),
            r#"{"note":"say \"hi\"\n","ok":true,"none":null}"#
        );
        assert_eq!(
            order().render(),
            r#"{"id":"o-1","total":41.5,"lines":["a","b"]}"#
        );
    }

    /// NaN, infinity and negative infinity are each refused as numbers.
    #[test]
    fn a_number_that_is_not_finite_is_refused() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(FlowData::number(value).is_err());
        }
    }

    /// A map with two fields called `id` is refused. A path to `id` could
    /// not say which one it meant.
    /// An order read back from JSON comes with its fields sorted by name.
    /// It is the same order as the one Ann's step handed on, field for
    /// field.
    #[test]
    fn maps_with_the_same_fields_in_another_order_are_alike() {
        let given = FlowData::map(vec![
            (field("total"), FlowData::number(12.0).unwrap()),
            (field("id"), FlowData::text("A-7").unwrap()),
        ])
        .unwrap();
        let sorted = FlowData::map(vec![
            (field("id"), FlowData::text("A-7").unwrap()),
            (field("total"), FlowData::number(12.0).unwrap()),
        ])
        .unwrap();
        let other = FlowData::map(vec![
            (field("id"), FlowData::text("A-8").unwrap()),
            (field("total"), FlowData::number(12.0).unwrap()),
        ])
        .unwrap();

        assert_eq!(given, sorted);
        assert_ne!(given, other);
    }

    #[test]
    fn a_map_naming_a_field_twice_is_refused() {
        let twice = FlowData::map(vec![
            (field("id"), FlowData::null()),
            (field("id"), FlowData::bool(true)),
        ]);

        assert!(twice.is_err());
    }

    /// Lists nested [`MAX_DEPTH`] deep are allowed and one more level is
    /// refused. A list of two texts, each half of [`MAX_SIZE`], is refused
    /// once the charge per value pushes it over.
    #[test]
    fn data_nested_too_deep_or_too_large_is_refused() {
        let deep =
            (0..MAX_DEPTH).try_fold(FlowData::null(), |inner, _| FlowData::list(vec![inner]));
        assert!(deep.is_ok());
        assert!(FlowData::list(vec![deep.unwrap()]).is_err());

        let half = FlowData::text("x".repeat(MAX_SIZE / 2)).unwrap();
        assert!(FlowData::list(vec![half.clone(), half]).is_err());
    }

    /// Null, empty text and an empty list read as empty. False and a full
    /// order do not.
    #[test]
    fn empty_values_read_as_empty() {
        assert!(FlowData::null().is_empty());
        assert!(FlowData::text("").unwrap().is_empty());
        assert!(FlowData::list(Vec::new()).unwrap().is_empty());
        assert!(!FlowData::bool(false).is_empty());
        assert!(!order().is_empty());
    }

    /// An empty path, `a..b`, `.a` and `a.b c` with a space are each
    /// refused.
    #[test]
    fn a_path_with_an_empty_or_unnamed_step_is_refused() {
        for text in ["", "a..b", "a.b c", ".a"] {
            assert!(DataPath::parse(text).is_err(), "{text:?}");
        }
    }
}
