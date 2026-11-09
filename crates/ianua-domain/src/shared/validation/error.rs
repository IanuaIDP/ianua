//! A failed validation rule, tied to the field it failed on.

use crate::message;
use crate::shared::errors::Refusal;

/// A failed validation rule tied to a specific field.
///
/// Every variant gives:
/// - [`field`](Self::field): the machine-readable name of the input
/// - [`code`](Self::code): a stable identifier for the kind of mistake
/// - [`refusal`](Self::refusal): a message a person can read in a UI,
///   with its message key so it can be read in their language; `Display`
///   shows its English
/// - its own data, so a structured error can be built without parsing the
///   message
///
/// # JSON response example
///
/// The API sends only the message. A structured response built from the
/// rest could look like this:
/// ```json
/// {
///   "field": "slug",
///   "code": "invalid_length",
///   "message": "Slug must be between 2 and 63 characters long. You provided 1 character.",
///   "constraints": { "min": 2, "max": 63, "actual": 1 }
/// }
/// ```
#[derive(Debug)]
pub enum ValidationError {
    /// The input length falls outside the allowed range.
    Length {
        /// The input that failed.
        field: &'static str,
        /// The shortest allowed length.
        min: usize,
        /// The longest allowed length.
        max: usize,
        /// The length the input had.
        actual: usize,
    },

    /// The input contains characters outside the permitted set.
    InvalidCharacters {
        /// The input that failed.
        field: &'static str,
        /// A readable description of the characters that are allowed.
        allowed: String,
    },

    /// The first or last character violates the boundary constraint.
    InvalidBoundary {
        /// The input that failed.
        field: &'static str,
        /// A readable description of what the input must start and end with.
        expected: &'static str,
    },

    /// The input is empty where a value is required.
    Empty {
        /// The input that failed.
        field: &'static str,
    },

    /// The input contains non-ASCII bytes where only ASCII is permitted.
    NotAscii {
        /// The input that failed.
        field: &'static str,
    },

    /// A numeric value falls outside the allowed range.
    OutOfRange {
        /// The input that failed.
        field: &'static str,
        /// The smallest allowed value.
        min: u64,
        /// The largest allowed value.
        max: u64,
        /// The value the input had.
        actual: u64,
    },

    /// A list holds fewer or more entries than allowed.
    Count {
        /// The input that failed.
        field: &'static str,
        /// The fewest entries allowed.
        min: usize,
        /// The most entries allowed.
        max: usize,
        /// The number of entries the input had.
        actual: usize,
    },

    /// A business rule the input breaks that belongs to no single field,
    /// such as two settings contradicting each other.
    Rule {
        /// The message shown to the user, made safe to show and log since
        /// it may quote what they sent.
        message: Refusal,
    },

    /// A failed check that brings its own code and message.
    ///
    /// Format checks built on the [`Rule`](crate::shared::validation::Rule)
    /// trait return it, and so do checks such as the internal-address
    /// screen.
    Custom {
        /// The input that failed.
        field: &'static str,
        /// The stable error code returned by [`code`](ValidationError::code).
        code: String,
        /// The message shown to the user, made safe to show and log since
        /// it may quote what they sent.
        message: Refusal,
    },
}

impl ValidationError {
    /// Machine-readable field name identifying which input failed, or `None`
    /// for a [`Rule`](Self::Rule) no single field owns.
    ///
    /// Stable across versions, so a structured error response can name the
    /// input without parsing the display message. The API sends only the
    /// message.
    #[must_use]
    pub fn field(&self) -> Option<&'static str> {
        let field = match self {
            Self::Length { field, .. }
            | Self::InvalidCharacters { field, .. }
            | Self::InvalidBoundary { field, .. }
            | Self::Empty { field, .. }
            | Self::NotAscii { field, .. }
            | Self::OutOfRange { field, .. }
            | Self::Count { field, .. }
            | Self::Custom { field, .. } => field,
            Self::Rule { .. } => return None,
        };
        Some(field)
    }

    /// Stable error code for programmatic consumption.
    ///
    /// Lets a client match on the kind of mistake without depending on the
    /// message text, for example to highlight the right form field. The API
    /// sends only the message.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Length { .. } => "invalid_length",
            Self::InvalidCharacters { .. } => "invalid_characters",
            Self::InvalidBoundary { .. } => "invalid_boundary",
            Self::Empty { .. } => "required",
            Self::NotAscii { .. } => "not_ascii",
            Self::OutOfRange { .. } => "out_of_range",
            Self::Count { .. } => "invalid_count",
            Self::Rule { .. } => "invalid",
            Self::Custom { code, .. } => code,
        }
    }

    /// The message a person reads, under its message key, with the values
    /// it was filled with.
    #[must_use]
    pub fn refusal(&self) -> Refusal {
        match self {
            Self::Length {
                field,
                min,
                max,
                actual,
            } => length(field, *min, *max, *actual),
            Self::InvalidCharacters { field, allowed } => characters_allowed(field, allowed),
            Self::InvalidBoundary { field, expected } => boundary(field, expected),
            Self::Empty { field } => empty(field),
            Self::NotAscii { field } => not_ascii(field),
            Self::OutOfRange {
                field,
                min,
                max,
                actual,
            } => range(field, *min, *max, *actual),
            Self::Count {
                field,
                min,
                max,
                actual,
            } => count(field, *min, *max, *actual),
            Self::Rule { message } | Self::Custom { message, .. } => message.clone(),
        }
    }
}

fn length(field: &str, min: usize, max: usize, actual: usize) -> Refusal {
    message!(
        "values-must-be-between-and-characters-long",
        format!(
            "{field} must be between {min} and {max} characters long. You provided {actual} {}.",
            characters(actual)
        )
    )
}

fn characters_allowed(field: &str, allowed: &str) -> Refusal {
    message!(
        "values-can-only-contain-please-remove-any",
        format!("{field} can only contain {allowed}. Please remove any other characters.")
    )
}

fn boundary(field: &str, expected: &str) -> Refusal {
    message!(
        "values-must-start-and-end-with",
        format!("{field} must start and end with {expected}.")
    )
}

fn empty(field: &str) -> Refusal {
    message!(
        "values-is-required-and-cannot-be-left",
        format!("{field} is required and cannot be left blank.")
    )
}

fn not_ascii(field: &str) -> Refusal {
    message!(
        "values-must-contain-only-ascii-characters-please",
        format!(
            "{field} must contain only ASCII characters. Please remove any special or international characters."
        )
    )
}

fn range(field: &str, min: u64, max: u64, actual: u64) -> Refusal {
    message!(
        "values-must-be-between-and-you-provided",
        format!("{field} must be between {min} and {max}. You provided {actual}.")
    )
}

fn count(field: &str, min: usize, max: usize, actual: usize) -> Refusal {
    message!(
        "values-must-list-you-listed",
        format!(
            "{field} must list {}. You listed {actual}.",
            count_bounds(min, max)
        )
    )
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.refusal().as_str())
    }
}

impl std::error::Error for ValidationError {}

/// How many entries a list may hold, in words.
fn count_bounds(min: usize, max: usize) -> String {
    if max == usize::MAX {
        return format!("at least {min} {}", entries(min));
    }
    if min == max {
        return format!("exactly {min} {}", entries(min));
    }
    format!("between {min} and {max} entries")
}

fn entries(count: usize) -> &'static str {
    if count == 1 {
        return "entry";
    }
    "entries"
}

fn characters(count: usize) -> &'static str {
    if count == 1 {
        return "character";
    }
    "characters"
}
