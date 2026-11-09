use crate::shared::validation::ValidationError;

/// The error every domain operation returns.
///
/// Each variant is a business outcome, not a storage or transport error.
/// The API layer maps each variant to an HTTP status. The domain never
/// knows about HTTP.
///
/// A [`ValidationError`] converts into [`DomainError::Validation`] via
/// `From`.
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    /// The requested entity does not exist within the resolved tenant scope.
    #[error("entity not found")]
    NotFound,

    /// The operation would break a uniqueness rule, such as a second account
    /// with the same email in one tenant.
    #[error("conflict: {0}")]
    Conflict(Refusal),

    /// Input failed a check.
    ///
    /// That is a field's rule, or a business rule no single field owns, which
    /// is [`ValidationError::Rule`]. The error is kept whole, so its field and
    /// stable code reach whoever reports it.
    #[error("validation failed: {0}")]
    Validation(ValidationError),

    /// The tenant is suspended, so every operation in it is refused.
    #[error("tenant is suspended")]
    TenantSuspended,

    /// The caller's identity could not be verified. Credentials are missing
    /// or wrong.
    #[error("unauthorized: {0}")]
    Unauthorized(Refusal),

    /// The caller is known but may not do this.
    #[error("forbidden: {0}")]
    Forbidden(Refusal),

    /// A status move the state machine does not allow.
    #[error("invalid transition: {0}")]
    InvalidTransition(Refusal),

    /// Something outside the domain failed, such as the database, a cache or
    /// the network.
    ///
    /// It keeps the original error as its `#[source]`, so logs see every
    /// cause. Ports return this variant, so they never name an adapter's
    /// error type.
    #[error("infrastructure error")]
    Infrastructure(#[source] BoxedError),
}

/// Any error that can cross threads, as an infrastructure failure holds it.
pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

impl DomainError {
    /// Wraps any error as an infrastructure failure, keeping its causes.
    pub fn infra(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Infrastructure(Box::new(err))
    }

    /// Refuses because the operation would break a uniqueness rule.
    pub fn conflict(message: impl Into<Refusal>) -> Self {
        Self::Conflict(message.into())
    }

    /// Refuses because the caller's identity could not be verified.
    pub fn unauthorized(message: impl Into<Refusal>) -> Self {
        Self::Unauthorized(message.into())
    }

    /// Refuses because the caller may not do this.
    pub fn forbidden(message: impl Into<Refusal>) -> Self {
        Self::Forbidden(message.into())
    }

    /// Refuses a move its state machine does not allow.
    pub fn invalid_transition(message: impl Into<Refusal>) -> Self {
        Self::InvalidTransition(message.into())
    }

    /// Refuses input that breaks a business rule no single field owns.
    pub fn invalid(message: impl Into<Refusal>) -> Self {
        Self::Validation(ValidationError::Rule {
            message: message.into(),
        })
    }

    /// The words the caller reads, with their message key when they have
    /// one; none for an outcome that carries no words of its own.
    #[must_use]
    pub fn refusal(&self) -> Option<Refusal> {
        match self {
            Self::Validation(invalid) => Some(invalid.refusal()),
            Self::Conflict(refusal)
            | Self::Unauthorized(refusal)
            | Self::Forbidden(refusal)
            | Self::InvalidTransition(refusal) => Some(refusal.clone()),
            Self::NotFound | Self::TenantSuspended | Self::Infrastructure(_) => None,
        }
    }

    /// An infrastructure failure described by a message, when there is no
    /// error to wrap.
    ///
    /// For example, a subprocess printed something it should not.
    pub fn infra_msg(msg: impl Into<String>) -> Self {
        Self::Infrastructure(Box::new(InfraMessage(msg.into())))
    }

    /// Refuses a stored `entity` whose row contradicts itself or breaks a
    /// rule the entity always keeps.
    ///
    /// No code path could have written such a row, so the fault is the
    /// store's, not the caller's. The reason is fixed text, so no stored
    /// value reaches a log line.
    pub fn corrupt_row(entity: &'static str, reason: &'static str) -> Self {
        Self::Infrastructure(Box::new(CorruptRow {
            entity,
            reason,
            broken_rule: None,
        }))
    }

    /// Refuses a stored `entity` holding a value that no longer passes its
    /// own rules, keeping the rule it breaks as the cause.
    ///
    /// The cause names the field and the limit it breaks, such as a size, so
    /// a log tells one corrupt value from another. Pass only a rule's error
    /// that does not quote the stored value.
    pub fn corrupt_value(
        entity: &'static str,
        reason: &'static str,
        broken_rule: ValidationError,
    ) -> Self {
        Self::Infrastructure(Box::new(CorruptRow {
            entity,
            reason,
            broken_rule: Some(broken_rule),
        }))
    }
}

impl From<ValidationError> for DomainError {
    fn from(err: ValidationError) -> Self {
        Self::Validation(err)
    }
}

impl From<Refusal> for DomainError {
    /// A refusal of input on its own is a business rule the input breaks.
    fn from(refusal: Refusal) -> Self {
        Self::invalid(refusal)
    }
}

/// Why a request was turned away, in the words the caller reads.
///
/// Every error message the domain shows is a refusal, validation messages
/// included. A refusal often names what the caller sent, such as "an
/// account for `alice@example.com` already exists". So its words are not
/// trusted either.
///
/// A refusal is never refused, since it must still be reported. Instead it
/// is made safe to show and to log. It is cut to `MAX_REFUSAL_CHARS`
/// characters. Every character that could start a new log line, drive a
/// terminal or hide the text is replaced.
///
/// A refusal made with [`message!`](crate::message) also carries its
/// message key and the values its text was filled with, so a caller can
/// read it in its own language. The values are made safe the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    text: String,
    wording: Wording,
}

/// How a refusal can be read in another language. A keyed wording is
/// boxed, so every error that holds a refusal stays small.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Wording {
    /// Only in its English words: no message names it.
    EnglishOnly,
    /// As its message names it, filled with its values.
    Keyed(Box<KeyedWording>),
}

/// The message a refusal reads as, and the values that fill it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyedWording {
    key: &'static str,
    values: Vec<RefusalValue>,
}

/// One value a refusal's words were filled with, under the name its
/// message gives it, such as `from` or `arg0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalValue {
    name: &'static str,
    value: String,
}

impl RefusalValue {
    /// The name the message gives the value.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The value as the refusal's words show it, made safe.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// The longest a refusal's words are kept, in characters.
pub(crate) const MAX_REFUSAL_CHARS: usize = 1024;

impl Refusal {
    /// The refusal `message` describes, made safe to show, with no key.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            text: safe(&message.into()),
            wording: Wording::EnglishOnly,
        }
    }

    /// The refusal `message` describes under its message `key`, with the
    /// named `values` its text was filled with. Called by
    /// [`message!`](crate::message), which names the values.
    pub fn keyed(
        key: &'static str,
        message: impl Into<String>,
        values: Vec<(&'static str, String)>,
    ) -> Self {
        let values = values
            .into_iter()
            .map(|(name, value)| RefusalValue {
                name,
                value: safe(&value),
            })
            .collect();
        Self {
            text: safe(&message.into()),
            wording: Wording::Keyed(Box::new(KeyedWording { key, values })),
        }
    }

    /// The words, as the caller reads them.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The message key, when the refusal was made with one.
    #[must_use]
    pub fn key(&self) -> Option<&'static str> {
        match &self.wording {
            Wording::Keyed(keyed) => Some(keyed.key),
            Wording::EnglishOnly => None,
        }
    }

    /// The named values the text was filled with.
    #[must_use]
    pub fn values(&self) -> &[RefusalValue] {
        match &self.wording {
            Wording::Keyed(keyed) => &keyed.values,
            Wording::EnglishOnly => &[],
        }
    }
}

/// `text` made safe to show and log, cut to its limit.
fn safe(text: &str) -> String {
    crate::shared::validation::safe_text::made_safe(text, MAX_REFUSAL_CHARS)
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl PartialEq<str> for Refusal {
    /// Whether the refusal reads exactly `other`.
    fn eq(&self, other: &str) -> bool {
        self.text == other
    }
}

impl PartialEq<&str> for Refusal {
    /// Whether the refusal reads exactly `other`.
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

impl From<String> for Refusal {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for Refusal {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

/// A plain message used as an error source.
#[derive(Debug)]
struct InfraMessage(String);

impl std::fmt::Display for InfraMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InfraMessage {}

/// A stored row that contradicts itself, named by the entity it was meant
/// to rebuild.
#[derive(Debug, thiserror::Error)]
#[error("stored {entity} is corrupt: {reason}")]
pub(crate) struct CorruptRow {
    entity: &'static str,
    reason: &'static str,
    #[source]
    broken_rule: Option<ValidationError>,
}

#[cfg(test)]
impl CorruptRow {
    /// The entity named by a corrupt-row assertion.
    #[must_use]
    pub(crate) fn entity(&self) -> &'static str {
        self.entity
    }
}

/// An error and everything that caused it, joined with `: `.
///
/// Use this at log sites that diagnose a failure.
///
/// [`DomainError::Infrastructure`] displays as the bare words
/// "infrastructure error". That way a cause holding a connection string or
/// a host name cannot reach a user through `to_string()`. But `%error` at a
/// log site then prints only those two words. A failing TLS handshake and a
/// database that is down read the same. The log formatter prints the causes
/// too.
///
/// ```
/// use ianua_domain::shared::errors::{DomainError, causes};
///
/// let error = DomainError::infra_msg("grpc connect: connection refused");
/// assert_eq!(
///     causes(&error),
///     "infrastructure error: grpc connect: connection refused"
/// );
/// ```
#[must_use]
pub fn causes(error: &dyn std::error::Error) -> String {
    let mut chain = vec![error.to_string()];
    let mut current = error.source();

    while let Some(cause) = current {
        chain.push(cause.to_string());
        current = cause.source();
    }

    chain.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An infrastructure error made from "grpc connect: connection refused"
    /// shows only "infrastructure error". The causes still end with that
    /// message, so a log can tell one failure from another.
    #[test]
    fn causes_reaches_past_the_opaque_display() {
        let error = DomainError::infra_msg("grpc connect: connection refused");

        assert_eq!(error.to_string(), "infrastructure error");
        assert!(causes(&error).ends_with("grpc connect: connection refused"));
    }

    /// `NotFound` has no source, so its causes are its own words and nothing
    /// is joined after them.
    #[test]
    fn causes_of_a_sourceless_error_is_just_that_error() {
        let error = DomainError::NotFound;

        assert_eq!(causes(&error), "entity not found");
    }

    /// A business-rule error and an empty-field error each read
    /// "validation failed: " plus their own message. The API shows these
    /// words to callers, so they stay exact.
    #[test]
    fn a_validation_error_reads_as_it_always_has() {
        let rule = DomainError::invalid("a client must be allowed at least one grant type");
        let field: DomainError = ValidationError::Empty { field: "name" }.into();

        assert_eq!(
            rule.to_string(),
            "validation failed: a client must be allowed at least one grant type"
        );
        assert_eq!(
            field.to_string(),
            "validation failed: name is required and cannot be left blank."
        );
    }

    /// An empty `name` turned into a domain error still reports the field
    /// `name` and the code `required`, so a form can mark the right input.
    #[test]
    fn a_validation_error_keeps_its_field_and_code() {
        let DomainError::Validation(error) = ValidationError::Empty { field: "name" }.into() else {
            panic!("a validation error converts into DomainError::Validation");
        };

        assert_eq!(error.field(), Some("name"));
        assert_eq!(error.code(), "required");
        assert_eq!(
            DomainError::invalid("x").to_string(),
            "validation failed: x"
        );
    }

    /// A conflict message quoting a name with a newline has that newline
    /// removed from its displayed refusal, preventing a second log line.
    #[test]
    fn a_refusal_cannot_forge_a_log_line() {
        let refused = DomainError::conflict("`a\nlevel=INFO msg=ok` is taken");

        assert!(!refused.to_string().contains('\n'));
    }

    /// Validation refusals remove newlines, Unicode line separators and
    /// direction overrides from displayed input, keeping log text unambiguous.
    #[test]
    fn a_validation_message_is_made_safe_like_any_refusal() {
        for forged in [
            "not an actor label: x\nlevel=INFO msg=ok",
            "evil\u{2028}level=INFO msg=ok",
            "name \u{202E}gnp.exe",
        ] {
            let refused = DomainError::invalid(forged).to_string();

            assert!(
                !refused.contains(['\n', '\u{2028}', '\u{202E}']),
                "{refused:?}"
            );
        }
    }

    /// A stored row holds an empty name. The error reads as a corrupt row,
    /// and its causes end with the rule the name breaks.
    #[test]
    fn a_corrupt_value_keeps_the_rule_it_breaks() {
        let error = DomainError::corrupt_value(
            "role",
            "its name is not valid",
            ValidationError::Empty { field: "name" },
        );

        let chain = causes(&error);

        assert!(chain.contains("stored role is corrupt: its name is not valid"));
        assert!(chain.ends_with("name is required and cannot be left blank."));
    }

    /// "only the owner may do this" reads the same after the refusal is made
    /// safe. Ordinary words are not changed.
    #[test]
    fn a_refusal_reads_as_it_was_written() {
        let refused = DomainError::forbidden("only the owner may do this");

        assert_eq!(refused.to_string(), "forbidden: only the owner may do this");
    }

    /// A refusal ten characters over [`MAX_REFUSAL_CHARS`] keeps exactly
    /// that many characters.
    #[test]
    fn a_long_refusal_is_cut_to_its_limit() {
        let refusal = Refusal::new("x".repeat(MAX_REFUSAL_CHARS + 10));

        assert_eq!(refusal.as_str().chars().count(), MAX_REFUSAL_CHARS);
    }

    /// A keyed refusal keeps its key, its English text and each value its
    /// text was filled with, under the value's field name.
    #[test]
    fn a_keyed_refusal_keeps_its_key_and_values() {
        let (from, to) = ("active", "draft");

        let refusal = crate::message!(
            "routing-cannot-move-a-route-from-to",
            format!("cannot move a route from {from:?} to {to}")
        );

        assert_eq!(
            refusal.as_str(),
            "cannot move a route from \"active\" to draft"
        );
        assert_eq!(refusal.key(), Some("routing-cannot-move-a-route-from-to"));
        assert_eq!(values(&refusal), [("from", "\"active\""), ("to", "draft")]);
    }

    /// Unnamed fields are named by position, the way the Fluent resources name them.
    #[test]
    fn unnamed_fields_are_named_by_position() {
        let refusal = crate::message!("routing-x", format!("{} of {}", 2, "three"));

        assert_eq!(values(&refusal), [("arg0", "2"), ("arg1", "three")]);
    }

    /// A keyed refusal strips a newline from its interpolated value, keeping
    /// translation parameters safe to log.
    #[test]
    fn a_keyed_value_is_made_safe() {
        let name = "Ann\nERROR forged";

        let refusal = crate::message!("people-x", format!("{name} is taken"));

        assert!(!refusal.values()[0].value().contains('\n'));
    }

    /// A refusal's values as name and value pairs.
    fn values(refusal: &Refusal) -> Vec<(&'static str, &str)> {
        refusal
            .values()
            .iter()
            .map(|value| (value.name(), value.value()))
            .collect()
    }

    /// A literal refusal is keyed with no values.
    #[test]
    fn a_literal_keyed_refusal_has_no_values() {
        let refusal = crate::message!("people-x", "Not yours");

        assert_eq!(refusal.as_str(), "Not yours");
        assert!(refusal.values().is_empty());
    }
}
