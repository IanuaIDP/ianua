/// Classification rules for response fields, and how the proxy's Redact
/// stage hides them.
pub mod classification;
/// Who may change how the tenant's response fields are classified.
pub mod control;
/// What adding and removing classification rules records.
pub mod events;
/// How sensitive data is, from public to restricted.
pub mod level;
pub(crate) mod sealed;
