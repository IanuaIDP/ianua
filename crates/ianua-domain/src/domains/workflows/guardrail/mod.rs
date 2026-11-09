//! Guardrails: checking a text from an earlier step before a workflow goes
//! on with it.
//!
//! A guardrail step reads one value, often an agent's answer, and checks
//! it for personal data, for known ways of tricking a model and for the
//! words it bans. Personal data is what the tenant's own classification
//! rules hold sensitive, the same rules the gateway hides fields by, and
//! the shapes personal data takes in free text. Each finding records its
//! kind and place, never the text it matched.
//!
//! The step hands on what it checked under [`CHECKED_FIELD`], with what
//! was found taken out when it removes findings, the findings under
//! [`FINDINGS_FIELD`] and how many there were under [`FOUND_FIELD`].

pub mod banned;
pub mod finding;
pub mod scan;
pub mod shapes;
pub mod tricks;
pub mod words;

/// The field a guardrail hands on the value it checked under: as it was,
/// or with its findings taken out when the step removes them.
pub const CHECKED_FIELD: &str = "checked";

/// The field a guardrail hands on its findings under: each one's kind,
/// check and place.
pub const FINDINGS_FIELD: &str = "findings";

/// The field a guardrail hands on how many findings there were in all.
pub const FOUND_FIELD: &str = "found";
