pub mod clock;
/// Validation limits for slugs, display names and input size.
pub mod config;
/// The domain error type.
pub mod errors;
/// Domain events: the envelope that carries one, its payload, and the bus that publishes it.
pub mod events;
/// Building blocks every aggregate uses: the aggregate trait, status moves, row checks, two-case flags and limits.
pub mod model;
/// The randomness the domain draws on, as a port.
pub mod random;
/// Security primitives: changes only a person may make, constant-time comparison, internal-address screening and secrets.
pub mod security;
/// Shared input validation used by value objects.
pub mod validation;
/// How the web spells things: percent-encoding, request parameter names and the headers a proxy owns.
pub mod web;
/// Reading keywords out of text as whole words and their regular forms.
pub mod words;
