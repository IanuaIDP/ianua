//! Apps signing people in over OpenID Connect, each checking the
//! platform's answers with code of its own.
//!
//! - `discovery`: what the tenant publishes, its keys public only and its
//!   own, and an ID token checked against nothing else.
//! - `requests`: a request that drops PKCE or asks for a token in the
//!   address bar gets no code, and an address never registered is told
//!   nothing.
//! - `consent`: Pat's consent, asked once, shown back to her, and
//!   withdrawn, ending what the app holds for her.
//! - `forged`: unsigned, re-signed, changed, misused and foreign tokens get
//!   nothing, and a real one ends with its time.
//! - `bound`: tokens bound to an app's key work only with a fresh proof
//!   from that key.

mod bound;
mod consent;
mod discovery;
mod forged;
mod requests;
