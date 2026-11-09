//! What the gateway believes and what it vouches for: no header a caller
//! sets, no session cookie Mallory made or altered, no token she forged,
//! and no session left idle past its window lets anybody in. What reaches
//! the app about the caller is the gateway's signed word alone.
//!
//! - `headers`: Pat's own claims and a real assertion she kept from
//!   someone else are dropped; the app verifies the one the gateway signed.
//! - `sessions`: forged, altered, foreign and doubled session cookies, and
//!   forged tokens, are refused without reaching the app.
//! - `expiry`: a session left idle past the tenant's window ends, and only
//!   a fresh sign-in lets Pat back.

mod expiry;
mod headers;
mod sessions;
