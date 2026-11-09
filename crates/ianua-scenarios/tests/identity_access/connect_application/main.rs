//! Outside apps that sign people in with the tenant as their identity
//! provider, each checking the platform's answers with code of its own,
//! and services and programs proving themselves to the tenant.
//!
//! - `saml`: Ledger, a SAML app Tess registers, learns the tenant from its
//!   published metadata, sends Pat's browser with its request, and
//!   accepts the platform's signed answer for her; the answer is good
//!   once, a changed one fails Ledger's check, and an app Tess never
//!   registered, an address she never allowed or a switched-off app gets
//!   no answer. Once Ledger signs its requests, an unsigned or foreign
//!   one is not answered.
//! - `initiated`: Pat signing in to Ledger from the tenant's side, with no
//!   request from Ledger, for the person signed in and an app that is on.
//! - `logout`: single logout with Ledger either way. Ledger's request ends
//!   Pat's session only when it names her, and is taken once; Pat signing
//!   out at the platform sends Ledger a signed request for her, whose
//!   answer is taken.
//! - `oidc`: apps over OpenID Connect: what the tenant publishes, requests
//!   that get no code, consent and its withdrawal, forged tokens and
//!   tokens bound to a key.
//! - `machines`: services with a secret or a signed assertion, and token
//!   exchange.
//! - `keys`: a program's API key paused and resumed, within its scopes.
//! - `key_ends`: a key with an end, refused from then on like a wrong key
//!   and swept once; an end behind now refused; a key that cannot outlive
//!   the key that made it.

#![cfg(test)]

mod clients;
mod initiated;
mod key_ends;
mod keys;
mod logout;
mod machines;
mod oidc;
mod saml;
mod support;
