//! The tenant's links to the outside, over the real protocols: an
//! application of Pat's own signing her in over OpenID Connect, a
//! directory making and removing people over SCIM, a domain the tenant
//! proves and serves an app on, and the keys a program calls the API
//! with. Every link is bound to Tess's authority, every secret shown once
//! and found nowhere else.
//!
//! - `oauth`: an application completes the code flow with PKCE, verifies
//!   Pat's ID token against the published keys, reads who she is, trades
//!   its refresh token and gives its access up; a wrong callback or
//!   verifier gets nothing; a refresh token used twice takes its
//!   successor down; signing out through the application ends Pat's
//!   session and its tokens.
//! - `device`: Pat types the code her TV shows and the TV collects her
//!   tokens; a refused or unanswered TV gets none; only Pat answers.
//! - `directory`: a directory makes Pat, who proves her mailbox and signs
//!   in, and later deactivates her, ending her session; its token is
//!   rotated and the link switched off; only Tess sets it up.
//! - `domains`: a domain is proved by its DNS record and serves an app on
//!   the certificate the tenant brought; only Tess removes it.
//! - `services`: a program's key reads what its scopes allow, loses it when
//!   they narrow, and dies when the key is revoked or replaced; only Tess
//!   revokes a key.

#![cfg(test)]

mod device;
mod directory;
mod domains;
mod oauth;
mod services;
