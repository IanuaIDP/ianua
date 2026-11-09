//! Starting, probing and stopping the real platform, and publishing the
//! discovery documents and public keys its clients need. Installation and
//! first usable owner access are covered by `accounts/sign_up/installation`.
//!
//! Bob, the platform's operator, signs in with his password for a key and
//! runs the platform with it, and a tenant's administrator replaces its
//! signing key.
//!
//! - `starts`: readiness through the internal listener and clean shutdown.
//! - `published`: public discovery, distinct keys and unknown tenant privacy.
//! - `operators`: Bob's sign-in and key, a closed company staying closed
//!   even to him, and guessing his password locking out the guesser's
//!   network and never Bob.
//! - `sign_in_records`: every refused operator sign-in recorded in the
//!   platform's log with its true reason and network, sign-ins that
//!   worked recorded as keys made, no password in any record, and the log
//!   closed to tenant administrators.
//! - `impersonation`: Bob acting as Pat through his grant, only in her
//!   tenant and only while the grant holds; what he changes recorded as
//!   Bob acting as Pat, and the grant and its end in Ann's log; acting as
//!   Lou, a member, nothing Lou may not do; a grant ending on its own and
//!   none longer than a day.
//! - `dead_jobs`: a mail given up on, shown to Bob without its contents,
//!   closed to Tess, and left dead once the mail service is back; Bob's
//!   retry sends it once across a restart, a second retry is refused, and
//!   the retry is recorded once.
//! - `rotation`: Bob, as Pat, replacing the tenant's signing key: a token
//!   the old key signed works until its own end, new tokens are signed
//!   with the new key, and the replacement is recorded as Bob acting.
//! - `keys`: Tess replacing the signing key and retiring the old one;
//!   the last key that signs stays, and Max may not touch the keys.
//! - `retention`: a shortened audit retention deletes nothing while older
//!   records are owed their longer period, then removes what has expired,
//!   and the removal is itself recorded.

#![cfg(test)]

mod dead_jobs;
mod impersonation;
mod keys;
mod operators;
mod published;
mod retention;
mod rotation;
mod sign_in_records;
mod starts;
mod support;
