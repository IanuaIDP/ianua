//! A tenant telling an outside service what happens to its people, under
//! the Shared Signals framework: Tess registers Acme's receiver, the
//! receiver proves its endpoint by echoing the challenge it was sent, and
//! then reads signed Security Event Tokens it checks against the keys the
//! tenant publishes. Poll streams carry the whole journey in these
//! scenarios: no push needs a reachable receiver.
//!
//! - `journey`: the published configuration, registration, the endpoint
//!   proved by its challenge, a role change arriving as a signed token, a
//!   changed token failing the check, and delivery history; a receiver
//!   asking for a verification event carrying its own state.
//! - `lifecycle`: reading status and changing a stream, pausing, resuming
//!   and disabling it; only a disabled stream is deleted; a new endpoint
//!   must prove itself again.
//! - `subjects`: a stream starting with nobody hears only of those added
//!   to it, by its receiver or a person.
//! - `attacks`: nobody without the right reads or changes a stream;
//!   Mallory's made-up key, another stream's key, a wrong challenge and an
//!   endpoint inside the deployment are all refused.

#![cfg(test)]

mod attacks;
mod journey;
mod lifecycle;
mod subjects;
mod support;
