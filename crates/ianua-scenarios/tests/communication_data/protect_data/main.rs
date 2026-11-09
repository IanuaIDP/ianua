//! Protecting sensitive data on its way out: Tess classifies the fields of
//! the records app's answers, and the gateway redacts them by each route's
//! clearance before anyone reads them.
//!
//! - `clearance`: a partner route and a clinic route show the same record
//!   with different fields removed, masked or replaced by a digest.
//! - `digests`: a digest is good within a tenant only: the same card
//!   number reads differently at another company.
//! - `rules`: a raised or removed rule takes effect on the next answer and
//!   is on record; only someone who may classify changes the rules, and a
//!   rule that could never work is refused.
//! - `withheld`: an answer the gateway cannot redact is held back, and a
//!   stage naming another tenant's rules is refused when saved; a text
//!   answer passes.

#![cfg(test)]

mod clearance;
mod digests;
mod rules;
mod support;
mod withheld;
