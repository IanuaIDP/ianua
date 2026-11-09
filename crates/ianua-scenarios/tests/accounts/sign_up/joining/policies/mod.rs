//! The policies behind the public form, run over every point of a finite
//! matrix: the ways in a tenant offers, whether it is open to the public,
//! its second-factor policy, and whether it has a mail server. Pat's form
//! is taken exactly where the policy admits it, and a refused form leaves
//! nothing behind. Ann's settings are saved only where they can be met.
//!
//! - `admission`: every subset of the ways in, open and closed, under each
//!   second-factor policy, with mail and without.
//! - `assurance`: the stronger assurances against every subset of the
//!   ways in; empty sets and doubled factor offers.
//! - `passwords`: the character classes, lengths and hygiene rules a
//!   password is held to.
//! - `transitions`: a policy changed while a proof or an invitation is
//!   pending.
//! - `support`: one point of the matrix, Ann saving settings, and Pat
//!   signed in as the policy asks.

mod admission;
mod assurance;
mod passwords;
mod support;
mod transitions;
