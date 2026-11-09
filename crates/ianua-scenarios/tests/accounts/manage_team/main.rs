//! Ann runs her company's team: she creates colleagues outright, changes
//! the role and the tenant roles they hold, locks, lets back in and
//! removes them, hands the company on, and minds the invitations she
//! sent. Every change shows at once on the sessions the colleague already
//! holds, and whoever lacks the right to a change is refused it with
//! nothing changed and nothing recorded.
//!
//! - `creation`: a colleague created with a password proves the mailbox
//!   and signs in; a weak password or a taken address creates nobody;
//!   who may create which role.
//! - `roles`: each role change takes effect on the next sign-in; the role
//!   held again changes nothing; what an administrator may change.
//! - `access`: tenant roles granted, narrowed and withdrawn change what a
//!   colleague reaches at once; who and what takes no grant.
//! - `reach`: Max reads what he reaches himself and sees each grant on
//!   the session he holds; nobody outside reads a reach in Acme.
//! - `standing`: a lock or removal cuts a colleague off on every browser;
//!   who may change a standing; an owner's standing.
//! - `ownership`: a handover, who may hand on and to whom, the last active
//!   owner, an API key, and two owners or two handovers at once.
//! - `invitations`: who may send an invitation again or take it back, and
//!   whose invitation there is none of.

#![cfg(test)]

mod access;
mod creation;
mod invitations;
mod ownership;
mod reach;
mod roles;
mod standing;
mod support;
