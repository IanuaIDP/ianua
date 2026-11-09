//! Who may do what in a tenant, and what each change does to a person's
//! real access: groups and what they inherit, the policy and its drafts,
//! access requests and reviews, separation of duties, clearance, the
//! access check, relationships and emergency access. Whatever grants or
//! withdraws access is tried through the operation it protects, and
//! everything nobody granted stays refused.
//!
//! - `access_requests`: Pat asks for a group for a while, Tess answers,
//!   and the place ends when the time is up; nobody answers their own,
//!   and a request nobody answers runs out.
//! - `reviews`: Bea decides who keeps a place; what she removes goes only
//!   when the review completes, a review called off changes nothing, and
//!   one past its date settles the undecided as it said.
//! - `separation`: nobody holds both roles of a rule, however the second
//!   would arrive, until the rule is lifted.
//! - `groups`: moving a group under another changes what its members
//!   inherit at once; renamed, read and deleted, children first.
//! - `policy`: a draft goes live only when someone else approves it;
//!   simulation answers what any version would do, and a request no rule
//!   matches is refused.
//! - `checks`: the access check refuses what the records do not show,
//!   answers from a role's app permissions and from relationships, and
//!   keeps a record of every answer.
//! - `clearance`: who is cleared for what data, written by someone
//!   cleared themselves.
//! - `break_glass`: emergency access given, closed and timed out, and what
//!   a user may give themselves under the tenant's policy.

#![cfg(test)]

mod access_requests;
mod break_glass;
mod checks;
mod clearance;
mod groups;
mod policy;
mod reviews;
mod separation;
mod support;
