//! A company signing up as a customer does it, and every other way an
//! account comes to be: a self-hosted installation proved by its
//! installer, a verified member founding another company, a person
//! registering through a tenant's public form, and members and users
//! joining from an invitation, with mail or without. What follows the
//! first sign-in belongs to `sign_in`.
//!
//! - `founding`: Ann signs her company up and founds it from the mail.
//! - `conflicts`: one link opened in two browsers at once, a name claimed
//!   before the other founder confirms, and a name spelt differently.
//! - `links`: an expired link replaced by a fresh one, and a form sent
//!   again inside and after the mail cooldown.
//! - `attacks`: links replayed, made up or spoiled, someone else's
//!   address, a sign-up never confirmed, weak passwords, a header or a
//!   script in a name, fields the form never had, and a flood of links.
//! - `deployments`: a self-hosted installation and a deployment without
//!   mail take no public sign-up.
//! - `installation`: the installer's one-time proof, used once for its
//!   purpose, with mail and without, and after its day.
//! - `recovery`: founding through an audit failure, a cache, bus,
//!   database or mail outage, and a restart of the API and worker.
//! - `tenant`: the first tenant is ready and its company's own; founders
//!   are not notified of their own founding.
//! - `companies`: a verified member founds another company from their own
//!   session, and nothing else founds one.
//! - `joining`: a tenant's public form, member and user invitations,
//!   joining without mail, and the admission policies behind them.

#![cfg(test)]

mod attacks;
mod companies;
mod conflicts;
mod deployments;
mod founding;
mod installation;
mod joining;
mod links;
mod recovery;
mod support;
mod tenant;
