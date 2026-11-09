//! A company and its members, as Ann runs it and as Max, Sam and Mallory
//! try it: colleagues join and change rank, ownership is handed over,
//! invitations are sent and abused, a member leaves, and each company
//! keeps its own tenants.
//!
//! - `team`: Zoe joins, is promoted and steps back; nobody raises their
//!   own rank or anyone else's without the right.
//! - `owners`: ownership is handed from Ann to Zoe and never dropped.
//! - `invitations`: Uma joins as offered, her link works once, Vic's
//!   unaccepted seat opens nothing, only the right invites.
//! - `leaving`: Max, removed, is cut off at once.
//! - `tenants`: Ann's company and Sam's each have their own production,
//!   and only their own.

#![cfg(test)]

mod invitations;
mod leaving;
mod owners;
mod support;
mod team;
mod tenants;
