//! Reviewing what happened in a tenant and a company: their audit logs
//! read and narrowed, exported with bounded rights, a tamper-evident chain
//! checked, activity counted, and secrets kept out of every record.
//!
//! - `trail`: Tess reads the log page by page, newest first, narrowed to a
//!   person or a time; a plain member may not read it.
//! - `exports`: only someone who may export gets the file, written in full
//!   by the worker and downloaded once through a signed link, on record.
//! - `organization`: one log for a whole company, narrowed by tenant and
//!   by who did it, nothing of any other company's in it; its export only
//!   for someone who may.
//! - `reach`: a member reads the company's log, calendar and files only
//!   as far as the tenants they reach; a viewer reads its own records.
//! - `activity`: the dashboard's calendars count what happened, for those
//!   who may read the trail.
//! - `secrets`: no record or export holds a password, token or key handed
//!   over that day.
//! - `chain`: the worker finds the chain intact, and broken from the first
//!   record someone holding the database changed.

#![cfg(test)]

mod activity;
mod chain;
mod exports;
mod organization;
mod reach;
mod sealed;
mod secrets;
mod support;
mod trail;
