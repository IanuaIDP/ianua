//! Ann managing her organization's tenants: making a second one and
//! waiting for its setup, changing a tenant's profile, copying parts of
//! one tenant into another, and moving a tenant through suspension, the
//! archive, restoration and deletion. Every refusal leaves the tenant as
//! it was, every record is written once, and restarts lose nothing.
//!
//! - `creation`: a new tenant finishes its setup and survives restarts;
//!   the plan, the wrong people and a record that cannot be written refuse
//!   it whole; a bus outage neither loses nor doubles the setup.
//! - `settings`: Tess changes the tenant's profile; a bad value refuses
//!   the whole change; nobody else changes it.
//! - `environment`: Tess labels the tenant as a stage of the product and
//!   back; a stage that is not one is refused; nobody else relabels it.
//! - `clones`: a copy of the roles reaches the new tenant and brings no
//!   people with it; the wrong person or target starts no copy.
//! - `lifecycle`: a suspended or archived tenant signs its people out
//!   until a fresh sign-in after it is back; only Ann moves it; a record
//!   that cannot be written changes nothing; deletion after the grace
//!   frees the organization's room and tears the tenant down once.

#![cfg(test)]

mod clones;
mod creation;
mod environment;
mod lifecycle;
mod settings;
mod support;
