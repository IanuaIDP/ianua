//! Apps published behind the gateway, used by the people they are for:
//! Tess publishes, moves, takes down and removes a route, and each change
//! shows at the real upstream; Pat and Uma sign in on a protected app's
//! own host, and a lock, a restored account or a sign-out shows there too.
//! Nobody but an administrator changes a route, and a change whose record
//! cannot be written changes nothing.
//!
//! - `lifecycle`: a route forwards only where Tess last pointed it; Max,
//!   Sam and nobody signed in cannot take an app down; a withdrawal whose
//!   record cannot be written leaves the app up.
//! - `protection`: a locked Pat is cut off from the app while Uma goes
//!   on, and is back only after a fresh sign-in; her sign-out ends that
//!   too.
//! - `policy`: a sign-in waiting for Pat's code obeys the tenant's
//!   baseline raised meanwhile, and finishes once it is lowered again.

#![cfg(test)]

mod lifecycle;
mod policy;
mod protection;
mod support;
