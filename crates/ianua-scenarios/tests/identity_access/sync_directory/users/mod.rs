//! The people a directory keeps, record by record: what it sends and reads
//! back, every way it may change a record, how it finds and pages people,
//! which records clash, which accounts it may never move, and the room
//! the tenant has for them.
//!
//! - `records`: Pat's whole record read back as sent, its version
//!   answered "not modified", a replaced record clearing what was left
//!   out, and records the endpoint cannot keep refused without a trace.
//! - `patches`: every patch form a directory sends (by path, fully
//!   qualified, pathless, Entra's string booleans, an `emails` path, an
//!   attribute not kept), and `remove` clearing profile fields only.
//! - `search`: filters on each kept attribute joined by `and`, `or` and
//!   parentheses, letter case as each attribute compares it, and pages in
//!   either order.
//! - `conflicts`: a second account at Pat's address in any letter case is
//!   refused however it is asked for, while two records may share the
//!   directory's own id.
//! - `guarded`: an administrator is never moved to a new address or let
//!   back in by the directory, and is only switched off when removed.
//! - `limits`: no account is made past the tenant's user limit.

mod conflicts;
mod guarded;
mod limits;
mod patches;
mod records;
mod search;

use ianua_scenarios::api::directory;
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::directory::DirectoryResource;
use ianua_scenarios::world::World;

/// The enterprise extension's schema, which a record names when it
/// carries a department, an employee number or a manager.
const ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

/// The record the directory reads for the user `user_id`.
async fn read(world: &World<'_>, linked: &Client, user_id: &str) -> DirectoryResource {
    directory::get_user(world.tenant(), user_id)
        .send(linked)
        .await
        .ok()
}
