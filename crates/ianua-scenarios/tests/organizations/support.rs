//! What the organization scenarios share: a role change to send, reading
//! a member's role the way the owner sees it, a sign-in told no more than
//! that nobody matched, and how long a mailbox is watched for a mail that
//! must not come.

use std::time::Duration;

use ianua_scenarios::api::{members, sessions};
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::{ChangeRole, OrgRole};
use ianua_scenarios::wire::sign_in::PasswordSignIn;
use ianua_scenarios::world::World;

/// How long a mailbox is watched for a mail that must not come.
pub(crate) const QUIET: Duration = Duration::from_secs(3);

/// A change of a member's role to `role`.
pub(crate) fn change_to(role: OrgRole) -> ChangeRole {
    ChangeRole { role }
}

/// The role `member_id` holds in the world's organization, as its owner
/// reads the members; `None` when they are no member any more.
///
/// # Panics
///
/// When the owner cannot read the members.
pub(crate) async fn role_of(world: &World<'_>, member_id: &str) -> Option<OrgRole> {
    let page = members::list(world.org(), None)
        .send(world.owner().client())
        .await
        .ok();
    page.items
        .into_iter()
        .find(|member| member.id == member_id)
        .and_then(|member| member.role)
}

/// Asserts `client` signing in as `email` with `password` is told no
/// more than that nobody matched.
///
/// # Panics
///
/// When the sign-in is answered anything else.
pub(crate) async fn sign_in_refused(client: &Client, email: &str, password: &str) {
    sessions::member_sign_in(&PasswordSignIn::of(email, password))
        .send(client)
        .await
        .refused(Status::NOT_FOUND, "not_found");
}
