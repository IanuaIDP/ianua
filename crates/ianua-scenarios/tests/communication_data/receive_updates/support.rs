//! What the update scenarios share: a person Tess invited who joined and
//! signed in, a role Tess can give and take back, and waiting for the
//! notice a step put in someone's inbox.

use std::collections::HashSet;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{OrgPath, TenantPath, notifications, people, roles};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::notifications::Notification;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::roles::{AssignRole, NewRole, SystemPermission};
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// The category a role given or taken back is told under.
pub(crate) const AUTHORIZATION: &str = "Authorization";

/// The record a single notice marked read leaves.
pub(crate) const READ_ONE: &str = "notifications.notification_read";

/// The record marking the whole inbox read leaves.
pub(crate) const READ_ALL: &str = "notifications.all_notifications_read";

/// Someone at the address `name`, invited into the tenant by Tess with
/// its `Member` role, who accepted from the mailed link and signed in.
///
/// # Panics
///
/// When the invitation, the acceptance or the sign-in is refused.
pub(crate) async fn person(world: &World<'_>, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Notified"));
    let invitation = people::invite(
        world.tenant(),
        &InviteUser {
            email: person.email().to_owned(),
            display_name: person.account().display_name.clone(),
            role_id: world.role_id(MEMBER_ROLE).await,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    person.record_invitation(&invitation.id);
    person.accept_invitation(world.stack()).await;
    person.sign_in(world.stack()).await;
    person
}

/// The id of a role Tess makes that lets its holder read the tenant's
/// users: a role whose giving and taking back the holder is always told.
///
/// # Panics
///
/// When the role cannot be made.
pub(crate) async fn reader_role(world: &World<'_>) -> String {
    roles::create(
        world.tenant(),
        &NewRole {
            name: "Notified Readers".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id
}

/// Tess gives `person` the role `role_id`.
///
/// # Panics
///
/// When the assignment is refused.
pub(crate) async fn give_role(world: &World<'_>, person: &Person, role_id: &str) {
    let assignment = AssignRole {
        user_id: person.id().to_owned(),
    };
    roles::assign(world.tenant(), role_id, &assignment)
        .send(world.admin().client())
        .await
        .ok();
}

/// Tess takes the role `role_id` back from `person`.
///
/// # Panics
///
/// When the revocation is refused.
pub(crate) async fn take_role(world: &World<'_>, person: &Person, role_id: &str) {
    roles::unassign(world.tenant(), role_id, person.id())
        .send(world.admin().client())
        .await
        .ok();
}

/// The ids of every notice in the tenant inbox `reader` holds now.
///
/// # Panics
///
/// When the inbox cannot be read.
pub(crate) async fn tenant_ids(tenant: &TenantPath, reader: &Client) -> HashSet<String> {
    let inbox = notifications::inbox(tenant).send(reader).await.ok();
    inbox.items.into_iter().map(|notice| notice.id).collect()
}

/// The ids of every notice in the organization inbox `reader` holds now.
///
/// # Panics
///
/// When the inbox cannot be read.
pub(crate) async fn member_ids(org: &OrgPath, reader: &Client) -> HashSet<String> {
    let inbox = notifications::member_inbox(org).send(reader).await.ok();
    inbox.items.into_iter().map(|notice| notice.id).collect()
}

/// The unread notice of `category` in the tenant inbox `reader` holds
/// that is not among `seen`, once the worker has put one there.
///
/// # Panics
///
/// When none comes within the patience of `eventually`.
pub(crate) async fn fresh_tenant_notice(
    tenant: &TenantPath,
    reader: &Client,
    seen: &HashSet<String>,
    category: &str,
) -> Notification {
    let what = format!("a new {category} notice for {}", reader.actor());
    eventually(&what, || async move {
        let unread = notifications::unread(tenant).send(reader).await.ok();
        fresh(unread.items, seen, category)
    })
    .await
}

/// The unread notice of `category` in the organization inbox `reader`
/// holds that is not among `seen`, once the worker has put one there.
///
/// # Panics
///
/// When none comes within the patience of `eventually`.
pub(crate) async fn fresh_member_notice(
    org: &OrgPath,
    reader: &Client,
    seen: &HashSet<String>,
    category: &str,
) -> Notification {
    let what = format!("a new {category} notice for {}", reader.actor());
    eventually(&what, || async move {
        let unread = notifications::member_unread(org).send(reader).await.ok();
        fresh(unread.items, seen, category)
    })
    .await
}

/// The first of `notices` of `category` whose id is not in `seen`.
fn fresh(
    notices: Vec<Notification>,
    seen: &HashSet<String>,
    category: &str,
) -> Option<Notification> {
    notices
        .into_iter()
        .find(|notice| notice.category == category && !seen.contains(&notice.id))
}
