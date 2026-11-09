//! What the access control scenarios share: a person Tess invited who
//! joined and signed in, a role reading the tenant's users and nothing
//! else, groups, and whether a person can read the users on the session
//! they hold.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, policies, roles};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::policies::{GroupRole, NewGroup, NewGroupMember};
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::world::{MEMBER_ROLE, World};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// The kind of principal a tenant user is, on the wire.
pub(crate) const USER: &str = "user";

/// Someone at the address `name`, invited into the tenant by Tess with
/// its `Member` role, who accepted from the mailed link and signed in.
pub(crate) async fn person(world: &World<'_>, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Tenant Holder"));
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

/// The id of a role named `name` that Tess makes, carrying `permissions`,
/// each a resource and an action such as `("Users", "View")`.
pub(crate) async fn role_with(
    world: &World<'_>,
    name: &str,
    permissions: &[(&str, &str)],
) -> String {
    roles::create(
        world.tenant(),
        &NewRole {
            name: name.to_owned(),
            system_permissions: permissions
                .iter()
                .map(|(resource, action)| SystemPermission::new(resource, action))
                .collect(),
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id
}

/// The id of a role Tess makes that lets its holder read the tenant's
/// users and nothing else: the one protected read these scenarios try.
pub(crate) async fn reader(world: &World<'_>) -> String {
    role_with(world, "User Reader", &[("Users", "View")]).await
}

/// The id of a new group named `name`, made by Tess.
pub(crate) async fn group(world: &World<'_>, name: &str) -> String {
    policies::create_group(
        world.tenant(),
        &NewGroup {
            name: name.to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id
}

/// A new group named `name`, holding the role `role`.
pub(crate) async fn group_with_role(world: &World<'_>, name: &str, role: &str) -> String {
    let id = group(world, name).await;
    bind_role(world, &id, role).await;
    id
}

/// Tess binds the role `role` to the group `group`.
pub(crate) async fn bind_role(world: &World<'_>, group: &str, role: &str) {
    let body = GroupRole {
        role_id: role.to_owned(),
    };
    policies::grant_group_role(world.tenant(), group, &body)
        .send(world.admin().client())
        .await
        .ok();
}

/// Tess puts `person` in the group `group`.
pub(crate) async fn add_to_group(world: &World<'_>, group: &str, person: &Person) {
    let member = NewGroupMember {
        kind: USER.to_owned(),
        id: person.id().to_owned(),
    };
    policies::add_member(world.tenant(), group, &member)
        .send(world.admin().client())
        .await
        .ok();
}

/// `person` reads the tenant's users on the session they hold, finding
/// themselves among them, at once.
pub(crate) async fn reads_the_users(world: &World<'_>, person: &Person) {
    let listed = people::list(world.tenant(), None)
        .send(person.client())
        .await
        .ok();
    assert!(
        listed.items.iter().any(|user| user.id == person.id()),
        "{} is among the users they read",
        person.email()
    );
}

/// `person` is refused the tenant's users on the session they hold, at
/// once.
pub(crate) async fn refused_the_users(world: &World<'_>, person: &Person) {
    people::list(world.tenant(), None)
        .send(person.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Waits until `person` can read the tenant's users, `why` saying what
/// changed.
pub(crate) async fn comes_to_read(world: &World<'_>, person: &Person, why: &str) {
    let what = format!("{} to read the users {why}", person.email());
    eventually(&what, || async {
        let read = people::list(world.tenant(), None)
            .send(person.client())
            .await;
        read.status().is_success().then_some(())
    })
    .await;
}

/// Waits until `person` is refused the tenant's users, `why` saying what
/// changed.
pub(crate) async fn comes_to_be_refused(world: &World<'_>, person: &Person, why: &str) {
    let what = format!("{} to be refused the users {why}", person.email());
    eventually(&what, || async {
        let read = people::list(world.tenant(), None)
            .send(person.client())
            .await;
        (read.status() == Status::FORBIDDEN).then_some(())
    })
    .await;
}

/// The moment `after` from now, in RFC 3339, to date a review.
pub(crate) fn time_after(after: Duration) -> String {
    let at = OffsetDateTime::now_utc() + after;
    at.format(&Rfc3339).expect("a formattable instant")
}
