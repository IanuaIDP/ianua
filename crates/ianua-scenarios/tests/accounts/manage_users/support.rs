//! What the user scenarios share: a person Tess invited who joined and
//! signed in, a role that lets its holder read the tenant's users and
//! nothing else, and whether a person can read them on the session they
//! hold.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, roles};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// Someone at the address `name`, invited into the tenant by Tess with
/// its `Member` role, who accepted from the mailed link and signed in.
///
/// # Panics
///
/// When the invitation, the acceptance or the sign-in is refused.
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

/// The id of a role Tess makes that lets its holder read the tenant's
/// users and nothing else: the one protected read these scenarios try.
///
/// # Panics
///
/// When the role cannot be made.
pub(crate) async fn reader(world: &World<'_>) -> String {
    roles::create(
        world.tenant(),
        &NewRole {
            name: "User Reader".to_owned(),
            system_permissions: vec![SystemPermission::new("Users", "View")],
        },
    )
    .send(world.admin().client())
    .await
    .ok()
    .id
}

/// `person` reads the tenant's users on the session they hold, and finds
/// themselves among them.
///
/// # Panics
///
/// When the read is refused, or they are not listed.
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

/// `person` is refused the tenant's users on the session they hold.
///
/// # Panics
///
/// When the read is anything but forbidden.
pub(crate) async fn refused_the_users(world: &World<'_>, person: &Person) {
    people::list(world.tenant(), None)
        .send(person.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}
