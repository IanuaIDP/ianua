//! What the service scenarios share: a person Tess invited who joined and
//! signed in.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::people;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// Someone at the address `name`, invited into the tenant by Tess with
/// its `Member` role, who accepted from the mailed link and signed in.
///
/// # Panics
///
/// When the invitation, the acceptance or the sign-in is refused.
pub(crate) async fn person(world: &World<'_>, name: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Partnered"));
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
