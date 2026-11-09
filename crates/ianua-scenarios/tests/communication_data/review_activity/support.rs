//! The people the activity scenarios invite and the readers they give the
//! log to.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, roles};
use ianua_scenarios::wire::audit::AuditEntry;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::roles::{NewRole, SystemPermission};
use ianua_scenarios::world::{MEMBER_ROLE, World};

/// The id of the person an invitation record names in its details.
pub(crate) fn invitee(entry: &AuditEntry) -> Option<String> {
    entry.details["user"]["id"].as_str().map(str::to_owned)
}

/// Someone called `name`, invited by Tess with the Member role, their
/// invitation not yet taken up: it leaves its record either way.
pub(crate) async fn invited(world: &World<'_>, name: &str) -> Person {
    let role = world.role_id(MEMBER_ROLE).await;
    invited_as(world, name, &role).await
}

/// Vic, given by Tess a role that may read the tenant's audit log and
/// nothing more, signed in.
pub(crate) async fn log_reader(world: &World<'_>) -> Person {
    let readers = roles::create(
        world.tenant(),
        &NewRole {
            name: "Log readers".to_owned(),
            system_permissions: vec![SystemPermission::new("AuditLog", "View")],
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let mut vic = invited_as(world, "vic", &readers.id).await;
    vic.accept_invitation(world.stack()).await;
    vic.sign_in(world.stack()).await;
    vic
}

/// Someone called `name`, invited by Tess with the role `role_id`.
async fn invited_as(world: &World<'_>, name: &str, role_id: &str) -> Person {
    let mut person = world.newcomer(name, &format!("{name} Reviewed"));
    let invitation = InviteUser {
        email: person.email().to_owned(),
        display_name: person.account().display_name.clone(),
        role_id: role_id.to_owned(),
    };
    let made = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    person.record_invitation(&made.id);
    person
}
