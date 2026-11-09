//! What the team scenarios share: a colleague's account form and password,
//! a member read from Ann's team list, the one audit record a change
//! leaves, a second browser of a member, a provisioned colleague ready to
//! sign in.

use ianua_scenarios::actors::{Member, MemberAccount};
use ianua_scenarios::api::members;
use ianua_scenarios::net::Client;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::audit::AuditEntry;
use ianua_scenarios::wire::organization::{CreateMember, Member as ListedMember, OrgRole};
use ianua_scenarios::world::World;

/// The password Ann chooses for a colleague she creates: a sentence, so no
/// scanner takes it for a key, and nothing like their name or address.
pub(crate) const PASSWORD: &str = "Separate golden orchard meadow 7814!";

/// The form for a colleague at the address `name`, with no role chosen,
/// so the platform's default role shows.
pub(crate) fn account(world: &World<'_>, name: &str) -> CreateMember {
    CreateMember {
        email: world.address(name),
        display_name: "New Colleague".to_owned(),
        password: PASSWORD.to_owned(),
        role: None,
    }
}

/// The member `id` as Ann's team list shows them, inactive ones included.
///
/// # Panics
///
/// When the list cannot be read, or the member is not on it.
pub(crate) async fn listed(world: &World<'_>, id: &str) -> ListedMember {
    let found = members::list(world.org(), None)
        .send(world.owner().client())
        .await
        .ok()
        .items
        .into_iter()
        .find(|member| member.id == id);
    let Some(member) = found else {
        panic!("the member {id} is on the team list");
    };
    member
}

/// The one record of `event` naming the member `member`, made by `actor`.
///
/// # Panics
///
/// When the trail holds no such record, more than one, or one by someone
/// else.
pub(crate) async fn recorded(
    world: &World<'_>,
    event: &str,
    member: &str,
    actor: &str,
) -> AuditEntry {
    let matching: Vec<AuditEntry> = world
        .trail()
        .entries(event)
        .await
        .into_iter()
        .filter(|entry| entry.details["org_user"]["id"].as_str() == Some(member))
        .collect();
    let [record] = matching.as_slice() else {
        panic!("one {event} names this member, not {}", matching.len());
    };
    assert!(
        record.actor.contains(actor),
        "the {event} names who made the change"
    );
    record.clone()
}

/// `original` on a second browser, signed in there: the sign-in replaces
/// the session the first browser held, as every member sign-in does, so
/// the step after knows which browser is still in before it changes the
/// team.
///
/// # Panics
///
/// When the sign-in is refused, or the first browser is still in.
pub(crate) async fn another(world: &World<'_>, original: &Member) -> Member {
    let mut member = Member::new(
        Client::new(world.stack(), "another team browser").expect("a client"),
        original.account().clone(),
        original.password(),
    );
    member.sign_in(world.stack()).await;
    members::me(world.org())
        .send(original.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    members::me(world.org()).send(member.client()).await.ok();
    member
}

/// The colleague Ann provisioned with `form`, whose account got `id`, on
/// a browser of their own and not yet signed in; the platform's default
/// role when the form chose none.
pub(crate) fn provisioned(world: &World<'_>, id: String, form: &CreateMember) -> Member {
    Member::new(
        Client::new(world.stack(), "provisioned colleague").expect("a client"),
        MemberAccount {
            id,
            email: form.email.clone(),
            display_name: form.display_name.clone(),
            org: world.org().clone(),
            role: form.role.unwrap_or(OrgRole::Member),
            landing: None,
        },
        &form.password,
    )
}
