//! What the company scenarios share: a change to every field of the
//! company's profile, the other company untouched by whatever was done to
//! Ann's, Bob the platform's operator, and a colleague ready to act.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{members, operators, organizations};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::operators::OperatorSignIn;
use ianua_scenarios::wire::organization::{OrgRole, OrganizationChange};
use ianua_scenarios::world::World;

/// How long a mailbox is watched for a mail that must not come.
pub(crate) const QUIET: Duration = Duration::from_secs(1);

/// The network Bob works from, in the range set aside for documentation,
/// which no other client of these scenarios stands for.
const BOBS_OFFICE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

/// A change to every field of the company's profile, with a contact
/// mailbox unique to this world.
pub(crate) fn change(world: &World<'_>) -> OrganizationChange {
    OrganizationChange {
        name: Some("Orchard Industries".to_owned()),
        contact_email: Some(world.address("company-contact")),
        display_name: Some("Orchard Team".to_owned()),
    }
}

/// Sam's company is still active, and Sam still in it on the session he
/// holds: nothing done to Ann's company reached his.
///
/// # Panics
///
/// When his company is not active, or his session is dead.
pub(crate) async fn twin_usable(world: &World<'_>) {
    let globex = organizations::get(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
    assert_eq!(globex.status, "Active", "Sam's company is still active");
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();
}

/// Bob, the platform's first operator, signed in from his office with
/// his password: a client carrying his own key.
///
/// # Panics
///
/// When the sign-in is refused.
pub(crate) async fn bob_signed_in(stack: &Stack) -> Client {
    let mut client =
        Client::at(stack, "Bob, the platform's operator", BOBS_OFFICE).expect("a client for Bob");
    let sign_in = OperatorSignIn {
        email: stack.operator().email().to_owned(),
        password: stack.operator().password().to_owned(),
    };
    let made = operators::sign_in(&sign_in).send(&client).await.ok();
    client.authorize(&made.raw_key);
    client
}

/// The id of Ann's company, as Ann reads it.
///
/// # Panics
///
/// When she cannot read her company.
pub(crate) async fn company_id(world: &World<'_>) -> String {
    organizations::get(world.org())
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// Someone at an address of this world for `name`, invited by Ann with
/// `role`, who accepted and signed in.
///
/// # Panics
///
/// When the invitation, acceptance or sign-in is refused.
pub(crate) async fn colleague_signed_in(world: &World<'_>, name: &str, role: OrgRole) -> Member {
    let display_name = format!("{name} Colleague");
    let mut colleague = world.colleague(name, &display_name, role).await;
    colleague.sign_in(world.stack()).await;
    colleague
}
