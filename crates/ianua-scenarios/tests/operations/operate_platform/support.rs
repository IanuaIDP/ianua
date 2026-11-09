//! What the operator scenarios share: Bob, the platform's first operator,
//! signed in from a network of his own with his password; Pat, a person
//! invited into the world's tenant as an administrator; Lou, invited as
//! an ordinary member; and the switch with which Ann lets operators act
//! as her tenant's people.

use std::net::{IpAddr, Ipv4Addr};

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{operators, people, tenants};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::operators::OperatorSignIn;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::wire::tenants::{PasswordAgain, ReplaceCompliance};
use ianua_scenarios::world::{ADMIN_ROLE, MEMBER_ROLE, World};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// The network Bob works from, in the range set aside for documentation,
/// which no other client of these scenarios stands for.
pub(crate) const BOBS_OFFICE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

/// Bob, signed in on the operator plane: his device carrying the key his
/// password got him, and his operator id.
pub(crate) struct Bob {
    /// His device, carrying his key.
    pub(crate) client: Client,
    /// His operator id, which his own grants are made under.
    pub(crate) id: String,
}

/// Bob's sign-in: the stack's first operator's address and password.
pub(crate) fn bobs_password(stack: &Stack) -> OperatorSignIn {
    OperatorSignIn {
        email: stack.operator().email().to_owned(),
        password: stack.operator().password().to_owned(),
    }
}

/// Bob, signed in from his office with his password.
///
/// # Panics
///
/// When the sign-in is refused, or Bob is not among the operators.
pub(crate) async fn bob_signed_in(stack: &Stack) -> Bob {
    let mut client =
        Client::at(stack, "Bob, the platform's operator", BOBS_OFFICE).expect("a client for Bob");
    let made = operators::sign_in(&bobs_password(stack))
        .send(&client)
        .await
        .ok();
    client.authorize(&made.raw_key);
    let listed = operators::list().send(&client).await.ok();
    let Some(bob) = listed
        .items
        .into_iter()
        .find(|operator| operator.email == stack.operator().email())
    else {
        panic!("Bob, who signed in, is among the operators");
    };
    Bob { client, id: bob.id }
}

/// Pat, invited into the world's tenant by Tess with the `Admin` role, so
/// she may read the tenant's users, having accepted from the mailed link.
///
/// # Panics
///
/// When the invitation or its acceptance is refused.
pub(crate) async fn pat_joined(world: &World<'_>) -> Person {
    joined(world, "pat", "Pat Person", ADMIN_ROLE).await
}

/// Lou, invited into the world's tenant by Tess with only the `Member`
/// role, so she may not read the tenant's users or touch its keys, having
/// accepted from the mailed link.
///
/// # Panics
///
/// When the invitation or its acceptance is refused.
pub(crate) async fn lou_joined(world: &World<'_>) -> Person {
    joined(world, "lou", "Lou Member", MEMBER_ROLE).await
}

/// Ann lets operators act as her tenant's users, which a tenant forbids
/// until its owner says otherwise, proving who she is with her password.
///
/// # Panics
///
/// When the posture cannot be read or the change is refused.
pub(crate) async fn impersonation_allowed(world: &World<'_>) {
    let posture = tenants::compliance(world.tenant())
        .send(world.owner().client())
        .await
        .ok();
    let allowed = ReplaceCompliance {
        data_residency: posture.data_residency,
        audit_retention_days: posture.audit_retention_days,
        operator_impersonation: true,
        proof: PasswordAgain {
            password: world.owner().password().to_owned(),
            code: None,
        },
    };
    tenants::replace_compliance(world.tenant(), &allowed)
        .send(world.owner().client())
        .await
        .ok();
}

/// The id of the world's tenant, as Ann reads it, which a grant names.
///
/// # Panics
///
/// When Ann cannot read her tenant.
pub(crate) async fn tenant_id(world: &World<'_>) -> String {
    tenants::get(world.tenant())
        .send(world.owner().client())
        .await
        .ok()
        .id
}

/// `after` from now, as a grant's end time is written.
///
/// # Panics
///
/// When the time cannot be written in RFC 3339, which never happens for
/// a time this close.
pub(crate) fn from_now(after: Duration) -> String {
    (OffsetDateTime::now_utc() + after)
        .format(&Rfc3339)
        .expect("an RFC 3339 time")
}

/// Someone called `name`, invited into the world's tenant by Tess with
/// the role named `role`, having accepted from the mailed link.
async fn joined(world: &World<'_>, name: &str, display_name: &str, role: &str) -> Person {
    let mut person = world.newcomer(name, display_name);
    let invitation = InviteUser {
        email: person.email().to_owned(),
        display_name: person.account().display_name.clone(),
        role_id: world.role_id(role).await,
    };
    let invited = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    person.record_invitation(&invited.id);
    person.accept_invitation(world.stack()).await;
    person
}
