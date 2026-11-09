//! What the people scenarios share: Tess's requests, each exchange kept,
//! and Tess's invitation of a newcomer with the tenant's `Member` role.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{Request, people};
use ianua_scenarios::wire::people::{InviteUser, UserInvited};
use ianua_scenarios::wire::{Answer, Exchange};
use ianua_scenarios::world::{MEMBER_ROLE, World};
use serde::de::DeserializeOwned;

/// Sends `request` as Tess, keeping the exchange in `exchanges`.
pub(crate) async fn as_tess<T: DeserializeOwned>(
    world: &World<'_>,
    request: Request<T>,
    exchanges: &mut Vec<Exchange>,
) -> Answer<T> {
    let answer = request.send(world.admin().client()).await;
    exchanges.push(answer.exchange().clone());
    answer
}

/// Tess's invitation of `pat` with the tenant's `Member` role, its
/// exchanges kept in `exchanges`.
pub(crate) async fn invitation_of(
    world: &World<'_>,
    pat: &mut Person,
    exchanges: &mut Vec<Exchange>,
) -> UserInvited {
    let invitation = InviteUser {
        email: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let made = as_tess(
        world,
        people::invite(world.tenant(), &invitation),
        exchanges,
    )
    .await
    .ok();
    pat.record_invitation(&made.id);
    made
}
