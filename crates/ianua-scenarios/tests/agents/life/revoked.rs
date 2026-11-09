//! Reporter's key revoked by Ann: the token it minted is refused at the
//! relay from the next request on, and the key signs Reporter in nowhere.

use ianua_scenarios::api::agents::credentials;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use super::{Agents, reporting};
use crate::support::{Witness, hidden_from_the_rest, report};

/// How many tries Reporter gives a report after the revocation, waiting
/// as told between them, so a refusal is not a rate limit's.
const TRIES: u32 = 5;

/// Ann revokes Reporter's key; nobody else may. From the next request on,
/// the token Reporter minted with it is refused at the relay, and the key
/// signs Reporter in nowhere. The revocation is on record; the refusals
/// record nothing.
pub(super) async fn key_revoked(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    agents: &Agents<'_>,
    topic: &str,
) {
    let Agents { reporter, helper } = *agents;
    let revoke = credentials::revoke(world.tenant(), reporter.id(), reporter.credential_id());
    hidden_from_the_rest(
        Matrix::new("revoking Reporter's key", revoke.call()),
        world,
        &[reporter, helper],
    )
    .run()
    .await;
    revoke.send(world.owner().client()).await.ok();
    witness.recorded("agents.credential_revoked").await;
    witness.caught_up().await;

    reporter
        .publish_backing_off(topic, &report("After the revoke."), TRIES)
        .await
        .answer
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    reporter
        .ask_token(&reporting(topic))
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    witness.nothing_new("agents.message_authorized").await;
    witness.nothing_new("agents.token_issued").await;
}
