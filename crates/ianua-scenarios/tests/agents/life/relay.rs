//! Reporter at the relay: it reports with its bearer token, nobody else
//! publishes in its area, its key-bound token is refused where no proof
//! of a key is checked, and a burst of reports spends what the relay
//! allows one address in a minute.

use ianua_scenarios::agent::external::{ExternalAgent, IssuedToken};
use ianua_scenarios::api::agents::{delegation, relay};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::wire::agents::authority::{Budget, Granted};
use ianua_scenarios::wire::{Answer, Status};
use ianua_scenarios::world::World;

use super::{BUDGET, WINDOW};
use crate::support::{RELAY_PER_MINUTE, Witness, report};

/// How many tries Reporter gives a report that is told to come back
/// later, waiting as told between them.
const TRIES: u32 = 5;

/// The peer, topic and alternative token involved in the relay checks.
pub(super) struct RelayAccess<'a> {
    /// The other agent refused access to Reporter's topic.
    pub(super) helper: &'a ExternalAgent,
    /// The destination Reporter alone may publish to.
    pub(super) topic: &'a str,
    /// The key-bound token refused by a relay that checks no key proof.
    pub(super) bound: &'a IssuedToken,
}

/// Reporter reports through the relay with its bearer token, on record.
/// The relay takes Reporter alone: Helper may not publish in Reporter's
/// area, which is on record too, and a person's session is no task token.
/// Reporter's key-bound token is refused there, since the relay checks no
/// proof of a key; it works only where one is checked.
pub(super) async fn relayed(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    reporter: &mut ExternalAgent,
    access: RelayAccess<'_>,
) {
    let RelayAccess {
        helper,
        topic,
        bound,
    } = access;
    reporter
        .publish(topic, &report("Week 43: all green."))
        .await
        .ok();
    witness.recorded("agents.message_authorized").await;
    assert_relay_cast(world, reporter, helper, topic).await;
    witness.recorded("agents.message_denied").await;
    let Some(bearer) = reporter.token().cloned() else {
        panic!("Reporter holds its bearer token");
    };
    reporter.hold(bound.clone());
    reporter
        .publish(topic, &report("Bound and refused."))
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    reporter.hold(bearer);
}

/// Only Reporter's task token can publish in its own topic.
async fn assert_relay_cast(
    world: &World<'_>,
    reporter: &ExternalAgent,
    helper: &ExternalAgent,
    topic: &str,
) {
    let call = relay::publish(world.tenant(), topic, &report("Week 43, once more.")).call();
    Matrix::new("publishing to Reporter's topic", call)
        .allowed(reporter.client())
        .refused(helper.client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.owner().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .refused(
            world.stranger().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .run()
        .await;
}

/// Reporter reads its budget from its token, fifty requests an hour, and
/// Ann reads the same on its delegation; the gateway is what counts it.
/// Then Reporter sends what the relay allows one address in a minute and
/// is told to come back later, in `Retry-After`; it waits as told, and
/// its next report goes through.
pub(super) async fn allowance_spent(
    world: &World<'_>,
    reporter: &ExternalAgent,
    topic: &str,
    grant: &Granted,
) {
    assert_budget(world, reporter, grant).await;
    let refused = burst_until_refused(reporter, topic).await;
    let retry_after = refused
        .header("retry-after")
        .and_then(|seconds| seconds.parse::<u64>().ok());
    assert!(
        retry_after.is_some_and(|seconds| (1..=60).contains(&seconds)),
        "the relay's rate-limit refusal names when to come back, got {retry_after:?}"
    );
    refused.refused(Status::TOO_MANY_REQUESTS, "rate_limit_exceeded");
    let backed_off = reporter
        .publish_backing_off(topic, &report("After the wait."), TRIES)
        .await;
    backed_off.answer.ok();
    assert!(
        backed_off.waits.iter().all(|wait| wait.as_secs() >= 1),
        "Reporter waited at least a second each time it was told to"
    );
}

/// Reporter and Ann both read the same hourly budget from their respective records.
async fn assert_budget(world: &World<'_>, reporter: &ExternalAgent, grant: &Granted) {
    assert_eq!(
        reporter.token().and_then(IssuedToken::budget),
        Some(Budget::of(BUDGET, WINDOW)),
        "Reporter reads Ann's budget from its token"
    );
    let held = delegation::list(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();
    let budget = held
        .iter()
        .find(|delegation| delegation.delegation_id == grant.delegation_id)
        .and_then(|delegation| delegation.budget);
    assert_eq!(
        budget.map(|budget| (budget.max_requests, budget.window_seconds)),
        Some((BUDGET, WINDOW)),
        "Ann reads the same budget on the delegation"
    );
}

/// The first refusal of a burst of reports, each sent at once after the
/// last.
async fn burst_until_refused(reporter: &ExternalAgent, topic: &str) -> Answer<()> {
    for sent in 0..RELAY_PER_MINUTE.saturating_mul(2) {
        let answer = reporter
            .publish(topic, &report(&format!("Burst {sent}.")))
            .await;
        if answer.status() == Status::TOO_MANY_REQUESTS {
            return answer;
        }
        assert_eq!(
            answer.status(),
            Status::NO_CONTENT,
            "report {sent} of the burst went through: {}",
            answer.summary()
        );
    }
    panic!(
        "the relay took {} reports in a row from one address",
        RELAY_PER_MINUTE * 2
    );
}
