//! Reporter waiting on people: three calls it needs a person's say for,
//! asked through its developer's backend signed in as Ann; Tess approves
//! one, denies one, and comes too late for the third.

use ianua_scenarios::agent::external::{ApprovalAsk, ExternalAgent};
use ianua_scenarios::api::agents::approvals;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::authority::Granted;
use ianua_scenarios::world::World;

use super::Agents;
use crate::support::{Witness, refused_to_the_rest};

/// How long a person has to decide a call, in seconds: a quarter of an
/// hour, long enough for Tess to get to it.
const DECIDING_SECONDS: u32 = 900;

/// How long the third call waits, in seconds: one, so it lapses before
/// anyone decides.
const LAPSING_SECONDS: u32 = 1;

/// The call Reporter means to make with `method` at `target`, under Ann's
/// grant, for a person to decide within `ttl_seconds`.
fn approval_for(method: &str, target: &str, grant: &Granted, ttl_seconds: u32) -> ApprovalAsk {
    ApprovalAsk {
        method: method.to_owned(),
        target: target.to_owned(),
        delegation_id: grant.delegation_id.clone(),
        ttl_seconds,
    }
}

/// Reporter needs a person's say for three calls, asked through its
/// developer's backend, signed in as Ann. The read Tess approves; Ann, who
/// asked, may not, nor may anyone outside the tenant. The write Tess
/// denies. The third lapses before anyone decides, and Tess's late
/// approval is refused and records nothing.
pub(super) async fn waited_on_people(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    agents: &Agents<'_>,
    grant: &Granted,
) {
    approve_read(world, witness, agents, grant).await;
    deny_write(world, witness, agents.reporter, grant).await;
    refuse_late_approval(world, witness, agents.reporter, grant).await;
}

/// The requested read waits for one person and Tess's approval is attributed to her.
async fn approve_read(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    agents: &Agents<'_>,
    grant: &Granted,
) {
    let reporter = agents.reporter;
    let backend = world.owner().client();
    let read = reporter
        .ask_approval(
            backend,
            &approval_for("GET", "/reports/weekly", grant, DECIDING_SECONDS),
        )
        .await;
    witness.recorded("agents.approval_requested").await;
    assert_eq!(
        (read.status.as_str(), read.approvers_needed),
        ("pending", 1),
        "the read waits for one person"
    );
    approve_as_tess(world, agents, &read.id).await;
    let approved = reporter.decision_on(backend, &read.id).await;
    assert_eq!(approved.status, "approved", "Tess approved the read");
    assert_eq!(
        approved.decided_by.map(|by| by.id),
        Some(world.admin().id().to_owned()),
        "the approval names Tess as who decided"
    );
    witness.recorded("agents.approval_granted").await;
}

/// Ann and the rest of the cast are refused before Tess approves the read.
async fn approve_as_tess(world: &World<'_>, agents: &Agents<'_>, read: &str) {
    let Agents { reporter, helper } = *agents;
    let call = approvals::approve(world.tenant(), reporter.id(), read).call();
    let matrix = Matrix::new("approving Reporter's read", call).refused(
        world.owner().client(),
        Status::FORBIDDEN,
        "forbidden",
    );
    refused_to_the_rest(matrix, world, &[reporter, helper])
        .run()
        .await;
    approvals::approve(world.tenant(), reporter.id(), read)
        .send(world.admin().client())
        .await
        .ok();
}

/// Tess denies the write and its decision is recorded.
async fn deny_write(
    world: &World<'_>,
    witness: &mut Witness<'_>,
    reporter: &ExternalAgent,
    grant: &Granted,
) {
    let backend = world.owner().client();
    let write = reporter
        .ask_approval(
            backend,
            &approval_for("POST", "/reports", grant, DECIDING_SECONDS),
        )
        .await;
    approvals::deny(world.tenant(), reporter.id(), &write.id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        reporter.decision_on(backend, &write.id).await.status,
        "denied",
        "Tess denied the write"
    );
    witness.recorded("agents.approval_denied").await;
}

/// The expired third call refuses Tess's late approval without recording a grant.
async fn refuse_late_approval(
    world: &World<'_>,
    witness: &Witness<'_>,
    reporter: &ExternalAgent,
    grant: &Granted,
) {
    let backend = world.owner().client();
    let lapsing = reporter
        .ask_approval(
            backend,
            &approval_for("GET", "/reports/monthly", grant, LAPSING_SECONDS),
        )
        .await;
    assert_eq!(
        reporter.decision_on(backend, &lapsing.id).await.status,
        "expired",
        "the third call lapsed before anyone decided"
    );
    approvals::approve(world.tenant(), reporter.id(), &lapsing.id)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    witness.nothing_new("agents.approval_granted").await;
}
