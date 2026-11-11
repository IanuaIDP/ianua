//! Deny by default: a rule acts for the person who published it, and when
//! that person may no longer run it, the rule cannot start. A rule that
//! cannot start cannot allow, so the change it guards is refused, even
//! though the rule itself would have allowed it. The refused start is on
//! the record.

use ianua_scenarios::api::{people, policies, workflows};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::policies::NewGroupMember;
use ianua_scenarios::wire::workflows::Publication;
use ianua_scenarios::world::World;

use super::{before, deciding, group, refused_by_the_rule};
use crate::support::{drafted, invited, pat};

/// The record of a rule that could not start.
const START_REFUSED: &str = "workflows.start_refused";

/// Tess drafts a rule allowing access, and Max, who may change and run
/// workflows, publishes it. Tess deactivates Max, then puts Pat into
/// "Helpdesk": the rule cannot start for Max, so the change is refused
/// with the rule's 403, Pat is not in the group, the rule has no run, and
/// the refused start is recorded.
#[tokio::test]
async fn a_rule_whose_publisher_was_deactivated_refuses_the_change() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = pat(&world).await;
    let max = invited(
        &world,
        ("max", "Max Publisher"),
        &[
            ("Workflows", "View"),
            ("Workflows", "Update"),
            ("Workflows", "Run"),
        ],
    )
    .await;
    let helpdesk = group(&world, "Helpdesk").await;
    let draft = drafted(&world, before("access_given"), deciding("allow")).await;
    let publication = Publication {
        revision: draft.revision.clone(),
    };
    let rule = workflows::publish(world.tenant(), &draft.id, &publication)
        .send(max.client())
        .await
        .ok();
    let seen = world.trail().ids().await;

    people::deactivate(world.tenant(), max.id())
        .send(world.admin().client())
        .await
        .ok();
    let member = NewGroupMember {
        kind: "user".to_owned(),
        id: pat.id().to_owned(),
    };
    refused_by_the_rule(
        &world,
        policies::add_member(world.tenant(), &helpdesk, &member),
    )
    .await;

    let members = policies::members(world.tenant(), &helpdesk)
        .send(world.admin().client())
        .await
        .ok()
        .items;
    let runs = workflows::executions(world.tenant(), &rule.id)
        .send(world.admin().client())
        .await
        .ok()
        .items;
    assert!(members.is_empty(), "Pat is not in Helpdesk");
    assert!(runs.is_empty(), "the rule never ran");
    world.trail().recorded_after(&seen, START_REFUSED).await;
    stack.stop().await.expect("the stack stops cleanly");
}
