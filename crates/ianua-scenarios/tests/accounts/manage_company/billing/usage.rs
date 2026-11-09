//! Ann reads the bill and what her company uses: a new company stands on
//! the Free plan with its one tenant, and the limits she reads are the
//! plan's. Uma the viewer reads them too; Tess, Max, Sam and nobody
//! signed in do not.

use ianua_scenarios::api::{billing, people};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::wire::people::InviteUser;
use ianua_scenarios::world::{MEMBER_ROLE, World};

use crate::support::colleague_signed_in;

/// A new company reads as the Free plan, billed monthly and paid up, no
/// payment method on file and its trial unused. It works under the Free
/// plan's limits, with its one tenant in use; Pat, invited and joined, is counted among
/// its users.
#[tokio::test]
async fn ann_reads_the_bill_of_a_new_company_and_what_it_uses() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let bill = billing::subscription(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(bill.plan, "Free", "a new company is on the Free plan");
    assert_eq!(bill.cycle, "monthly", "billed monthly");
    assert_eq!(bill.state, "active", "with nothing owed");
    assert!(bill.trial_ends_at.is_none(), "no trial runs");
    assert!(bill.past_due_since.is_none(), "nothing fell due");
    assert!(!bill.payment_method_on_file, "no card is on file");
    assert!(!bill.trial_used, "the one trial is still there");

    let report = billing::usage(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(report.plan, "Free", "the usage is against the Free plan");
    assert_eq!(
        report.limits["max_tenants_per_org"], 1,
        "the Free plan's tenant limit applies"
    );
    assert_eq!(report.usage.tenants, 1, "one tenant is in use");

    let pat_counted = report.usage.users + 1;
    invite_pat_and_let_her_accept(&world).await;
    let after = billing::usage(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        after.usage.users, pat_counted,
        "Pat is counted once she joined"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat, invited into Ann's tenant by Tess with the `Member` role, accepts
/// from the mailed link.
async fn invite_pat_and_let_her_accept(world: &World<'_>) {
    let mut pat = world.newcomer("pat", "Pat Person");
    let invitation = InviteUser {
        email: pat.email().to_owned(),
        display_name: pat.account().display_name.clone(),
        role_id: world.role_id(MEMBER_ROLE).await,
    };
    let invited = people::invite(world.tenant(), &invitation)
        .send(world.admin().client())
        .await
        .ok();
    pat.record_invitation(&invited.id);
    pat.accept_invitation(world.stack()).await;
}

/// Uma, a viewer, reads the bill and the usage, as Ann does. Tess and
/// Max, plain members, do not; nor does Sam, of another company; nor
/// anyone signed in to nothing.
#[tokio::test]
async fn the_bill_is_read_only_by_whoever_may_read_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let uma = colleague_signed_in(&world, "uma", OrgRole::Viewer).await;

    for call in [
        billing::subscription(world.org()).call(),
        billing::usage(world.org()).call(),
    ] {
        Matrix::new("reading what the company pays and uses", call)
            .allowed(world.owner().client())
            .allowed(uma.client())
            .refused(world.admin().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
            .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
            .refused(
                world.anonymous().client(),
                Status::UNAUTHORIZED,
                "unauthenticated",
            )
            .run()
            .await;
    }

    stack.stop().await.expect("the stack stops cleanly");
}
