//! An organization member's own privacy choices: Max decides his consent,
//! not Ann; Max calls off his own erasure with the link mailed to him and
//! signs in afresh; and Ann, the only owner, cannot erase her account and
//! leave nobody to run the company.

use ianua_scenarios::actors::Member;
use ianua_scenarios::api::{account, members};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::account::{Consent, ErasureRequest};
use ianua_scenarios::wire::people::LinkToken;
use ianua_scenarios::world::World;

use crate::support::{device, mail_linking_to};

/// Ann cannot grant Max's marketing consent on his behalf. Max grants it
/// and then withdraws it: his history holds both decisions, the
/// withdrawal first, and he still reads his organization.
#[tokio::test]
async fn max_decides_his_own_consent_and_ann_cannot_decide_it_for_him() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let max = world.member();
    let mut decision = Consent {
        consent_type: "Marketing".to_owned(),
        version: "v1".to_owned(),
        granted: true,
    };

    account::member_consent(world.org(), max.id(), &decision)
        .send(world.owner().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    decide_as_max(&world, &mut decision).await;
    members::me(world.org()).send(max.client()).await.ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// Max's own grant and withdrawal remain as two decisions with the withdrawal first.
async fn decide_as_max(world: &World<'_>, decision: &mut Consent) {
    let max = world.member();
    account::member_consent(world.org(), max.id(), decision)
        .send(max.client())
        .await
        .ok();
    decision.granted = false;
    account::member_consent(world.org(), max.id(), decision)
        .send(max.client())
        .await
        .ok();
    let history = account::member_consents(world.org(), max.id())
        .send(max.client())
        .await
        .ok();
    assert_eq!(history.len(), 2, "Max's history holds both decisions");
    assert!(
        !history[0].granted && history[1].granted,
        "the withdrawal comes first, newest first"
    );
}

/// Max asks to erase his account: his session reads nothing at once. He
/// calls the erasure off with the link mailed to him, but the old session
/// stays ended. On a fresh device he signs in and is himself again, and
/// Ann's own session was never touched.
#[tokio::test]
async fn max_calls_off_his_erasure_and_his_old_session_stays_ended() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let max = world.member();
    request_and_cancel_max_erasure(&world).await;
    let mut fresh = Member::new(
        device(&stack, "Max, after calling his erasure off"),
        max.account().clone(),
        max.password(),
    );
    fresh.sign_in(&stack).await;
    let own = members::me(world.org()).send(fresh.client()).await.ok();
    assert_eq!(own.id, max.id(), "Max signs in afresh as himself");
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    stack.stop().await.expect("the stack stops cleanly");
}

/// Max's erasure ends his session, and cancelling by mail does not revive that session.
async fn request_and_cancel_max_erasure(world: &World<'_>) {
    let max = world.member();
    account::member_erase(world.org(), max.id(), &leaving())
        .send(max.client())
        .await
        .ok();
    members::me(world.org())
        .send(max.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let mail = mail_linking_to(world.stack(), max.email(), "/cancel-erasure").await;
    let proof = LinkToken {
        token: mail.token_in("/cancel-erasure"),
    };
    account::member_cancel_erasure(world.org(), &proof)
        .send(world.anonymous().client())
        .await
        .ok();
    members::me(world.org())
        .send(max.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Ann cannot erase her account while she is Acme's only owner. The
/// refusal explains that an owner must stay. Ann still reads her
/// organization, and no erasure is recorded.
#[tokio::test]
async fn ann_the_only_owner_cannot_erase_her_account() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;

    let problem = account::member_erase(world.org(), world.owner().id(), &leaving())
        .send(world.owner().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    assert!(
        problem.message().contains("owner"),
        "the refusal says an owner must stay"
    );
    members::me(world.org())
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        world
            .trail()
            .count("organization.org_erasure_requested")
            .await,
        0,
        "the refused erasure is not recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// The reason given with each erasure in these scenarios.
fn leaving() -> ErasureRequest {
    ErasureRequest {
        reason: "Leaving".to_owned(),
    }
}
