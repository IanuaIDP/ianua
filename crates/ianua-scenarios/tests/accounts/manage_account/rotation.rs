//! Pat's session token traded for a new one: the refreshed session
//! retires the token it came from, a replayed old token ends Pat's
//! sessions and nobody else's, and Uma cannot spend Pat's token.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{people, sessions};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::tenant_sign_in::{RefreshSession, RefreshedSession};
use ianua_scenarios::world::World;

use crate::support::{
    SignedDevice, device, invited_and_signed_in, signed_in_elsewhere, still_signed_in,
    tenant_records,
};

/// Pat refreshes the session on her laptop and uses the new token. The old
/// token, copied before that, is replayed from her other device: the
/// platform takes the replay for a theft and ends the laptop's new session
/// and that other device too, while Uma's session goes on. One revocation
/// is recorded, with neither token in it.
#[tokio::test]
async fn a_replayed_old_token_ends_pats_sessions_and_nobody_elses() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    let laptop = signed_in_elsewhere(&world, &pat).await;

    let old = RefreshSession {
        refresh_token: laptop.session.refresh_token.clone(),
    };
    let refreshed = sessions::refresh(world.tenant(), &old)
        .send(&laptop.client)
        .await
        .ok();
    let mut browser = device(&stack, "Pat's laptop with the new token");
    browser.authorize(&refreshed.refresh_token);
    people::me(world.tenant()).send(&browser).await.ok();
    still_signed_in(&world, &pat).await;
    replay_old_token(&world, &pat, &old, &browser).await;
    still_signed_in(&world, &uma).await;
    check_replay_record(&world, &refreshed, &old).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Replay detection records one revocation without either the old or replacement token.
async fn check_replay_record(
    world: &World<'_>,
    refreshed: &RefreshedSession,
    old: &RefreshSession,
) {
    assert_eq!(
        tenant_records(
            world,
            "authentication.session_revoked",
            &[&refreshed.refresh_token, &old.refresh_token]
        )
        .await,
        1,
        "the theft response is recorded once"
    );
}

/// Replaying the old token from Pat's other device invalidates both of Pat's sessions.
async fn replay_old_token(world: &World<'_>, pat: &Person, old: &RefreshSession, browser: &Client) {
    sessions::refresh(world.tenant(), old)
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::me(world.tenant())
        .send(browser)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    people::me(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Pat, on her laptop, refreshes her session: the new token and session
/// are not the old ones, the old token reads nothing any more, and the new
/// one reads Pat's record in her tenant and nothing in the twin. Uma's
/// session goes on, and one refresh is recorded with no token in it.
#[tokio::test]
async fn a_refreshed_session_retires_the_token_it_came_from() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    let laptop = signed_in_elsewhere(&world, &pat).await;
    people::me(world.tenant()).send(&laptop.client).await.ok();

    let old = RefreshSession {
        refresh_token: laptop.session.refresh_token.clone(),
    };
    let refreshed = sessions::refresh(world.tenant(), &old)
        .send(&laptop.client)
        .await
        .ok();
    check_retired_token(&world, &laptop, &refreshed).await;
    check_new_token(&world, &pat, &refreshed).await;
    still_signed_in(&world, &uma).await;
    assert_eq!(
        tenant_records(
            &world,
            "authentication.token_refreshed",
            &[&refreshed.refresh_token, &old.refresh_token]
        )
        .await,
        1,
        "the refresh is recorded once"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Rotation changes both token and session identity and retires the original browser's token.
async fn check_retired_token(
    world: &World<'_>,
    laptop: &SignedDevice,
    refreshed: &RefreshedSession,
) {
    assert!(
        refreshed.refresh_token != laptop.session.refresh_token,
        "the refresh hands out a new token"
    );
    assert_ne!(
        refreshed.session_id, laptop.session.session_id,
        "the refresh opens a new session"
    );
    people::me(world.tenant())
        .send(&laptop.client)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// The replacement token reads Pat's own account but cannot enter the twin tenant.
async fn check_new_token(world: &World<'_>, pat: &Person, refreshed: &RefreshedSession) {
    let mut browser = device(world.stack(), "Pat's laptop with the new token");
    browser.authorize(&refreshed.refresh_token);
    let own = people::me(world.tenant()).send(&browser).await.ok();
    assert_eq!(own.id, pat.id(), "the new token reads Pat's own record");
    people::me(world.twin())
        .send(&browser)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Uma cannot refresh Pat's token, and Pat's laptop cannot refresh it in
/// the twin tenant. Neither attempt spends the token: Pat's laptop still
/// refreshes it, the new token reads Pat's record, Uma's session goes
/// on, and one refresh is recorded with no token in it.
#[tokio::test]
async fn uma_cannot_spend_pats_refresh_token() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    let laptop = signed_in_elsewhere(&world, &pat).await;
    let pats = RefreshSession {
        refresh_token: laptop.session.refresh_token.clone(),
    };
    refuse_foreign_refresh(&world, &uma, &laptop, &pats).await;

    let refreshed = sessions::refresh(world.tenant(), &pats)
        .send(&laptop.client)
        .await
        .ok();
    let mut browser = device(&stack, "Pat's laptop with the new token");
    browser.authorize(&refreshed.refresh_token);
    let own = people::me(world.tenant()).send(&browser).await.ok();
    assert_eq!(own.id, pat.id(), "the new token reads Pat's own record");
    still_signed_in(&world, &uma).await;
    assert_own_refresh_record(&world, &pats).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Only the laptop's successful refresh is recorded, without its credential.
async fn assert_own_refresh_record(world: &World<'_>, pats: &RefreshSession) {
    assert_eq!(
        tenant_records(
            world,
            "authentication.token_refreshed",
            &[&pats.refresh_token]
        )
        .await,
        1,
        "only the laptop's own refresh is recorded"
    );
}

/// Another holder and a foreign tenant cannot spend the laptop's token or end its session.
async fn refuse_foreign_refresh(
    world: &World<'_>,
    uma: &Person,
    laptop: &SignedDevice,
    pats: &RefreshSession,
) {
    sessions::refresh(world.tenant(), pats)
        .send(uma.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    sessions::refresh(world.twin(), pats)
        .send(&laptop.client)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    people::me(world.tenant()).send(&laptop.client).await.ok();
}
