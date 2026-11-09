//! Pat looking after her own sessions in the tenant: signing out
//! everywhere else and keeping this device, ending one session by its id,
//! Uma's session id giving her no hold over it, and each holder reading
//! their own sign-ins and nobody else's.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{account, people, sessions};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::world::World;

use crate::support::{invited_and_signed_in, still_signed_in, tenant_records};

/// Pat, signed in on her laptop and her phone as well, signs out
/// everywhere else from her first device. The laptop and the phone are
/// out at once; her first device and Uma's session go on. Signing out
/// everywhere else again changes nothing, and still keeps this device.
#[tokio::test]
async fn signing_out_everywhere_else_keeps_this_device_and_umas() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    let (laptop, _) = pat.on_another_device(&stack, "Pat's laptop").await;
    let (phone, _) = pat.on_another_device(&stack, "Pat's phone").await;
    people::me(world.tenant()).send(&laptop).await.ok();
    people::me(world.tenant()).send(&phone).await.ok();
    sign_out_other_devices(&world, &pat, &laptop, &phone).await;
    still_signed_in(&world, &pat).await;
    still_signed_in(&world, &uma).await;
    check_current_session(&world, &pat).await;

    account::sign_out_others(world.tenant())
        .send(pat.client())
        .await
        .ok();
    still_signed_in(&world, &pat).await;
    assert!(
        tenant_records(&world, "authentication.session_revoked", &[]).await >= 2,
        "each device signed out is recorded"
    );

    stack.stop().await.expect("the stack stops cleanly");
}

/// Signing out other devices blocks both the laptop and phone on their next request.
async fn sign_out_other_devices(world: &World<'_>, pat: &Person, laptop: &Client, phone: &Client) {
    account::sign_out_others(world.tenant())
        .send(pat.client())
        .await
        .ok();
    people::me(world.tenant())
        .send(laptop)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    people::me(world.tenant())
        .send(phone)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
}

/// Only the requesting session remains active and is marked current.
async fn check_current_session(world: &World<'_>, pat: &Person) {
    let live = sessions::my_sessions(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert_eq!(
        live.iter()
            .filter(|session| session.status == "active")
            .count(),
        1,
        "one session of Pat's is left"
    );
    assert!(
        live.iter()
            .any(|session| session.id == pat.session_id() && session.current),
        "the session left is the one that asked"
    );
}

/// Pat ends her laptop's session, then the one she is asking from. Each
/// is out on its very next request; the laptop's ending leaves her phone
/// signed in, and an ended session lists no sessions any more.
#[tokio::test]
async fn an_ended_session_is_out_on_its_very_next_request() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut pat = invited_and_signed_in(&world, "pat").await;
    let (laptop, laptop_session) = pat.on_another_device(&stack, "Pat's laptop").await;
    let (phone, _) = pat.on_another_device(&stack, "Pat's phone").await;
    people::me(world.tenant()).send(&laptop).await.ok();

    sessions::end_my_session(world.tenant(), &laptop_session)
        .send(pat.client())
        .await
        .ok();
    people::me(world.tenant())
        .send(&laptop)
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    people::me(world.tenant()).send(&phone).await.ok();
    end_current_session(&world, &pat, &phone).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Ending the requesting session blocks its session list while the unended phone still reads Pat.
async fn end_current_session(world: &World<'_>, pat: &Person, phone: &Client) {
    sessions::end_my_session(world.tenant(), pat.session_id())
        .send(pat.client())
        .await
        .ok();
    sessions::my_sessions(world.tenant())
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    let from_phone = people::me(world.tenant()).send(phone).await.ok();
    assert_eq!(
        from_phone.id,
        pat.id(),
        "the phone, never ended, still reads Pat's record"
    );
}

/// Pat cannot end Uma's session by its id, and anonymous callers cannot
/// list sessions. Uma's session is not even listed to
/// her, and both go on as before.
#[tokio::test]
async fn umas_session_id_gives_pat_no_hold_over_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    sessions::end_my_session(world.tenant(), uma.session_id())
        .send(pat.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    sessions::my_sessions(world.tenant())
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");

    let pats = sessions::my_sessions(world.tenant())
        .send(pat.client())
        .await
        .ok();
    assert!(
        pats.iter().all(|session| session.id != uma.session_id()),
        "Uma's session is not among Pat's"
    );
    still_signed_in(&world, &pat).await;
    still_signed_in(&world, &uma).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat and Uma, in the same tenant, each read their own sign-ins: each
/// sees their own successful sign-in and none of the other's records.
/// Nobody signed in reads any, and Pat's session reads none in the twin.
#[tokio::test]
async fn each_holder_reads_only_their_own_sign_ins() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = invited_and_signed_in(&world, "pat").await;
    let uma = invited_and_signed_in(&world, "uma").await;
    check_separate_histories(&world, &pat, &uma).await;

    account::sign_ins(world.tenant())
        .send(world.anonymous().client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    account::sign_ins(world.twin())
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");

    stack.stop().await.expect("the stack stops cleanly");
}

/// Each holder sees a successful sign-in and none of the other holder's history entries.
async fn check_separate_histories(world: &World<'_>, pat: &Person, uma: &Person) {
    let pats = account::sign_ins(world.tenant())
        .send(pat.client())
        .await
        .ok();
    let umas = account::sign_ins(world.tenant())
        .send(uma.client())
        .await
        .ok();
    assert!(
        pats.items
            .iter()
            .any(|event| event.event_type == "authentication.login_succeeded"),
        "Pat sees her own sign-in"
    );
    assert!(
        umas.items
            .iter()
            .any(|event| event.event_type == "authentication.login_succeeded"),
        "Uma sees her own sign-in"
    );
    assert!(
        pats.items
            .iter()
            .all(|event| umas.items.iter().all(|other| other.id != event.id)),
        "no record is in both histories"
    );
}
