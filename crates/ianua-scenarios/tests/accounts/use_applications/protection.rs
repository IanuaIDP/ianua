//! Pat and Uma sign in on a protected app's own host. Tess locks Pat: her
//! cookie reaches the app no more, while Uma goes on. Tess restores Pat:
//! only a fresh sign-in lets her back, and signing out ends that too.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{app_sign_in, people};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::AssertionCheck;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::people::ChangeUserStatus;
use ianua_scenarios::world::World;

use crate::support::{Application, invited, signed_in_at};

/// Pat and Uma, invited into the tenant, each sign in on the protected
/// app's host and reach it with a verified assertion. Tess locks Pat: her
/// cookie is refused and the upstream sees only Uma. Tess makes Pat active
/// again: her old cookie is still dead, a fresh sign-in reaches the app,
/// and once she signs out her cookie reaches nothing.
#[tokio::test]
async fn a_locked_person_is_cut_off_from_the_app_until_a_fresh_sign_in() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = Application::protected(&world).await;
    let pat = invited(&world, "pat", "Pat Holder").await;
    let uma = invited(&world, "uma", "Uma Colleague").await;
    for person in [&pat, &uma] {
        verify_app_sign_in(&app, person).await;
    }
    lock_pat(&world, &app, &pat, &uma).await;
    restore_pat(&world, &app, &pat).await;
    sign_out_pat(&app, &pat).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// A password sign-in reaches the app with a verified gateway assertion.
async fn verify_app_sign_in(app: &Application, person: &Person) {
    signed_in_at(app, person).await;
    let arrival = app.visit("/app/account").send(person.client()).await.ok();
    assert!(
        matches!(arrival.assertion, AssertionCheck::Verified { .. }),
        "the app verifies the assertion naming {}",
        person.email()
    );
}

/// Locking Pat blocks her cookie while Uma's request still reaches the upstream.
async fn lock_pat(world: &World<'_>, app: &Application, pat: &Person, uma: &Person) {
    let locked = ChangeUserStatus {
        status: "Locked".to_owned(),
    };
    people::change_status(world.tenant(), pat.id(), &locked)
        .send(world.admin().client())
        .await
        .ok();
    app.upstream.forget();
    app.visit("/app/account")
        .send(pat.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    app.visit("/app/account").send(uma.client()).await.ok();
    assert_eq!(
        app.upstream.arrivals().len(),
        1,
        "the app saw Uma's request alone"
    );
}

/// Restoring Pat keeps her old cookie invalid until she signs in again.
async fn restore_pat(world: &World<'_>, app: &Application, pat: &Person) {
    let active = ChangeUserStatus {
        status: "Active".to_owned(),
    };
    people::change_status(world.tenant(), pat.id(), &active)
        .send(world.admin().client())
        .await
        .ok();
    app.visit("/app/account")
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    signed_in_at(app, pat).await;
    app.visit("/app/account").send(pat.client()).await.ok();
}

/// Signing out prevents Pat's cookie from forwarding any further request.
async fn sign_out_pat(app: &Application, pat: &Person) {
    app_sign_in::log_out(&app.host)
        .send(pat.client())
        .await
        .ok();
    app.upstream.forget();
    app.visit("/app/account")
        .send(pat.client())
        .await
        .refused(Status::UNAUTHORIZED, "unauthenticated");
    assert!(
        app.upstream.arrivals().is_empty(),
        "nothing reaches the app after Pat signed out"
    );
}
