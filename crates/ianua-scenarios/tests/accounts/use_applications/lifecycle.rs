//! Tess publishes an app and moves its route through its life: pointed
//! at a replacement upstream and a new path, taken down, put back up,
//! removed. A visitor's requests reach only the upstream the route points
//! at now, with their path and query; a route taken down or removed
//! forwards nothing. Max, Sam and nobody signed in take nothing down, and
//! a withdrawal whose record cannot be written leaves the app up.

use ianua_scenarios::api::{members, routing};
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::stack::{AuditWrites, Profile, Stack};
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::routing::{NewService, TokenAudience, Upstream};
use ianua_scenarios::world::World;

use crate::support::{Application, once_answering};

/// The longest the replacement upstream may take to answer, in seconds.
const UPSTREAM_TIMEOUT: u32 = 30;

/// Tess publishes an app; a visitor's request reaches it with its path
/// and query. Tess points the route at a replacement upstream under a new
/// path: the old path answers nothing and the new one reaches only the
/// replacement. She takes the route down: nothing is forwarded. She puts
/// it back up: the visitor is served again. Removing a live route is
/// refused; taken down first, it is removed, and nothing is forwarded.
/// Each move is recorded once, the two withdrawals twice.
#[tokio::test]
async fn a_route_forwards_only_where_tess_last_pointed_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = Application::public(&world).await;
    check_original_route(&world, &app).await;
    let replacement = replace_upstream(&world, &app).await;
    check_replacement(&world, &app, &replacement).await;
    disable_route(&world, &app, &replacement).await;
    reactivate_route(&world, &app).await;
    remove_route(&world, &app, &replacement).await;
    check_route_events(&world).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// The original public route forwards the visitor's path and query unchanged.
async fn check_original_route(world: &World<'_>, app: &Application) {
    let visitor = world.anonymous().client();

    app.upstream.forget();
    let arrival = app.visit("/app/order?number=17").send(visitor).await.ok();
    assert_eq!(arrival.path, "/app/order", "the path reaches the upstream");
    assert_eq!(
        arrival.query.as_deref(),
        Some("number=17"),
        "the query reaches the upstream"
    );
}

/// Tess points the existing route at a new upstream and path.
async fn replace_upstream(world: &World<'_>, app: &Application) -> Echo {
    let replacement = Echo::start(world.stack(), &app.host)
        .await
        .expect("the replacement app starts");
    let service = NewService {
        name: "replacement-app".to_owned(),
        upstream: Upstream::at(
            &replacement.url(),
            UPSTREAM_TIMEOUT,
            TokenAudience::NoTokenAccepted,
        ),
    };
    let made = routing::create_service(world.tenant(), &service)
        .send(world.admin().client())
        .await
        .ok();
    app.route_moved(world, &made.id, "/new-app/*")
        .send(world.admin().client())
        .await
        .ok();
    replacement
}

/// The old path disappears and only the replacement upstream receives the new path.
async fn check_replacement(world: &World<'_>, app: &Application, replacement: &Echo) {
    let visitor = world.anonymous().client();
    once_answering(visitor, app.visit("/app/order"), Status::NOT_FOUND).await;
    eventually("the replacement app to receive traffic", || async {
        let answer = app.visit("/new-app/order").send(visitor).await;
        (answer.status() == Status::OK && !replacement.arrivals().is_empty()).then_some(())
    })
    .await;
    app.upstream.forget();
    replacement.forget();
    app.visit("/new-app/order").send(visitor).await.ok();
    assert!(
        app.upstream.arrivals().is_empty(),
        "the old upstream sees nothing any more"
    );
    assert_eq!(
        replacement.arrivals().len(),
        1,
        "the replacement sees the one request"
    );
}

/// Disabling the route removes it from the gateway and forwards nothing.
async fn disable_route(world: &World<'_>, app: &Application, replacement: &Echo) {
    let visitor = world.anonymous().client();
    app.route_disabled(world)
        .send(world.admin().client())
        .await
        .ok();
    once_answering(visitor, app.visit("/new-app/order"), Status::NOT_FOUND).await;
    replacement.forget();
    app.visit("/new-app/order")
        .send(visitor)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert!(
        replacement.arrivals().is_empty(),
        "a route taken down forwards nothing"
    );
}

/// Reactivation makes the replacement path reachable again.
async fn reactivate_route(world: &World<'_>, app: &Application) {
    let visitor = world.anonymous().client();
    app.route_activated(world)
        .send(world.admin().client())
        .await
        .ok();
    once_answering(visitor, app.visit("/new-app/order"), Status::OK).await;
}

/// A live route cannot be removed, but disabling it first permits permanent removal.
async fn remove_route(world: &World<'_>, app: &Application, replacement: &Echo) {
    let visitor = world.anonymous().client();
    app.route_removed(world)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    app.visit("/new-app/order").send(visitor).await.ok();
    app.route_disabled(world)
        .send(world.admin().client())
        .await
        .ok();
    app.route_removed(world)
        .send(world.admin().client())
        .await
        .ok();
    once_answering(visitor, app.visit("/new-app/order"), Status::NOT_FOUND).await;
    replacement.forget();
    app.visit("/new-app/order")
        .send(visitor)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert!(
        replacement.arrivals().is_empty(),
        "a removed route forwards nothing"
    );
}

/// Each lifecycle operation records once, including both separate withdrawals.
async fn check_route_events(world: &World<'_>) {
    for event in [
        "routing.route_updated",
        "routing.route_activated",
        "routing.route_deleted",
    ] {
        assert_eq!(
            world.trail().count(event).await,
            1,
            "one {event} is recorded"
        );
    }
    assert_eq!(
        world.trail().count("routing.route_disabled").await,
        2,
        "both withdrawals are recorded"
    );
}

/// Max, Sam and an anonymous visitor cannot take Tess's app down:
/// a visitor still reaches the upstream, nothing recorded a withdrawal,
/// and Sam still reads his own organization.
#[tokio::test]
async fn nobody_but_an_administrator_takes_an_app_down() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = Application::public(&world).await;
    refuse_withdrawal_callers(&world, &app).await;

    app.upstream.forget();
    app.visit("/app/still-live")
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(
        app.upstream.arrivals().len(),
        1,
        "the app is still up for a visitor"
    );
    assert_eq!(
        world.trail().count("routing.route_disabled").await,
        0,
        "a refused withdrawal records nothing"
    );
    members::me(world.stranger().org())
        .send(world.stranger().client())
        .await
        .ok();

    stack.stop().await.expect("the stack stops cleanly");
}

/// Non-administrators and an anonymous visitor cannot withdraw the app.
async fn refuse_withdrawal_callers(world: &World<'_>, app: &Application) {
    Matrix::new("taking the app down", app.route_disabled(world).call())
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

/// Tess cannot take her app down when the audit record cannot be written.
/// The request fails whole: a visitor still
/// reaches the upstream and nothing is recorded. Once records can be
/// written, the same withdrawal stops the traffic and is recorded once.
#[tokio::test]
async fn a_withdrawal_whose_record_cannot_be_written_leaves_the_app_up() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let app = Application::public(&world).await;
    fail_withdrawal(&world, &app).await;
    check_failed_withdrawal(&world, &app).await;
    retry_withdrawal(&world, &app).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// An unwritable trail makes Tess's withdrawal fail.
async fn fail_withdrawal(world: &World<'_>, app: &Application) {
    world.stack().audit_writes(AuditWrites::Refuse).await;
    let failed = app.route_disabled(world).send(world.admin().client()).await;
    assert_eq!(
        failed.status(),
        Status::INTERNAL_SERVER_ERROR,
        "a withdrawal whose record cannot be written fails: {}",
        failed.summary()
    );
    world.stack().audit_writes(AuditWrites::Allow).await;
}

/// The failed withdrawal leaves the app reachable without a withdrawal event.
async fn check_failed_withdrawal(world: &World<'_>, app: &Application) {
    app.upstream.forget();
    app.visit("/app/still-live")
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(
        app.upstream.arrivals().len(),
        1,
        "the app is still up for a visitor"
    );
    assert_eq!(
        world.trail().count("routing.route_disabled").await,
        0,
        "a failed withdrawal records nothing"
    );
}

/// Retrying after audit recovery stops forwarding and records one withdrawal.
async fn retry_withdrawal(world: &World<'_>, app: &Application) {
    app.route_disabled(world)
        .send(world.admin().client())
        .await
        .ok();
    once_answering(
        world.anonymous().client(),
        app.visit("/app/still-live"),
        Status::NOT_FOUND,
    )
    .await;
    app.upstream.forget();
    app.visit("/app/still-live")
        .send(world.anonymous().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert!(
        app.upstream.arrivals().is_empty(),
        "a route taken down forwards nothing"
    );
    assert_eq!(
        world.trail().count("routing.route_disabled").await,
        1,
        "the withdrawal is recorded once"
    );
}
