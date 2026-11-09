//! Wiki on the tenant's flat random label under the apps domain: every
//! actor reaches its public page there and nobody on another label; Pat
//! signs in to it there and is stopped once she signs out.

use std::time::Duration;

use ianua_scenarios::api::{app_sign_in, routing};
use ianua_scenarios::expect::{Matrix, Records, eventually_within};
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::app_sign_in::{AppLogIn, AppSignInSettings, ConfigureAppSignIn};
use ianua_scenarios::wire::routing::{NewRoute, RoutePolicy};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{customer, probe, profile};

/// How long the gateway is given to pick up Wiki's sign-in setting.
const RELOAD_PATIENCE: Duration = Duration::from_secs(30);

/// Tess pins Wiki to the tenant's random flat label under the apps domain.
/// Ann, Tess, Max, Sam and nobody signed in all reach its public page.
/// Nobody reaches Wiki on the twin tenant's label or on a label nobody
/// holds, and Tess cannot even save a route on either: the API refuses
/// both before a route exists. The gateway records the allowed request.
#[tokio::test]
async fn wiki_answers_on_the_tenants_own_random_label_and_on_no_other() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let own = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let other = routing::hostnames(world.twin())
        .send(world.stranger().client())
        .await
        .ok();
    assert!(
        !own.readable_address && own.slug_subdomain.is_none(),
        "a tenant starts with its random label alone"
    );
    assert_ne!(
        own.platform_label, other.platform_label,
        "the twin tenant has a label of its own"
    );
    let host = format!("wiki-{}", own.uuid_subdomain);
    let wiki = Echo::start(&stack, &host).await.expect("Wiki starts");
    let applied = RouteSpec::public("wiki", "/wiki/*")
        .on_hosts(std::slice::from_ref(&host))
        .applied(
            world.admin().client(),
            &probe(&stack),
            Placement {
                tenant: world.tenant(),
                upstream: &wiki.url(),
                host: &host,
            },
        )
        .await;
    wiki.forget();

    let url = format!("https://{host}/wiki/page");
    Matrix::new("reading Wiki on its random platform label", Call::get(&url))
        .allowed(world.owner().client())
        .allowed(world.admin().client())
        .allowed(world.member().client())
        .allowed(world.stranger().client())
        .allowed(world.anonymous().client())
        .run()
        .await;
    assert_eq!(wiki.arrivals().len(), 5, "every actor reached Wiki once");

    wiki.forget();
    for foreign in [
        format!("wiki-{}", other.uuid_subdomain),
        format!("wiki-unknown.{}", stack.apps_domain()),
    ] {
        let answer = world
            .anonymous()
            .client()
            .get::<IgnoredAny>(&format!("https://{foreign}/wiki/page"))
            .await;
        assert_eq!(
            answer.status(),
            Status::NOT_FOUND,
            "Wiki is not served on {foreign}: {}",
            answer.summary()
        );
        let stolen = NewRoute {
            name: "forbidden-host".to_owned(),
            path_pattern: "/stolen/*".to_owned(),
            methods: Vec::new(),
            service_id: applied.service_id.clone(),
            pipeline_id: applied.pipeline_id.clone(),
            policy: RoutePolicy::Public,
            hosts: vec![foreign.clone()],
        };
        let refused = routing::create_route(world.tenant(), &stolen)
            .send(world.admin().client())
            .await;
        assert_eq!(
            refused.status(),
            Status::UNPROCESSABLE_ENTITY,
            "a route on {foreign} is refused before it exists: {}",
            refused.summary()
        );
    }
    assert!(
        wiki.arrivals().is_empty(),
        "nothing reached Wiki on a foreign label"
    );

    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded("/wiki/page")
        .await;
    assert_eq!(record.decision, "allowed", "the public page is allowed");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess puts Wiki on the tenant's random flat label, signing people in on
/// that host. Pat signs in there and reaches Wiki's private page; Ann,
/// Tess, Max, Sam and nobody signed in are refused it, Wiki seeing nothing
/// of them. Pat signs out and is refused too. The gateway records Pat's
/// allowed request, and the trail holds the sign-in setting.
#[tokio::test]
async fn a_random_app_host_signs_people_in_and_stops_them_after_sign_out() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let names = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let host = format!("wiki-{}", names.uuid_subdomain);
    let wiki = Echo::start(&stack, &host).await.expect("Wiki starts");
    let applied = RouteSpec::public("wiki", "/wiki/*")
        .asking(RoutePolicy::Authenticated)
        .pinned("wiki")
        .on_hosts(std::slice::from_ref(&host))
        .applied(
            world.admin().client(),
            &probe(&stack),
            Placement {
                tenant: world.tenant(),
                upstream: &wiki.url(),
                host: &host,
            },
        )
        .await;
    routing::configure_app_sign_in(
        world.tenant(),
        &applied.service_id,
        &ConfigureAppSignIn {
            app_sign_in: Some(AppSignInSettings {
                hosts: vec![host.clone()],
                signed_out_browsers: "refuse".to_owned(),
            }),
            accepts_app_sign_in_of: None,
            delivery: None,
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    let login = format!("https://{host}/.ianua/login");
    eventually_within("Wiki to accept sign-ins", RELOAD_PATIENCE, || async {
        let answer = world.anonymous().client().get::<IgnoredAny>(&login).await;
        (answer.status() == Status::OK).then_some(())
    })
    .await;
    let pat = customer(&world, "pat", "Pat Customer").await;

    let signed_in = app_sign_in::log_in(
        &host,
        &AppLogIn {
            email: pat.email().to_owned(),
            password: pat.password().to_owned(),
        },
    )
    .send(pat.client())
    .await
    .ok();
    assert!(
        signed_in.signed_in && !signed_in.mfa_required,
        "Pat is signed in at Wiki"
    );
    wiki.forget();
    let page = format!("https://{host}/wiki/private");
    Matrix::new("reading Wiki's private page", Call::get(&page))
        .allowed(pat.client())
        .refused(
            world.owner().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .refused(
            world.admin().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .refused(
            world.member().client(),
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
    assert_eq!(wiki.arrivals().len(), 1, "only Pat reached Wiki");
    let record = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where("/wiki/private", "Pat's allowed request", |record| {
            record.subject.id.as_deref() == Some(pat.id())
        })
        .await;
    assert_eq!(record.decision, "allowed", "Pat's request is allowed");

    app_sign_in::log_out(&host).send(pat.client()).await.ok();
    wiki.forget();
    Matrix::new(
        "reading Wiki's private page after signing out",
        Call::get(&page),
    )
    .refused(pat.client(), Status::UNAUTHORIZED, "unauthenticated")
    .run()
    .await;
    assert!(
        wiki.arrivals().is_empty(),
        "nothing reached Wiki after Pat signed out"
    );
    assert_eq!(
        world.trail().count("routing.app_sign_in_changed").await,
        1,
        "the trail holds Wiki's sign-in setting once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
