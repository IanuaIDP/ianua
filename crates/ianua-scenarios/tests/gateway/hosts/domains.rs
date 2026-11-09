//! A domain of the tenant's own through its whole life at the gateway:
//! while Tess holds it nobody else may claim it or route on it; once she
//! removes it the gateway stops serving the name at the handshake; and
//! when Sam proves it for his own tenant, only his app answers there.
//! None of Tess's old routes go along with the name.

use ianua_scenarios::api::{domains, routing};
use ianua_scenarios::expect::eventually;
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::{Placement, RouteSpec, domain, visit};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::domains::NewDomain;
use ianua_scenarios::wire::routing::{
    NewPipeline, NewRoute, NewService, RoutePolicy, TokenAudience, Upstream,
};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{probe, profile, word};

/// The path every visit asks for.
const MARKET_PAGE: &str = "/market/stall";

/// How long Sam's would-be route gives its app, in seconds.
const UPSTREAM_TIMEOUT: u32 = 30;

/// Tess proves a domain and serves her market app on it. Sam cannot claim
/// the name or put a route on it from his own tenant. Tess removes it:
/// soon a visitor's handshake is refused, the record is in the trail, and
/// the app sees nothing more. Sam now claims and proves the name for his
/// tenant and serves his own app there: a visitor reaches his app and
/// nothing of Tess's, though her route still names the host.
#[tokio::test]
async fn a_removed_domain_stops_serving_and_its_next_owner_inherits_nothing() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let name = format!("market-{}.{}", word(), stack.customer_domain());
    let tess = world.admin().client();
    let sam = world.stranger().client();
    let visitor = world.anonymous().client();

    domain::brought(&stack, tess, world.tenant(), &name).await;
    let tess_app = Echo::start(&stack, &name)
        .await
        .expect("Tess's market app starts");
    RouteSpec::public("market", "/market/*")
        .on_hosts(std::slice::from_ref(&name))
        .applied(
            tess,
            &probe(&stack),
            Placement {
                tenant: world.tenant(),
                upstream: &tess_app.url(),
                host: &name,
            },
        )
        .await;
    tess_app.forget();
    visit(&name, MARKET_PAGE).send(visitor).await.ok();
    assert_eq!(tess_app.arrivals().len(), 1, "Tess's app serves her name");

    domains::add(
        world.twin(),
        &NewDomain {
            domain: name.clone(),
        },
    )
    .send(sam)
    .await
    .refused(Status::CONFLICT, "conflict");
    let refused = routing::create_route(world.twin(), &route_on_held(&world, &name).await)
        .send(sam)
        .await;
    assert_eq!(
        refused.status(),
        Status::UNPROCESSABLE_ENTITY,
        "Sam cannot route on a name Tess holds: {}",
        refused.summary()
    );

    let held = domain_id(&world, &name).await;
    domains::remove(world.tenant(), &held).send(tess).await.ok();
    world.trail().recorded("tenant.domain_removed").await;
    let address = format!("https://{name}{MARKET_PAGE}");
    eventually(
        "the gateway to refuse the name at the handshake",
        || async {
            probe(&stack)
                .attempt::<IgnoredAny>(Call::get(address.as_str()))
                .await
                .is_err()
                .then_some(())
        },
    )
    .await;
    tess_app.forget();

    domain::brought(&stack, sam, world.twin(), &name).await;
    let sam_host = app_host_of_twin(&world).await;
    let sam_app = Echo::start(&stack, &sam_host)
        .await
        .expect("Sam's market app starts");
    RouteSpec::public("market", "/market/*")
        .on_hosts(std::slice::from_ref(&name))
        .applied(
            sam,
            &probe(&stack),
            Placement {
                tenant: world.twin(),
                upstream: &sam_app.url(),
                host: &name,
            },
        )
        .await;
    sam_app.forget();
    visit(&name, MARKET_PAGE).send(visitor).await.ok();
    assert_eq!(sam_app.arrivals().len(), 1, "the name now serves Sam's app");
    assert!(
        tess_app.arrivals().is_empty(),
        "nothing of the name reached Tess's old app"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// The route Sam tries to put on the name Tess holds, on a service and
/// pipeline of his own, so that the name is all that is wrong with it.
async fn route_on_held(world: &World<'_>, name: &str) -> NewRoute {
    let sam = world.stranger().client();
    let service_id = routing::create_service(
        world.twin(),
        &NewService {
            name: "sams-market-service".to_owned(),
            upstream: Upstream::at(
                "http://127.0.0.1:9",
                UPSTREAM_TIMEOUT,
                TokenAudience::NoTokenAccepted,
            ),
        },
    )
    .send(sam)
    .await
    .ok()
    .id;
    let pipeline_id = routing::create_pipeline(
        world.twin(),
        &NewPipeline {
            name: "sams-market-pipeline".to_owned(),
        },
    )
    .send(sam)
    .await
    .ok()
    .id;
    NewRoute {
        name: "stolen-market".to_owned(),
        path_pattern: "/market/*".to_owned(),
        methods: Vec::new(),
        service_id,
        policy: RoutePolicy::Public,
        pipeline_id,
        hosts: vec![name.to_owned()],
    }
}

/// The id of the domain Tess registered under `name`.
async fn domain_id(world: &World<'_>, name: &str) -> String {
    let listed = domains::list(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let Some(held) = listed
        .items
        .into_iter()
        .find(|domain| domain.domain == name)
    else {
        panic!("Tess holds no domain named {name}");
    };
    held.id
}

/// The twin tenant's own host under the apps domain, where its app's
/// assertions are checked.
async fn app_host_of_twin(world: &World<'_>) -> String {
    let names = routing::hostnames(world.twin())
        .send(world.stranger().client())
        .await
        .ok();
    names.slug_subdomain.unwrap_or(names.uuid_subdomain)
}
