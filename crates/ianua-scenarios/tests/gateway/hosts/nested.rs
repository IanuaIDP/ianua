//! Wiki on the tenant's nested random label: the worker orders the root
//! and wildcard certificates, the name server proves them, and the gateway
//! serves Wiki over TLS there and on no other tenant's label; a readable
//! name answers only once Tess opts in, and stops when she opts out.

use std::time::Duration;

use ianua_scenarios::api::{routing, tenants};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::{Matrix, eventually_within};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::{Placement, RouteSpec};
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::tenants::TenantChange;
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{probe, profile};

/// How far the application clock is advanced for the worker to order a
/// certificate it would otherwise wait its next pass for.
const NEXT_CERTIFICATE_PASS: Duration = Duration::from_secs(6 * 60);

/// How long the real worker, the authoritative name server and the
/// gateway's certificate reload are given to serve a new name.
const CERTIFICATE_PATIENCE: Duration = Duration::from_secs(45);

/// How long the gateway is given to withdraw a readable name.
const RELOAD_PATIENCE: Duration = Duration::from_secs(30);

/// On a deployment nesting labels under the apps domain, the worker orders
/// the tenant's root and wildcard certificates through ACME, the bundled
/// name server proves them, and Tess puts Wiki on the nested label, where
/// every actor reaches it over TLS. Nobody reaches Wiki on the twin's
/// label, and a label nobody holds gets no certificate at all. Max and Sam
/// may not enable readable names; Tess does, and Wiki answers on the
/// readable name once its certificate is there. Tess opts out again: the
/// readable name stops serving, the random label still serves, and both
/// choices are in the trail.
#[tokio::test]
async fn a_nested_label_is_served_over_tls_and_a_readable_name_follows_tess_consent() {
    let clock = Clock::controlled();
    let stack = Stack::start(profile().with("PLATFORM_ADDRESSING", "nested"))
        .await
        .expect("the nested stack starts");
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
    let host = format!("wiki.{}", own.uuid_subdomain);
    clock.advance(NEXT_CERTIFICATE_PASS);
    certificate_ready(world.anonymous().client(), &host).await;
    let wiki = Echo::start(&stack, &host).await.expect("Wiki starts");
    RouteSpec::public("nested-wiki", "/wiki/*")
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
    Matrix::new("reading Wiki on its nested random label", Call::get(&url))
        .allowed(world.owner().client())
        .allowed(world.admin().client())
        .allowed(world.member().client())
        .allowed(world.stranger().client())
        .allowed(world.anonymous().client())
        .run()
        .await;
    assert_eq!(wiki.arrivals().len(), 5, "every actor reached Wiki once");

    wiki.forget();
    let foreign = format!("wiki.{}", other.uuid_subdomain);
    certificate_ready(world.anonymous().client(), &foreign).await;
    let answer = world
        .anonymous()
        .client()
        .get::<IgnoredAny>(&format!("https://{foreign}/wiki/page"))
        .await;
    assert_eq!(
        answer.status(),
        Status::NOT_FOUND,
        "Wiki is not served on the twin's label: {}",
        answer.summary()
    );
    let unknown = format!("https://wiki.unknown.{}/wiki/page", stack.apps_domain());
    assert!(
        world
            .anonymous()
            .client()
            .attempt::<IgnoredAny>(Call::get(&unknown))
            .await
            .is_err(),
        "a label nobody holds has no certificate, so the handshake fails"
    );
    assert!(
        wiki.arrivals().is_empty(),
        "nothing reached Wiki on a foreign label"
    );

    let enable = TenantChange {
        readable_address: Some(true),
        ..TenantChange::default()
    };
    for caller in [world.member().client(), world.stranger().client()] {
        let refused = tenants::change(world.tenant(), &enable).send(caller).await;
        assert_eq!(
            refused.status(),
            Status::FORBIDDEN,
            "only someone with settings authority enables readable names: {}",
            refused.summary()
        );
    }
    tenants::change(world.tenant(), &enable)
        .send(world.admin().client())
        .await
        .ok();
    let on = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    let Some(readable_root) = on.slug_subdomain else {
        panic!("opting in gives the tenant a readable root");
    };
    let readable = format!("wiki.{readable_root}");
    assert_eq!(
        on.platform_label, own.platform_label,
        "opting in keeps the random label"
    );
    clock.advance(NEXT_CERTIFICATE_PASS);
    certificate_ready(world.anonymous().client(), &readable).await;
    RouteSpec::public("readable-wiki", "/wiki/*")
        .on_hosts(std::slice::from_ref(&readable))
        .applied(
            world.admin().client(),
            &probe(&stack),
            Placement {
                tenant: world.tenant(),
                upstream: &wiki.url(),
                host: &readable,
            },
        )
        .await;
    let readable_url = format!("https://{readable}/wiki/page");
    let answer = world
        .anonymous()
        .client()
        .get::<IgnoredAny>(&readable_url)
        .await;
    assert_eq!(
        answer.status(),
        Status::OK,
        "Wiki answers on the readable name: {}",
        answer.summary()
    );
    assert_eq!(
        world.trail().count("tenant.readable_address_changed").await,
        1,
        "the trail holds Tess opting in"
    );

    tenants::change(
        world.tenant(),
        &TenantChange {
            readable_address: Some(false),
            ..TenantChange::default()
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    wiki.forget();
    eventually_within(
        "the readable name to stop serving",
        RELOAD_PATIENCE,
        || async {
            match world
                .anonymous()
                .client()
                .attempt::<IgnoredAny>(Call::get(&readable_url))
                .await
            {
                Err(_) => Some(()),
                Ok(answer) if answer.status() == Status::NOT_FOUND => Some(()),
                Ok(_) => None,
            }
        },
    )
    .await;
    wiki.forget();
    let withdrawn = world
        .anonymous()
        .client()
        .attempt::<IgnoredAny>(Call::get(&readable_url))
        .await;
    assert!(
        withdrawn
            .as_ref()
            .is_ok_and(|answer| answer.status() == Status::NOT_FOUND)
            || withdrawn.is_err(),
        "the readable name serves nothing once Tess opted out"
    );
    assert!(
        wiki.arrivals().is_empty(),
        "nothing reached Wiki on the withdrawn readable name"
    );
    let still = world.anonymous().client().get::<IgnoredAny>(&url).await;
    assert_eq!(
        still.status(),
        Status::OK,
        "the random label still serves Wiki: {}",
        still.summary()
    );
    assert_eq!(
        world.trail().count("tenant.readable_address_changed").await,
        2,
        "the trail holds Tess opting out too"
    );
    let off = routing::hostnames(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        off.slug_subdomain.is_none(),
        "opting out withdraws the readable root"
    );
    assert_eq!(
        off.platform_label, own.platform_label,
        "opting out keeps the random label"
    );
    stack.stop().await.expect("the nested stack stops cleanly");
}

/// Waits until the gateway serves `host` over a trusted TLS handshake and
/// answers that it serves nothing at a path no route has, while the real
/// worker, the authoritative name server and the certificate reload
/// finish their work.
async fn certificate_ready(client: &Client, host: &str) {
    let url = format!("https://{host}/not-a-route");
    eventually_within(
        "the platform certificate to be served",
        CERTIFICATE_PATIENCE,
        || async {
            client
                .attempt::<IgnoredAny>(Call::get(&url))
                .await
                .ok()
                .filter(|answer| answer.status() == Status::NOT_FOUND)
        },
    )
    .await;
}
