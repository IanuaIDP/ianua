//! Tess brings a domain of the company's own: it is not proved until its
//! DNS record is published, then serves an app on the certificate the
//! tenant uploaded. Max, Sam and nobody signed in cannot remove it, and
//! Sam cannot reach it from his own tenant.

use ianua_scenarios::api::domains;
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::routes::{Placement, RouteSpec, visit};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::domains::{Domain, NewDomain, UploadCertificate};
use ianua_scenarios::world::World;

/// Tess registers a domain: verifying it before its record is published
/// proves nothing. She publishes the exact record the platform asked for,
/// and the domain is verified. She uploads a certificate for the name,
/// publishes an app on it, and a visitor reaches the upstream over that
/// name, once.
#[tokio::test]
async fn a_domain_is_proved_by_its_record_and_serves_an_app_on_its_certificate() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let name = format!("external-app.{}", stack.customer_domain());

    let added = register_unproved_domain(&world, &name).await;
    prove_domain(&world, &added).await;
    upload_certificate(&world, &added, &name).await;
    let _app = visit_domain_app(&world, &name).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Registration and an early verification leave the domain waiting for its DNS proof.
async fn register_unproved_domain(world: &World<'_>, name: &str) -> Domain {
    let added = domains::add(
        world.tenant(),
        &NewDomain {
            domain: name.to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    assert_eq!(
        added.verification_status, "Pending",
        "a new domain waits for its proof"
    );
    let unproved = domains::verify(world.tenant(), &added.id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        unproved.status, "Pending",
        "with no record published the domain is still waiting for its proof"
    );
    added
}

/// Publishing the requested TXT record lets verification finish.
async fn prove_domain(world: &World<'_>, added: &Domain) {
    let stack = world.stack();
    stack.name_server().write_txt(
        added.dns_record_name.as_deref().expect("the proving name"),
        added
            .dns_record_value
            .as_deref()
            .expect("the proving value"),
    );
    eventually("the domain's DNS proof", || async {
        let verified = domains::verify(world.tenant(), &added.id)
            .send(world.admin().client())
            .await
            .ok();
        (verified.status == "Verified").then_some(())
    })
    .await;
}

/// The uploaded certificate covers the domain the tenant proved.
async fn upload_certificate(world: &World<'_>, added: &Domain, name: &str) {
    let issued = world.stack().certificate_for(&[name.to_owned()]);
    let certificate = UploadCertificate {
        certificate_pem: issued.chain_pem().to_owned(),
        private_key_pem: issued.key_pem().to_owned(),
    };
    let served = domains::upload_certificate(world.tenant(), &added.id, &certificate)
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        served.subject_names.iter().any(|subject| subject == name),
        "the certificate covers the domain"
    );
}

/// A public route on the proved domain delivers exactly one visit to its upstream.
async fn visit_domain_app(world: &World<'_>, name: &str) -> Echo {
    let app = Echo::start(world.stack(), name)
        .await
        .expect("the domain's app starts");
    RouteSpec::public("domain-app", "/domain/*")
        .on_hosts(&[name.to_owned()])
        .applied(
            world.admin().client(),
            world.anonymous().client(),
            Placement {
                tenant: world.tenant(),
                upstream: &app.url(),
                host: name,
            },
        )
        .await;
    app.forget();
    let arrival = visit(name, "/domain/proved")
        .send(world.anonymous().client())
        .await
        .ok();
    assert_eq!(
        arrival.path, "/domain/proved",
        "the visit reaches the app over the proved name"
    );
    assert_eq!(app.arrivals().len(), 1, "the app saw the one visit");
    app
}

/// Max, Sam and an anonymous visitor cannot remove the domain Tess registered.
/// Sam cannot verify it from his own tenant either. Tess still
/// reads it, removes it herself, and then it is gone.
#[tokio::test]
async fn only_the_tenants_administrator_removes_its_domain() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let added = domains::add(
        world.tenant(),
        &NewDomain {
            domain: format!("owned.{}", stack.customer_domain()),
        },
    )
    .send(world.admin().client())
    .await
    .ok();

    refuse_other_domain_owners(&world, &added).await;
    remove_owned_domain(&world, &added).await;

    stack.stop().await.expect("the stack stops cleanly");
}

/// Other actors cannot remove the domain or verify it through another tenant.
async fn refuse_other_domain_owners(world: &World<'_>, added: &Domain) {
    Matrix::new(
        "removing the domain",
        domains::remove(world.tenant(), &added.id).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    domains::verify(world.twin(), &added.id)
        .send(world.stranger().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}

/// Tess still reads the domain after the refusals and can remove it herself.
async fn remove_owned_domain(world: &World<'_>, added: &Domain) {
    let kept = domains::get(world.tenant(), &added.id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(kept.id, added.id, "Tess still reads her domain");
    domains::remove(world.tenant(), &added.id)
        .send(world.admin().client())
        .await
        .ok();
    domains::get(world.tenant(), &added.id)
        .send(world.admin().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
}
