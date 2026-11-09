//! A digest standing in for a field lets one company match its own records
//! and nothing beyond: the same card number reads alike within a tenant
//! and differently at any other.

use ianua_scenarios::api::{classification, routing};
use ianua_scenarios::routes::Placement;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::classification::DataClass;
use ianua_scenarios::world::World;

use crate::support::{
    CARD, app_host, classified, patient_rules, probe, public_route, read, records_app, redacting,
    route,
};

/// Tess and Sam each classify the same records and each put the same app
/// behind a partner route that hashes the card number. Through Tess's
/// route the number reads as one digest however often it is read. Through
/// Sam's the same number reads as another, so nobody holding answers from
/// both companies can tell they are about the same card.
#[tokio::test]
async fn the_same_card_number_reads_differently_at_another_company() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let host = app_host(&world).await;
    let rule_set = classified(&world, &patient_rules())
        .await
        .id
        .expect("the first rule makes the rule set");
    let app = records_app(&["partner"], Vec::new()).await;
    let partner = public_route("partner").with_stage(redacting(&rule_set, DataClass::Confidential));
    route(&world, &app, &host, partner).await;

    let sam = world.stranger().client();
    for rule in &patient_rules() {
        classification::add(world.twin(), rule).send(sam).await.ok();
    }
    let their_set = classification::get(world.twin())
        .send(sam)
        .await
        .ok()
        .id
        .expect("Sam's first rule makes his rule set");
    let names = routing::hostnames(world.twin()).send(sam).await.ok();
    let their_host = names.slug_subdomain.unwrap_or(names.uuid_subdomain);
    public_route("partner")
        .with_stage(redacting(&their_set, DataClass::Confidential))
        .applied(
            sam,
            &probe(&stack),
            Placement {
                tenant: world.twin(),
                upstream: &app.url(),
                host: &their_host,
            },
        )
        .await;

    let reader = probe(&stack);
    let first = read(&reader, &host, "/partner/patient").await;
    let again = read(&reader, &host, "/partner/patient").await;
    let theirs = read(&reader, &their_host, "/partner/patient").await;
    let digest = &first["card"]["number"];
    assert_ne!(digest, CARD, "the card number is hidden");
    assert_eq!(
        digest, &again["card"]["number"],
        "one digest within a tenant"
    );
    assert_ne!(
        digest, &theirs["card"]["number"],
        "another company's digest of the same number differs"
    );

    stack.stop().await.expect("the stack stops cleanly");
}
