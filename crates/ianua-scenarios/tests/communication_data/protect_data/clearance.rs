//! What each app sees of the same record: Tess puts the records app behind
//! two routes, one redacting from Confidential up for a partner, one from
//! Restricted up for the clinic, and each answer holds only what its
//! clearance allows.

use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::classification::DataClass;
use ianua_scenarios::world::World;
use serde_json::Value;

use crate::support::{
    CARD, EMAIL, MASK, SSN, app_host, classified, patient_rules, probe, public_route, read,
    records_app, redacting, route,
};

/// Tess classifies Pat's record and puts the records app behind a partner
/// route redacting from Confidential up and a clinic route redacting from
/// Restricted up. Through the partner route nobody sees the number, the
/// diagnoses, the address or the card number, though equal card numbers
/// read equal; the note, only Internal, and the name come through. Through
/// the clinic route only the number and the diagnoses are hidden. The app
/// itself always sent the whole record.
#[tokio::test]
async fn each_route_shows_only_what_its_clearance_allows() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let host = app_host(&world).await;
    let rules = classified(&world, &patient_rules()).await;
    let rule_set = rules.id.expect("the first rule makes the rule set");
    let app = records_app(&["partner", "clinic"], Vec::new()).await;
    let partner = public_route("partner").with_stage(redacting(&rule_set, DataClass::Confidential));
    route(&world, &app, &host, partner).await;
    let clinic = public_route("clinic").with_stage(redacting(&rule_set, DataClass::Restricted));
    route(&world, &app, &host, clinic).await;
    let reader = probe(&stack);
    assert_partner(&reader, &host).await;
    let seen = read(&reader, &host, "/clinic/patient").await;
    assert_clinic(&seen);
    assert_eq!(
        app.asked_for("/partner/patient"),
        2,
        "the app was asked each time"
    );
    assert_eq!(app.asked_for("/clinic/patient"), 1);
    stack.stop().await.expect("the stack stops cleanly");
}

/// Partner answers hide classified fields and keep a stable card digest.
async fn assert_partner(reader: &Client, host: &str) {
    let seen = read(reader, host, "/partner/patient").await;
    assert_partner_fields(&seen);
    assert_visits(&seen);
    let digest = card_digest(&seen);
    assert_ne!(digest, CARD, "the card number is not sent as it is");
    assert!(!seen.to_string().contains(SSN) && !seen.to_string().contains(EMAIL));
    let again = read(reader, host, "/partner/patient").await;
    assert_eq!(
        card_digest(&again),
        digest,
        "the same card number reads the same digest, so records can still be matched"
    );
}

/// The partner sees unclassified and Internal fields but no clear identifiers.
fn assert_partner_fields(seen: &Value) {
    assert_eq!(
        seen["patient"]["name"], "Pat Doe",
        "an unclassified field comes through"
    );
    assert!(
        seen["patient"].get("ssn").is_none(),
        "a removed field is gone from the partner's answer: {seen}"
    );
    assert_eq!(
        seen["patient"]["email"], MASK,
        "the address is masked for the partner"
    );
    assert_eq!(
        seen["patient"]["notes"], "prefers morning appointments",
        "an Internal field is below the partner's Confidential threshold"
    );
}

/// Each visit keeps its date and masks its diagnosis.
fn assert_visits(seen: &Value) {
    for visit in seen["visits"].as_array().expect("the visits stay a list") {
        assert_eq!(
            visit["diagnosis"], MASK,
            "every visit's diagnosis is masked"
        );
        assert!(visit["date"].is_string(), "a visit's date comes through");
    }
}

/// Clinic answers hide Restricted fields while retaining the address and card.
fn assert_clinic(seen: &Value) {
    assert!(
        seen["patient"].get("ssn").is_none(),
        "the number is Restricted: removed"
    );
    assert_eq!(
        seen["visits"][0]["diagnosis"], MASK,
        "a diagnosis is Restricted: masked"
    );
    assert_eq!(
        seen["patient"]["email"], EMAIL,
        "the clinic sees the address"
    );
    assert_eq!(
        seen["card"]["number"], CARD,
        "the clinic sees the card number"
    );
}

/// The digest standing in for the card number in `answer`.
fn card_digest(answer: &Value) -> String {
    answer["card"]["number"]
        .as_str()
        .expect("a hashed field is replaced by text")
        .to_owned()
}
