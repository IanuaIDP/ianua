//! Changing the rules: a rule Tess raises or removes takes effect on the
//! next answer through the gateway, with the route left as it was, and the
//! change is on record with what it was before; nobody without the right
//! touches the rules, and a rule that could never work is refused.

use ianua_scenarios::api::classification;
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::net::Client;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::classification::{
    Classification, ClassificationChange, DataClass, NewClassificationRule, Redaction,
};
use ianua_scenarios::world::World;

use crate::support::{
    EMAIL, MASK, app_host, classified, patient_rules, probe, public_route, read, records_app,
    redacting, route,
};

/// The note on Pat's record as the app holds it.
const NOTE: &str = "prefers morning appointments";

/// Pat's note comes through the partner route, being only Internal. Tess
/// raises it to Confidential: soon after, the partner sees it masked, the
/// route untouched. She removes the rule on the address: the partner then
/// sees Pat's address. The trail holds both changes, the first with the
/// level and redaction before and after.
#[tokio::test]
async fn a_changed_rule_reaches_the_next_answer_and_a_removed_one_lets_the_field_through() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let host = app_host(&world).await;
    let rules = classified(&world, &patient_rules()).await;
    let rule_set = rules.id.clone().expect("the first rule makes the rule set");
    let app = records_app(&["partner"], Vec::new()).await;
    let partner = public_route("partner").with_stage(redacting(&rule_set, DataClass::Confidential));
    route(&world, &app, &host, partner).await;
    let reader = probe(&stack);
    let seen = read(&reader, &host, "/partner/patient").await;
    assert_eq!(
        seen["patient"]["notes"], NOTE,
        "the note starts below the threshold"
    );
    let note_rule = rule_for(&rules, "patient.notes");
    let email_rule = rule_for(&rules, "patient.email");
    raise_note(&world, &reader, &host, &note_rule).await;
    remove_email_rule(&world, &reader, &host, &email_rule).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Raising the note's classification masks it on the next answer and records both levels.
async fn raise_note(world: &World<'_>, reader: &Client, host: &str, note_rule: &str) {
    let raised = ClassificationChange {
        level: DataClass::Confidential,
        redaction: Redaction::Mask,
    };
    classification::change(world.tenant(), note_rule, &raised)
        .send(world.admin().client())
        .await
        .ok();
    eventually("the raised note to be masked", || async {
        let seen = read(reader, host, "/partner/patient").await;
        (seen["patient"]["notes"] == MASK).then_some(())
    })
    .await;
    let changed = world
        .trail()
        .recorded("proxy.classification_rule_changed")
        .await;
    assert_eq!(changed.details["field_path"], "patient.notes");
    assert_eq!(changed.details["level"]["change"]["from"], "internal");
    assert_eq!(changed.details["level"]["change"]["to"], "confidential");
}

/// Removing the address rule exposes it while other redaction and its audit record remain.
async fn remove_email_rule(world: &World<'_>, reader: &Client, host: &str, email_rule: &str) {
    classification::remove(world.tenant(), email_rule)
        .send(world.admin().client())
        .await
        .ok();
    eventually("the unclassified address to come through", || async {
        let seen = read(reader, host, "/partner/patient").await;
        (seen["patient"]["email"] == EMAIL).then_some(())
    })
    .await;
    world
        .trail()
        .recorded("proxy.classification_rule_removed")
        .await;
    let seen = read(reader, host, "/partner/patient").await;
    assert!(
        seen["patient"].get("ssn").is_none(),
        "the other rules still hold after one is removed"
    );
}

/// Max, a plain member, cannot declassify the number; Sam tries
/// it from his own company; nobody signed in tries it. Each is refused.
/// Tess's own mistakes are refused too: a second rule for a field already
/// classified, a rule asking for encryption nothing performs, and a path
/// that is no field. No rule is added, and the number remains Restricted
/// with removal as its redaction.
#[tokio::test]
async fn only_someone_who_may_classify_changes_the_rules_and_a_broken_rule_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let before = classified(&world, &patient_rules()).await;
    let ssn_rule = rule_for(&before, "patient.ssn");
    refuse_unauthorized_changes(&world, &ssn_rule).await;
    refuse_broken_rules(&world).await;
    assert_unchanged_rules(&world, &before, &ssn_rule).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Members, strangers and anonymous callers cannot declassify the number.
async fn refuse_unauthorized_changes(world: &World<'_>, ssn_rule: &str) {
    let lowered = ClassificationChange {
        level: DataClass::Public,
        redaction: Redaction::Mask,
    };

    Matrix::new(
        "lowering the number to Public",
        classification::change(world.tenant(), ssn_rule, &lowered).call(),
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
    Matrix::new(
        "removing the rule on the number",
        classification::remove(world.tenant(), ssn_rule).call(),
    )
    .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
    .run()
    .await;
}

/// Duplicate fields, unsupported encryption and malformed paths are refused.
async fn refuse_broken_rules(world: &World<'_>) {
    let second = rule("patient.ssn", Redaction::Mask);
    classification::add(world.tenant(), &second)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    for broken in [
        rule("patient.phone", Redaction::Encrypt),
        rule("patient..ssn", Redaction::Mask),
    ] {
        classification::add(world.tenant(), &broken)
            .send(world.admin().client())
            .await
            .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    }
}

/// Refused changes leave the original rule count and Restricted removal intact.
async fn assert_unchanged_rules(world: &World<'_>, before: &Classification, ssn_rule: &str) {
    let after = classification::get(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(after.rules.len(), before.rules.len(), "no rule was added");
    let ssn = after
        .rules
        .iter()
        .find(|rule| rule.id == ssn_rule)
        .expect("the rule on the number is still there");
    assert_eq!(
        ssn.level,
        DataClass::Restricted,
        "the number is still Restricted"
    );
    assert_eq!(
        ssn.redaction,
        Redaction::Remove,
        "the number is still removed"
    );
}

/// The id of the rule on `field_path` in `rules`.
fn rule_for(rules: &Classification, field_path: &str) -> String {
    rules
        .rules
        .iter()
        .find(|rule| rule.field_path == field_path)
        .map(|rule| rule.id.clone())
        .expect("the rule was added")
}

/// A Confidential rule on `field_path`, redacted as `redaction`.
fn rule(field_path: &str, redaction: Redaction) -> NewClassificationRule {
    NewClassificationRule {
        field_path: field_path.to_owned(),
        level: DataClass::Confidential,
        redaction,
    }
}
