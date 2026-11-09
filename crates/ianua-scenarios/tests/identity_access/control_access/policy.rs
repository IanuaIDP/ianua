//! The tenant's access policy: Tess drafts it, shapes its rules and sends
//! it for review, and only someone else puts it live. A draft decides
//! nothing until then; simulation answers what any version would do, and
//! a request no rule matches is refused while the default says so.

use ianua_scenarios::api::{control_access, policies};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::control_access::{
    DefaultAction, DraftSource, RuleOrder, RuleRewrite, RuleSwitch, SimulatedRequest, Simulation,
};
use ianua_scenarios::wire::policies::{BlankDraft, NewRule};
use ianua_scenarios::world::World;
use serde_json::{Value, json};

use crate::support::{group, person};

/// The action a rule that lets a request through carries.
fn allow() -> Value {
    json!("Allow")
}

/// The action refusing a request for `reason`.
fn deny(reason: &str) -> Value {
    json!({ "Deny": { "reason": reason } })
}

/// A blank draft refusing whatever no rule matched.
fn blank_refusing() -> BlankDraft {
    BlankDraft {
        from: "blank".to_owned(),
        default_action: deny("Nobody is let through by default"),
    }
}

/// A rule named `name`, firing for members of `group`, at `priority`.
fn for_group(name: &str, group: &str, action: Value, priority: u16) -> NewRule {
    NewRule {
        name: name.to_owned(),
        conditions: vec![json!({ "GroupIs": group })],
        action,
        priority,
    }
}

/// Tess adds `rule` to the open draft.
async fn add(world: &World<'_>, rule: &NewRule) {
    policies::add_rule(world.tenant(), rule)
        .send(world.admin().client())
        .await
        .ok();
}

/// A made-up request of someone in `groups` against `version`.
fn simulated(version: &str, groups: &[&str]) -> SimulatedRequest {
    SimulatedRequest {
        version: version.to_owned(),
        path: Some("/account/settings".to_owned()),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        risk: "Low".to_owned(),
        current_aal: "Aal1".to_owned(),
    }
}

/// Tess runs a made-up request of someone in `groups` against `version`.
async fn simulate(world: &World<'_>, version: &str, groups: &[&str]) -> Simulation {
    control_access::simulate(world.tenant(), &simulated(version, groups))
        .send(world.admin().client())
        .await
        .ok()
}

/// Tess starts a blank draft refusing by default, with `rule`, submits it
/// and Ann activates it.
async fn activated(world: &World<'_>, rule: &NewRule) {
    policies::start_draft(world.tenant(), &blank_refusing())
        .send(world.admin().client())
        .await
        .ok();
    add(world, rule).await;
    policies::move_on(world.tenant(), "submit_for_review")
        .send(world.admin().client())
        .await
        .ok();
    policies::move_on(world.tenant(), "activate")
        .send(world.owner().client())
        .await
        .ok();
}

/// Max, Sam and nobody signed in touch nothing of the policy. Tess starts
/// a draft and, while nothing is live, reads it back and sees no live
/// version. She shapes it: adds a rule, refuses another of the same name,
/// renames a rule and moves it, switches one off, orders them, sets the
/// default to refuse and removes one. In review it freezes and she cannot
/// approve what she sent; Ann does, and the version answers as live,
/// the draft gone. Every step is on the record.
#[tokio::test]
async fn a_draft_goes_live_only_when_someone_else_approves_it() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let staff = group(&world, "Staff").await;
    let contractors = group(&world, "Contractors").await;

    for call in [
        policies::start_draft(world.tenant(), &blank_refusing()).call(),
        control_access::simulate(world.tenant(), &simulated("live", &[])).call(),
    ] {
        Matrix::new("touching the policy", call)
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
    policies::start_draft(world.tenant(), &blank_refusing())
        .send(tess)
        .await
        .ok();
    control_access::live_policy(world.tenant())
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    control_access::draft_policy(world.tenant())
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let editing = control_access::current_policy(world.tenant())
        .send(tess)
        .await
        .ok();
    assert_eq!(editing.status, "Draft");
    assert!(editing.editable, "a draft being written may be edited");
    assert_eq!(editing.based_on, "blank");

    add(&world, &for_group("allow-staff", &staff, allow(), 10)).await;
    add(
        &world,
        &for_group(
            "no-contractors",
            &contractors,
            deny("Contractors stay out"),
            5,
        ),
    )
    .await;
    policies::add_rule(
        world.tenant(),
        &for_group("no-contractors", &contractors, allow(), 7),
    )
    .send(tess)
    .await
    .refused(Status::CONFLICT, "conflict");

    let renamed = control_access::change_rule(
        world.tenant(),
        "no-contractors",
        &RuleRewrite {
            name: "contractors-stay-out".to_owned(),
            conditions: vec![json!({ "GroupIs": contractors })],
            action: deny("Contractors are not let in"),
            priority: 1,
        },
    )
    .send(tess)
    .await
    .ok();
    assert!(
        renamed
            .rules
            .iter()
            .any(|rule| rule.name == "contractors-stay-out" && rule.priority == 1)
    );
    let switched = control_access::switch_rule(
        world.tenant(),
        "contractors-stay-out",
        &RuleSwitch { enabled: false },
    )
    .send(tess)
    .await
    .ok();
    assert!(
        switched
            .rules
            .iter()
            .any(|rule| rule.name == "contractors-stay-out" && !rule.enabled),
        "a switched-off rule is kept"
    );
    let ordered = control_access::reorder_rules(
        world.tenant(),
        &RuleOrder {
            names: vec!["allow-staff".to_owned(), "contractors-stay-out".to_owned()],
        },
    )
    .send(tess)
    .await
    .ok();
    assert_eq!(ordered.rules[0].name, "allow-staff", "order changed");
    let default_changed = control_access::change_default_action(
        world.tenant(),
        &DefaultAction {
            default_action: deny("Refused by default"),
        },
    )
    .send(tess)
    .await
    .ok();
    assert_eq!(
        default_changed.default_action["Deny"]["reason"],
        json!("Refused by default"),
        "the fallback is the safe one"
    );
    let trimmed = control_access::remove_rule(world.tenant(), "contractors-stay-out")
        .send(tess)
        .await
        .ok();
    assert_eq!(trimmed.rules.len(), 1, "the rule is out of the draft");

    let in_review = policies::move_on(world.tenant(), "submit_for_review")
        .send(tess)
        .await
        .ok();
    assert_eq!(in_review.status, "Review");
    policies::add_rule(
        world.tenant(),
        &for_group("late-addition", &contractors, allow(), 3),
    )
    .send(tess)
    .await
    .refused(Status::CONFLICT, "conflict");
    policies::move_on(world.tenant(), "activate")
        .send(tess)
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let live = policies::move_on(world.tenant(), "activate")
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(live.status, "Active");

    let reading = control_access::live_policy(world.tenant())
        .send(tess)
        .await
        .ok();
    assert_eq!(reading.version, live.version, "the live version answers");
    control_access::draft_policy(world.tenant())
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    let versions = control_access::policy_versions(world.tenant())
        .send(tess)
        .await
        .ok();
    assert_eq!(versions.len(), 1, "one version so far");
    control_access::policy_version(world.tenant(), live.version + 1)
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    control_access::policy_version(world.tenant(), 0)
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    for event in [
        "authorization.policy_draft_started",
        "authorization.policy_rule_added",
        "authorization.policy_rule_changed",
        "authorization.policy_rule_switched",
        "authorization.policy_rules_reordered",
        "authorization.policy_default_action_changed",
        "authorization.policy_rule_removed",
        "authorization.policy_submitted_for_review",
        "authorization.policy_activated",
    ] {
        world.trail().recorded(event).await;
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess sends a draft for review and Ann sends it back: editing opens
/// again. Tess abandons it, and with no draft open abandoning again is
/// refused; the rejection and the abandonment are on the record.
#[tokio::test]
async fn a_rejected_draft_can_be_edited_or_abandoned_without_going_live() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    policies::start_draft(world.tenant(), &blank_refusing())
        .send(tess)
        .await
        .ok();
    policies::move_on(world.tenant(), "submit_for_review")
        .send(tess)
        .await
        .ok();

    let rejected = policies::move_on(world.tenant(), "reject")
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(rejected.status, "Draft", "rejected back to draft");
    let reopened = control_access::draft_policy(world.tenant())
        .send(tess)
        .await
        .ok();
    assert!(reopened.editable, "a rejected draft is editable again");

    policies::move_on(world.tenant(), "abandon_draft")
        .send(tess)
        .await
        .ok();
    control_access::draft_policy(world.tenant())
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    policies::move_on(world.tenant(), "abandon_draft")
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    world
        .trail()
        .recorded("authorization.policy_rejected")
        .await;
    world
        .trail()
        .recorded("authorization.policy_archived")
        .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// A policy refusing by default with one rule allowing Staff is live.
/// Asked what it would do, the live version lets someone in Staff through
/// by that rule and refuses someone else by the default, no rule having
/// matched. A next-version draft adds a rule for Finance: the live version
/// still refuses Finance while the draft lets it through. Activated, the
/// draft becomes the live version; the past one, restored as a new draft,
/// names the version it came from; the live version may not be restored
/// over itself while one is live, and a second draft may not open beside
/// the first. Taken out of use, the policy leaves nothing live to
/// simulate. Each simulation is on the record.
#[tokio::test]
async fn simulation_answers_what_each_version_would_do_and_nothing_matched_is_refused() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let staff = group(&world, "Staff").await;
    let finance = group(&world, "Finance").await;
    activated(&world, &for_group("allow-staff", &staff, allow(), 10)).await;

    let allowed = simulate(&world, "live", &[staff.as_str()]).await;
    assert_eq!(allowed.action, allow(), "Staff are let through");
    assert_eq!(allowed.matched_rule.as_deref(), Some("allow-staff"));
    assert!(
        allowed
            .evaluated_rules
            .iter()
            .any(|rule| rule.name == "allow-staff" && rule.matched),
        "the trace shows the rule that fired"
    );
    let unmatched = simulate(&world, "live", &[]).await;
    assert!(
        unmatched.action.get("Deny").is_some(),
        "a request no rule matched is refused by the default, not let through"
    );
    assert_eq!(unmatched.matched_rule, None, "the default decided");

    let draft = control_access::start_draft_from(
        world.tenant(),
        &DraftSource {
            from: "next_version".to_owned(),
            version: None,
        },
    )
    .send(tess)
    .await
    .ok();
    assert_eq!(
        control_access::draft_policy(world.tenant())
            .send(tess)
            .await
            .ok()
            .based_on_version,
        Some(allowed.policy_version),
        "the draft names the version it copied"
    );
    add(&world, &for_group("allow-finance", &finance, allow(), 20)).await;
    assert_eq!(
        simulate(&world, "draft", &[finance.as_str()]).await.action,
        allow(),
        "the draft would let Finance through"
    );
    assert!(
        simulate(&world, "live", &[finance.as_str()])
            .await
            .action
            .get("Deny")
            .is_some(),
        "the live version still refuses Finance"
    );
    policies::start_draft(world.tenant(), &blank_refusing())
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");
    policies::move_on(world.tenant(), "submit_for_review")
        .send(tess)
        .await
        .ok();
    policies::move_on(world.tenant(), "activate")
        .send(world.owner().client())
        .await
        .ok();
    assert_eq!(
        simulate(&world, "live", &[finance.as_str()])
            .await
            .policy_version,
        draft.version,
        "the new live version decides now"
    );

    let restored = control_access::start_draft_from(
        world.tenant(),
        &DraftSource {
            from: "restore".to_owned(),
            version: Some(allowed.policy_version),
        },
    )
    .send(tess)
    .await
    .ok();
    assert_eq!(
        control_access::policy_version(world.tenant(), restored.version)
            .send(tess)
            .await
            .ok()
            .based_on,
        "restore",
        "the new draft says where it came from"
    );
    policies::move_on(world.tenant(), "abandon_draft")
        .send(tess)
        .await
        .ok();
    control_access::start_draft_from(
        world.tenant(),
        &DraftSource {
            from: "restore".to_owned(),
            version: Some(draft.version),
        },
    )
    .send(tess)
    .await
    .refused(Status::CONFLICT, "conflict");

    policies::move_on(world.tenant(), "take_out_of_use")
        .send(world.owner().client())
        .await
        .ok();
    control_access::live_policy(world.tenant())
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    control_access::simulate(world.tenant(), &simulated("live", &[]))
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    assert!(
        world.trail().count("authorization.policy_simulated").await >= 3,
        "simulations are on the record"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Pat, an ordinary user of the tenant, may neither read nor shape the
/// policy, however it stands.
#[tokio::test]
async fn pat_reads_and_shapes_no_policy() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let staff = group(&world, "Staff").await;
    policies::start_draft(world.tenant(), &blank_refusing())
        .send(world.admin().client())
        .await
        .ok();

    for call in [
        control_access::current_policy(world.tenant()).call(),
        control_access::live_policy(world.tenant()).call(),
        control_access::draft_policy(world.tenant()).call(),
        control_access::policy_versions(world.tenant()).call(),
        policies::add_rule(world.tenant(), &for_group("let-me-in", &staff, allow(), 1)).call(),
        policies::move_on(world.tenant(), "submit_for_review").call(),
    ] {
        Matrix::new("Pat touching the policy", call)
            .refused(pat.client(), Status::FORBIDDEN, "forbidden")
            .run()
            .await;
    }
    stack.stop().await.expect("the stack stops cleanly");
}
