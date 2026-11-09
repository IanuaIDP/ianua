//! A tenant's policy at the gateway: Tess writes a rule refusing a group,
//! Ann makes it live, and from then on it holds on every route, whatever
//! the route itself lets through. The gateway's record of each refusal
//! names the rule and the version of the policy that decided.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::policies;
use ianua_scenarios::expect::{Matrix, Records, eventually};
use ianua_scenarios::net::Call;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::policies::{BlankDraft, NewGroup, NewGroupMember, NewRule};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::json;

use crate::support::{Shop, ShopOwner, customer, profile, signed_in_at, word};

/// The rule's name, as the gateway's records name it.
const RULE: &str = "no-contractors";

/// Tess puts Quinn, a contractor, in the contractors group, and writes a
/// policy refusing that group; Ann makes it live. From then on Quinn,
/// signed in at the shop, is forbidden its account pages and the shop
/// sees nothing of him, while Pat still gets in. The gateway records
/// Quinn's request as refused by the policy, under the rule and the live
/// version, and Pat's as allowed under the same version; the trail holds
/// the policy's activation.
#[tokio::test]
async fn a_policy_refusing_a_group_holds_at_the_gateway() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let shop = Shop::opened(
        &stack,
        &ShopOwner {
            tenant: world.tenant(),
            admin: world.admin().client(),
            word: &word(),
        },
    )
    .await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    let quinn = customer(&world, "quinn", "Quinn Contractor").await;
    signed_in_at(&shop, &pat).await;
    signed_in_at(&shop, &quinn).await;
    let group = add_contractor(&world, &quinn).await;
    let version = activate_policy(&world, &group).await;
    assert_policy_access(&shop, &pat, &quinn).await;
    let records = Records::of_tenant(world.admin().client(), world.tenant());
    assert_quinn_record(&records, &quinn, version).await;
    assert_pat_record(&records, &pat, version).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess adds Quinn to the Contractors group named by the policy rule.
async fn add_contractor(world: &World<'_>, quinn: &Person) -> String {
    let tess = world.admin().client();

    let group = policies::create_group(
        world.tenant(),
        &NewGroup {
            name: "Contractors".to_owned(),
        },
    )
    .send(tess)
    .await
    .ok();
    policies::add_member(
        world.tenant(),
        &group.id,
        &NewGroupMember {
            kind: "user".to_owned(),
            id: quinn.id().to_owned(),
        },
    )
    .send(tess)
    .await
    .ok();
    group.id
}

/// Tess drafts the rule denying requests from members of Contractors.
async fn draft_policy(world: &World<'_>, group: &str) {
    let tess = world.admin().client();
    let blank = BlankDraft {
        from: "blank".to_owned(),
        default_action: json!("Allow"),
    };
    policies::start_draft(world.tenant(), &blank)
        .send(tess)
        .await
        .ok();
    let rule = NewRule {
        name: RULE.to_owned(),
        conditions: vec![json!({ "GroupIs": group })],
        action: json!({ "Deny": { "reason": "Contractors are not let in" } }),
        priority: 10,
    };
    policies::add_rule(world.tenant(), &rule)
        .send(tess)
        .await
        .ok();
}

/// Tess submits the rule and Ann activates it, leaving the activation record.
async fn activate_policy(world: &World<'_>, group: &str) -> u32 {
    draft_policy(world, group).await;
    policies::move_on(world.tenant(), "submit_for_review")
        .send(world.admin().client())
        .await
        .ok();
    let live = policies::move_on(world.tenant(), "activate")
        .send(world.owner().client())
        .await
        .ok();
    world
        .trail()
        .recorded("authorization.policy_activated")
        .await;
    live.version
}

/// The gateway refuses Quinn after propagation and still forwards Pat's request.
async fn assert_policy_access(shop: &Shop, pat: &Person, quinn: &Person) {
    let account = shop.page("/account/settings");
    eventually("the gateway to hold Quinn to the policy", || async {
        let answer = quinn
            .client()
            .send::<IgnoredAny>(Call::get(account.as_str()))
            .await;
        (answer.status() == Status::FORBIDDEN).then_some(())
    })
    .await;
    shop.app.forget();
    Matrix::new("reading an account page", Call::get(account.as_str()))
        .allowed(pat.client())
        .refused(quinn.client(), Status::FORBIDDEN, "forbidden")
        .run()
        .await;
    let arrived = shop.app.arrivals();
    assert_eq!(arrived.len(), 1, "only Pat reached the shop: {arrived:?}");
}

/// Quinn's recorded refusal names the rejecting rule and active policy version.
async fn assert_quinn_record(records: &Records<'_>, quinn: &Person, version: u32) {
    let refused = records
        .recorded_where("/account/settings", "Quinn's refused", |record| {
            record.subject.id.as_deref() == Some(quinn.id()) && record.decision == "refused"
        })
        .await;
    assert_eq!(
        refused.status,
        Status::FORBIDDEN,
        "Quinn's record carries the refusal"
    );
    assert_eq!(
        refused.rule.as_deref(),
        Some(RULE),
        "Quinn's record names the rule that refused him"
    );
    assert_eq!(
        refused.policy_version,
        Some(version),
        "Quinn's record names the live policy version"
    );
}

/// Pat's allowed request is recorded under the same active policy version.
async fn assert_pat_record(records: &Records<'_>, pat: &Person, version: u32) {
    let allowed = records
        .recorded_where("/account/settings", "Pat's", |record| {
            record.subject.id.as_deref() == Some(pat.id())
        })
        .await;
    assert_eq!(allowed.decision, "allowed", "Pat is let in");
    assert_eq!(
        allowed.policy_version,
        Some(version),
        "Pat's record names the same live policy version"
    );
}
