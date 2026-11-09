//! A tenant policy refusing by default: only people in the Staff group and
//! people holding the Auditors role get through, whatever the route lets
//! in, and the gateway follows the group as Tess changes who is in it.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{policies, roles};
use ianua_scenarios::expect::{Matrix, Records, eventually};
use ianua_scenarios::net::{Call, Client};
use ianua_scenarios::routes::RouteSpec;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::policies::{BlankDraft, NewGroup, NewGroupMember, NewRule};
use ianua_scenarios::wire::roles::{AssignRole, NewAppRole};
use ianua_scenarios::wire::routing::{CustomPermission, RoutePolicy};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;
use serde_json::{Value, json};

use crate::support::{HostedApp, app_host, customer, declared_permission, profile, signed_in_on};

/// The path every step reads.
const STOCK_PAGE: &str = "/stock/levels";

/// Who the policy lets in: the group and the role, by their ids.
struct AllowedIn {
    group: String,
    role: String,
}

/// Tess makes a Staff group with Pat in it and an Auditors role held by
/// Rob, then writes a policy refusing by default and allowing those two;
/// Ann makes it live. Pat and Rob read the stock levels. Quinn, signed in
/// just as they are, is forbidden, the app seeing nothing of him, and the
/// gateway records his refusal under the live version with no rule named,
/// since the default refused him. Tess takes Pat out of Staff and she is
/// forbidden on her next request while Rob goes on; Tess puts Quinn in and
/// he gets through.
#[tokio::test]
async fn a_policy_refusing_by_default_lets_in_only_its_group_and_role() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = Echo::start(&stack, &app_host(&world).await)
        .await
        .expect("the stock app starts");
    let spec = RouteSpec::public("stock", "/stock/*").asking(RoutePolicy::Authenticated);
    let app = HostedApp::opened(&world, "stock", spec, &echo.url()).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    let rob = customer(&world, "rob", "Rob Auditor").await;
    let quinn = customer(&world, "quinn", "Quinn Contractor").await;
    for person in [&pat, &rob, &quinn] {
        signed_in_on(&app.host, person).await;
    }
    let allowed = staff_and_auditors(&world, &pat, &rob).await;
    let version = activate_allow_list(&world, &allowed).await;
    let page = app.page(STOCK_PAGE);
    refused_once_live(quinn.client(), &page).await;

    echo.forget();
    Matrix::new("reading the stock levels", Call::get(page.as_str()))
        .allowed(pat.client())
        .allowed(rob.client())
        .refused(quinn.client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .run()
        .await;
    assert_eq!(echo.arrivals().len(), 2, "only Pat and Rob reached the app");
    assert_default_refused_quinn(&world, &quinn, version).await;

    policies::remove_member(world.tenant(), &allowed.group, "user", pat.id())
        .send(world.admin().client())
        .await
        .ok();
    refused_once_live(pat.client(), &page).await;
    rob.client()
        .send::<IgnoredAny>(Call::get(page.as_str()))
        .await
        .ok();
    add_to_group(&world, &allowed.group, &quinn).await;
    eventually("Quinn to be let in with the group", || async {
        let answer = quinn
            .client()
            .send::<IgnoredAny>(Call::get(page.as_str()))
            .await;
        (answer.status() == Status::OK).then_some(())
    })
    .await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// Waits until `client` is forbidden `page`, the policy having reached the
/// gateway.
async fn refused_once_live(client: &Client, page: &str) {
    eventually("the gateway to forbid the page", || async {
        let answer = client.send::<IgnoredAny>(Call::get(page)).await;
        (answer.status() == Status::FORBIDDEN).then_some(())
    })
    .await;
}

/// Tess makes the Staff group holding Pat and the Auditors role held by Rob.
async fn staff_and_auditors(world: &World<'_>, pat: &Person, rob: &Person) -> AllowedIn {
    let tess = world.admin().client();
    declared_permission(world, "stock", "audit").await;
    let group = policies::create_group(
        world.tenant(),
        &NewGroup {
            name: "Staff".to_owned(),
        },
    )
    .send(tess)
    .await
    .ok()
    .id;
    add_to_group(world, &group, pat).await;
    let role = roles::create_for_app(
        world.tenant(),
        &NewAppRole {
            name: "Auditors".to_owned(),
            custom_permissions: vec![CustomPermission {
                resource: "stock".to_owned(),
                action: "audit".to_owned(),
            }],
        },
    )
    .send(tess)
    .await
    .ok()
    .id;
    roles::assign(
        world.tenant(),
        &role,
        &AssignRole {
            user_id: rob.id().to_owned(),
        },
    )
    .send(tess)
    .await
    .ok();
    AllowedIn { group, role }
}

/// Tess puts `person` in the group.
async fn add_to_group(world: &World<'_>, group: &str, person: &Person) {
    policies::add_member(
        world.tenant(),
        group,
        &NewGroupMember {
            kind: "user".to_owned(),
            id: person.id().to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
}

/// A rule named `name` allowing whoever meets `condition`.
fn allowing(name: &str, condition: Value, priority: u16) -> NewRule {
    NewRule {
        name: name.to_owned(),
        conditions: vec![condition],
        action: json!("Allow"),
        priority,
    }
}

/// Tess drafts the policy and Ann makes it live, answering its version.
async fn activate_allow_list(world: &World<'_>, allowed: &AllowedIn) -> u32 {
    let tess = world.admin().client();
    let blank = BlankDraft {
        from: "blank".to_owned(),
        default_action: json!({ "Deny": { "reason": "Only staff and auditors get in" } }),
    };
    policies::start_draft(world.tenant(), &blank)
        .send(tess)
        .await
        .ok();
    for rule in [
        allowing("staff-in", json!({ "GroupIs": allowed.group }), 10),
        allowing("auditors-in", json!({ "RoleIs": allowed.role }), 20),
    ] {
        policies::add_rule(world.tenant(), &rule)
            .send(tess)
            .await
            .ok();
    }
    policies::move_on(world.tenant(), "submit_for_review")
        .send(tess)
        .await
        .ok();
    policies::move_on(world.tenant(), "activate")
        .send(world.owner().client())
        .await
        .ok()
        .version
}

/// Quinn's refusal is recorded under the live version, the default having
/// refused him, so no rule is named.
async fn assert_default_refused_quinn(world: &World<'_>, quinn: &Person, version: u32) {
    let refused = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where(STOCK_PAGE, "Quinn's refused", |record| {
            record.subject.id.as_deref() == Some(quinn.id()) && record.decision == "refused"
        })
        .await;
    assert_eq!(refused.status, Status::FORBIDDEN, "Quinn was forbidden");
    assert_eq!(
        refused.reason.as_deref(),
        Some("tenant_rule"),
        "the tenant's policy refused him"
    );
    assert_eq!(refused.rule, None, "the default refused him, not a rule");
    assert_eq!(
        refused.policy_version,
        Some(version),
        "the record names the live version"
    );
}
