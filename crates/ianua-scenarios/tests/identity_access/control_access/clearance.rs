//! Clearance rules: which app permissions clear their holders for
//! confidential or restricted data. Only someone cleared themselves
//! writes one, a rule clears for nothing below confidential, and Max and
//! Sam write none.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{control_access, roles};
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::control_access::{AppPermission, ClearanceLevel, NewClearanceRule};
use ianua_scenarios::wire::roles::AssignRole;
use ianua_scenarios::world::World;

use crate::support::{person, role_with};

/// The app permission Tess's rules clear for.
fn reading_invoices() -> AppPermission {
    AppPermission {
        resource: "invoices".to_owned(),
        action: "read".to_owned(),
    }
}

/// A rule clearing holders of reading invoices up to `up_to`.
fn clearing(up_to: &str) -> NewClearanceRule {
    NewClearanceRule {
        permission: reading_invoices(),
        up_to: up_to.to_owned(),
    }
}

/// Clara: a person who may change classification and is cleared for
/// confidential data, through a role Tess assigns her.
async fn clara(world: &World<'_>) -> Person {
    let clara = person(world, "clara").await;
    let role = role_with(
        world,
        "Classifiers",
        &[("Classification", "Update"), ("Data", "Confidential")],
    )
    .await;
    roles::assign(
        world.tenant(),
        &role,
        &AssignRole {
            user_id: clara.id().to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    clara
}

/// Tess, reading no rules yet, clears holders of reading invoices for
/// confidential data: the rule reads back, a second rule on the same
/// permission is refused, and so is one clearing for internal data, which
/// everyone has already. She raises it to restricted, then removes it, and
/// removing it again finds nothing. Max and Sam may read or change none,
/// and nobody signed in is refused. Every change is on the record.
#[tokio::test]
async fn tess_clears_for_confidential_data_and_can_change_or_remove_the_rule() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();

    let none = control_access::clearance_rules(world.tenant())
        .send(tess)
        .await
        .ok();
    assert!(none.rules.is_empty(), "no rules until one is written");
    for call in [
        control_access::add_clearance(world.tenant(), &clearing("Confidential")).call(),
        control_access::clearance_rules(world.tenant()).call(),
    ] {
        Matrix::new("touching clearance rules", call)
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

    let with_one = control_access::add_clearance(world.tenant(), &clearing("Confidential"))
        .send(tess)
        .await
        .ok();
    assert_eq!(with_one.rules.len(), 1);
    assert_eq!(with_one.rules[0].up_to, "Confidential");
    control_access::add_clearance(world.tenant(), &clearing("Confidential"))
        .send(tess)
        .await
        .refused(Status::CONFLICT, "conflict");
    control_access::add_clearance(world.tenant(), &clearing("Internal"))
        .send(tess)
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    let raised = control_access::change_clearance(
        world.tenant(),
        &reading_invoices(),
        &ClearanceLevel {
            up_to: "Restricted".to_owned(),
        },
    )
    .send(tess)
    .await
    .ok();
    assert_eq!(raised.rules[0].up_to, "Restricted");
    let removed = control_access::remove_clearance(world.tenant(), &reading_invoices())
        .send(tess)
        .await
        .ok();
    assert!(removed.rules.is_empty(), "the rule is gone");
    control_access::remove_clearance(world.tenant(), &reading_invoices())
        .send(tess)
        .await
        .refused(Status::NOT_FOUND, "not_found");
    for event in [
        "authorization.clearance_rule_added",
        "authorization.clearance_rule_changed",
        "authorization.clearance_rule_removed",
    ] {
        world.trail().recorded(event).await;
    }
    stack.stop().await.expect("the stack stops cleanly");
}

/// Clara may change classification but holds only confidential data
/// clearance. She clears a permission for confidential data, and is
/// refused raising it to restricted or adding one for restricted: nobody
/// clears others past their own clearance. Max may read none of it.
#[tokio::test]
async fn clara_clears_nothing_past_her_own_clearance() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let clara = clara(&world).await;

    control_access::add_clearance(world.tenant(), &clearing("Confidential"))
        .send(clara.client())
        .await
        .ok();
    let restricted = NewClearanceRule {
        permission: AppPermission {
            resource: "payroll".to_owned(),
            action: "read".to_owned(),
        },
        up_to: "Restricted".to_owned(),
    };
    control_access::add_clearance(world.tenant(), &restricted)
        .send(clara.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    control_access::change_clearance(
        world.tenant(),
        &reading_invoices(),
        &ClearanceLevel {
            up_to: "Restricted".to_owned(),
        },
    )
    .send(clara.client())
    .await
    .refused(Status::FORBIDDEN, "forbidden");
    let held = control_access::clearance_rules(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(
        held.rules[0].up_to, "Confidential",
        "the rule did not change"
    );
    assert_eq!(
        world
            .trail()
            .count("authorization.clearance_rule_changed")
            .await,
        0,
        "the refused raise is not recorded"
    );
    stack.stop().await.expect("the stack stops cleanly");
}
