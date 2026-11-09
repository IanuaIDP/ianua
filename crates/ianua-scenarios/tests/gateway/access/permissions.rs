//! A route asking a permission of the tenant's own: only someone holding
//! it through a role gets through, the app reads the permission in the
//! gateway's signed assertion, and taking the role back stops the holder
//! on their next request.

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::roles;
use ianua_scenarios::expect::{Matrix, Records, eventually};
use ianua_scenarios::net::Call;
use ianua_scenarios::routes::RouteSpec;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::upstreams::Echo;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::roles::{AssignRole, NewAppRole};
use ianua_scenarios::wire::routing::{CustomPermission, RoutePolicy};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use crate::support::{
    HostedApp, app_host, customer, declared_permission, last_caller, profile, signed_in_on,
};

/// What the reports route asks for.
fn reading_reports() -> CustomPermission {
    CustomPermission {
        resource: "reports".to_owned(),
        action: "read".to_owned(),
    }
}

/// Tess declares `reports:read` in the tenant's catalogue, makes a role
/// granting it, gives it to Pat alone, and asks that permission on the
/// reports route. Pat gets through and the app
/// reads her role and permission in the gateway's assertion. Quinn, who
/// signed in just as Pat did, is forbidden and nobody signed in is told to
/// sign in, the app seeing neither; the gateway records Quinn's refusal as
/// the permission missing. Tess takes the role back and Pat is forbidden
/// on her next request, the app seeing nothing more of her.
#[tokio::test]
async fn a_route_asking_a_permission_lets_in_only_who_holds_it() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let echo = Echo::start(&stack, &app_host(&world).await)
        .await
        .expect("the reports app starts");
    declared_permission(&world, "reports", "read").await;
    let spec = RouteSpec::public("reports", "/reports/*").asking(
        RoutePolicy::RequireCustomPermission(vec![reading_reports()]),
    );
    let app = HostedApp::opened(&world, "reports", spec, &echo.url()).await;
    let pat = customer(&world, "pat", "Pat Customer").await;
    let quinn = customer(&world, "quinn", "Quinn Contractor").await;
    let role = report_readers(&world, &pat).await;
    signed_in_on(&app.host, &pat).await;
    signed_in_on(&app.host, &quinn).await;
    echo.forget();

    let page = app.page("/reports/q3");
    Matrix::new("reading the report", Call::get(page.as_str()))
        .allowed(pat.client())
        .refused(quinn.client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .run()
        .await;
    assert_eq!(echo.arrivals().len(), 1, "only Pat reached the app");
    let caller = last_caller(&echo);
    assert_eq!(caller.sub, pat.id(), "the assertion names Pat");
    assert!(
        caller.roles.iter().any(|role| role == READERS),
        "the assertion names the role Pat holds: {:?}",
        caller.roles
    );
    assert!(
        caller.permissions.iter().any(|held| held == "reports:read"),
        "the assertion carries the permission Pat holds: {:?}",
        caller.permissions
    );
    assert_quinn_refused(&world, &quinn).await;

    roles::unassign(world.tenant(), &role, pat.id())
        .send(world.admin().client())
        .await
        .ok();
    assert_pat_stopped(&echo, &pat, &page).await;
    stack.stop().await.expect("the stack stops cleanly");
}

/// The role granting `reports:read`, as the assertion names it.
const READERS: &str = "Report readers";

/// Tess makes the role granting `reports:read` and gives it to Pat.
async fn report_readers(world: &World<'_>, pat: &Person) -> String {
    let role = roles::create_for_app(
        world.tenant(),
        &NewAppRole {
            name: READERS.to_owned(),
            custom_permissions: vec![reading_reports()],
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    roles::assign(
        world.tenant(),
        &role.id,
        &AssignRole {
            user_id: pat.id().to_owned(),
        },
    )
    .send(world.admin().client())
    .await
    .ok();
    role.id
}

/// The gateway's record of Quinn's request says the policy stage refused
/// it for the permission he does not hold.
async fn assert_quinn_refused(world: &World<'_>, quinn: &Person) {
    let refused = Records::of_tenant(world.admin().client(), world.tenant())
        .recorded_where("/reports/q3", "Quinn's refused", |record| {
            record.subject.id.as_deref() == Some(quinn.id()) && record.decision == "refused"
        })
        .await;
    assert_eq!(refused.status, Status::FORBIDDEN, "Quinn was forbidden");
    assert_eq!(
        refused.reason.as_deref(),
        Some("permission_missing"),
        "the record says the permission was missing"
    );
    let decided_by = refused.decided_by.expect("the record says what refused");
    assert_eq!(decided_by.kind, "stage", "a stage refused him");
    assert_eq!(decided_by.name, "policy", "the policy stage refused him");
}

/// Once her role is gone Pat is forbidden, and the app sees nothing more.
async fn assert_pat_stopped(echo: &Echo, pat: &Person, page: &str) {
    eventually("Pat to lose the report", || async {
        let answer = pat.client().send::<IgnoredAny>(Call::get(page)).await;
        (answer.status() == Status::FORBIDDEN).then_some(())
    })
    .await;
    echo.forget();
    pat.client()
        .send::<IgnoredAny>(Call::get(page))
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    assert!(
        echo.arrivals().is_empty(),
        "nothing of Pat reached the app after her role went"
    );
}
