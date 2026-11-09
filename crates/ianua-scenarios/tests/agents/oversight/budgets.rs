//! The request budget Ann's grant sets an agent: so many requests to the
//! tenant's apps in a window, counted at the gateway across the fleet.
//! Past it the agent is told to wait for as long as the window has left,
//! and the app sees nothing more; a second grant is no second budget; an
//! agent granted none is not counted at all.

use ianua_scenarios::agent::external::IssuedToken;
use ianua_scenarios::api::agents::delegation;
use ianua_scenarios::stack::Stack;
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::agents::authority::{Budget, Capabilities, Grant};
use ianua_scenarios::world::World;
use serde::de::IgnoredAny;

use super::{App, VIEW_USERS, bound_grant, granted_agent, proven_get, reports_app};
use crate::support::profile;

/// The requests Ann's grant lets Reporter make in a window.
const MOST: u32 = 3;

/// That window, in seconds: an hour, so it does not reset during the
/// scenario.
const WINDOW: u32 = 3600;

/// How many requests the agent with no budget sends: twice what the
/// budget would allow.
const UNCOUNTED: usize = 6;

/// Reading reports on `app`, at most [`MOST`] requests an hour.
fn budgeted(app: &App, name: &str) -> Grant {
    let mut grant = bound_grant(app.service_id(), name, Capabilities::http(&[VIEW_USERS]));
    grant.limits.budget = Some(Budget::of(MOST, WINDOW));
    grant
}

/// Reporter's grant lets it make three requests an hour. All three read
/// the report; the fourth is refused, saying the limit and how long until
/// it may try again, and never reaches the app. The listing Ann reads
/// shows the budget spent. Ann grants Reporter a second, fresh budget of
/// its own: Reporter is still refused, since every grant it holds counts
/// against the same agent.
#[tokio::test]
async fn an_agent_past_its_budget_waits_and_a_second_grant_does_not_reset_it() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let mut reporter =
        granted_agent(&stack, &world, "Reporter", &budgeted(&app, "Read reports")).await;
    let url = app.url("/reports/weekly");

    for _ in 0..MOST {
        reporter
            .client()
            .send::<IgnoredAny>(proven_get(&reporter, &url))
            .await
            .ok();
    }
    let over = reporter
        .client()
        .send::<IgnoredAny>(proven_get(&reporter, &url))
        .await;
    assert_eq!(
        over.header("ratelimit-limit"),
        Some(MOST.to_string().as_str())
    );
    assert_eq!(
        over.header("retry-after"),
        Some(WINDOW.to_string().as_str())
    );
    over.refused(Status::TOO_MANY_REQUESTS, "too_many_requests");
    assert_eq!(
        app.echo.arrivals().len(),
        usize::try_from(MOST).expect("a small number"),
        "the request past the budget never reached the app"
    );
    let held = delegation::list(world.tenant(), reporter.id())
        .send(world.owner().client())
        .await
        .ok();
    let used = held
        .iter()
        .find_map(|delegation| delegation.budget.and_then(|budget| budget.used_requests));
    assert!(
        used.is_some_and(|used| used >= MOST),
        "Ann reads the budget spent: {held:?}"
    );

    let fresh = delegation::grant(world.tenant(), reporter.id(), &budgeted(&app, "Read again"))
        .send(world.owner().client())
        .await
        .ok();
    reporter.hold(IssuedToken::of(fresh));
    reporter
        .client()
        .send::<IgnoredAny>(proven_get(&reporter, &url))
        .await
        .refused(Status::TOO_MANY_REQUESTS, "too_many_requests");
    stack.stop().await.expect("the stack stops cleanly");
}

/// Helper's grant sets no budget, so the gateway counts none of its
/// requests: twice what Reporter's budget allows all read the report.
#[tokio::test]
async fn an_agent_granted_no_budget_is_not_counted() {
    let stack = Stack::start(profile()).await.expect("the stack starts");
    let world = World::new(&stack).await;
    let app = reports_app(&stack, &world).await;
    let unmetered = bound_grant(
        app.service_id(),
        "Read reports",
        Capabilities::http(&[VIEW_USERS]),
    );
    let helper = granted_agent(&stack, &world, "Helper", &unmetered).await;
    let url = app.url("/reports/daily");

    for _ in 0..UNCOUNTED {
        helper
            .client()
            .send::<IgnoredAny>(proven_get(&helper, &url))
            .await
            .ok();
    }
    assert_eq!(app.echo.arrivals().len(), UNCOUNTED);
    stack.stop().await.expect("the stack stops cleanly");
}
