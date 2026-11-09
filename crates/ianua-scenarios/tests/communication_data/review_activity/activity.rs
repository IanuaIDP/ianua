//! The activity calendar on the dashboard: how many things happened each
//! day, counted from the audit trail, for those who may read the trail.

use ianua_scenarios::api::activity;
use ianua_scenarios::expect::{Matrix, eventually};
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::activity::ActivityCalendar;
use ianua_scenarios::wire::organization::OrgRole;
use ianua_scenarios::world::World;

use crate::support::invited;

/// The category an invitation is counted under.
const IDENTITY: &str = "Identity";

/// How many people Tess invites.
const INVITED_COUNT: u64 = 3;

/// The fewest days a default window, a year ending today, shows.
const DAYS_OF_A_YEAR: usize = 365;

/// The tenant's calendar and the company's start at some count for today.
/// Tess invites three people. Each calendar soon counts those three more
/// under identity changes today, today's square is coloured in, and the
/// default window is a whole year, quiet days included, oldest first and
/// ending today.
#[tokio::test]
async fn the_calendars_count_what_tess_did_today() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let tess = world.admin().client();
    let ann = world.owner().client();
    let tenant_before = activity::tenant(world.tenant(), &[]).send(tess).await.ok();
    let today = tenant_before.to.clone();
    let company_before = activity::organization(world.org(), &[])
        .send(ann)
        .await
        .ok();

    for name in ["uma", "vic", "wes"] {
        invited(&world, name).await;
    }

    let wanted = tenant_before.count_on(&today, IDENTITY) + INVITED_COUNT;
    let counted = eventually("the tenant's calendar to count the invitations", || async {
        let calendar = activity::tenant(world.tenant(), &[]).send(tess).await.ok();
        (calendar.count_on(&today, IDENTITY) >= wanted).then_some(calendar)
    })
    .await;
    let wanted = company_before.count_on(&today, IDENTITY) + INVITED_COUNT;
    eventually("the company's calendar to count them too", || async {
        let calendar = activity::organization(world.org(), &[])
            .send(ann)
            .await
            .ok();
        (calendar.count_on(&today, IDENTITY) >= wanted).then_some(())
    })
    .await;
    assert_shape(&counted, &today);

    stack.stop().await.expect("the stack stops cleanly");
}

/// Max may not read the tenant's calendar, as he may not read its trail;
/// Bea, who runs the bill, may not read the company's; Sam reads neither of
/// Acme's and nobody signed in is asked to sign in. Tess's window running
/// backwards is refused.
#[tokio::test]
async fn nobody_who_may_not_read_the_trail_reads_the_calendar() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let mut bea = world
        .colleague("bea", "Bea Billing", OrgRole::Billing)
        .await;
    bea.sign_in(&stack).await;

    Matrix::new(
        "reading the tenant's calendar",
        activity::tenant(world.tenant(), &[]).call(),
    )
    .allowed(world.admin().client())
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
        "reading the company's calendar",
        activity::organization(world.org(), &[]).call(),
    )
    .allowed(world.owner().client())
    .refused(bea.client(), Status::FORBIDDEN, "forbidden")
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .refused(
        world.anonymous().client(),
        Status::UNAUTHORIZED,
        "unauthenticated",
    )
    .run()
    .await;
    activity::tenant(
        world.tenant(),
        &[("from", "2026-06-02"), ("to", "2026-06-01")],
    )
    .send(world.admin().client())
    .await
    .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");

    stack.stop().await.expect("the stack stops cleanly");
}

/// A calendar reads a whole year, oldest first, ending today, and today's
/// square is coloured in.
fn assert_shape(calendar: &ActivityCalendar, today: &str) {
    assert!(
        calendar.days.len() >= DAYS_OF_A_YEAR,
        "the default window is a year"
    );
    assert_eq!(
        calendar.days.first().map(|day| day.date.as_str()),
        Some(calendar.from.as_str())
    );
    let last = calendar.days.last().expect("the window holds days");
    assert_eq!(last.date, today, "the window ends today");
    assert!(last.level >= 1, "today's square is coloured in");
    assert!(
        calendar
            .categories
            .iter()
            .any(|category| category == IDENTITY),
        "identity changes are among the categories offered"
    );
}
