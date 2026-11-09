//! Waiting for working hours: a workflow reaching a team while it works
//! goes on at once, and one reaching it on a day off waits.

use ianua_scenarios::expect::eventually;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::workflows::{Graph, Node, Step, Trigger, WorkingHours};
use ianua_scenarios::world::World;
use serde_json::json;
use time::OffsetDateTime;

use crate::support::{drafted, ended, published, run, started_with};

/// The key of the waiting step.
const WAIT_STEP: &str = "support-hours";

/// Every day of the week, by name.
const DAYS: [&str; 7] = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];

/// A graph of one step waiting for `hours`.
fn waiting_for(hours: WorkingHours) -> Graph {
    Graph {
        nodes: vec![Node {
            key: WAIT_STEP.to_owned(),
            name: "Wait for support hours".to_owned(),
            step: Step::Wait {
                duration_seconds: None,
                working_hours: Some(hours),
            },
        }],
        edges: vec![],
    }
}

/// Hours worked on `days`, all day long in UTC.
fn all_day_on(days: Vec<String>) -> WorkingHours {
    WorkingHours {
        days,
        opens: "00:00".to_owned(),
        closes: "24:00".to_owned(),
        timezone: "UTC".to_owned(),
    }
}

/// Support works every day, all day: the run reaches it while it works and
/// goes straight through.
#[tokio::test]
async fn a_wait_during_working_hours_goes_on_at_once() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let every_day = DAYS.iter().map(|&day| day.to_owned()).collect();
    let draft = drafted(&world, Trigger::Manual, waiting_for(all_day_on(every_day))).await;
    let workflow = published(&world, &draft).await;

    let started = started_with(&world, &workflow, json!({})).await;

    ended(&world, &started.execution_id, "succeeded").await;
}

/// Support works only the day after tomorrow: the run reaches it on a day
/// off and waits, its step still running.
#[tokio::test]
async fn a_wait_outside_working_hours_waits() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let later = OffsetDateTime::now_utc() + time::Duration::days(2);
    let index = usize::from(later.weekday().number_days_from_monday());
    let draft = drafted(
        &world,
        Trigger::Manual,
        waiting_for(all_day_on(vec![DAYS[index].to_owned()])),
    )
    .await;
    let workflow = published(&world, &draft).await;

    let started = started_with(&world, &workflow, json!({})).await;
    let execution = eventually("the wait to begin", || async {
        let execution = run(&world, &started.execution_id).await;
        (execution.steps[0].phase == "running").then_some(execution)
    })
    .await;

    assert_eq!(execution.status, "running");
}
