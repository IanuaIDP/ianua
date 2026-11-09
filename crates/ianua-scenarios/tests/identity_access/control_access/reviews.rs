//! Access reviews: Tess asks Bea whether each member of a group keeps
//! their place. What Bea marks to go goes, and only when the review
//! completes; a review called off changes nothing; a review past its due
//! date settles undecided holders as it said it would. Nobody decides on
//! themselves, and whoever is not its reviewer decides nothing.

use std::time::Duration as StdDuration;

use ianua_scenarios::actors::Person;
use ianua_scenarios::api::{control_access, policies};
use ianua_scenarios::clock::Clock;
use ianua_scenarios::expect::Matrix;
use ianua_scenarios::stack::{Profile, Stack};
use ianua_scenarios::wire::Status;
use ianua_scenarios::wire::control_access::{NewAccessReview, ReviewDecision, ReviewScope};
use ianua_scenarios::world::World;
use time::Duration;

use crate::support::{
    USER, add_to_group, comes_to_be_refused, group_with_role, person, reader, reads_the_users,
    time_after,
};

/// A week, as a review's due date is set.
const A_WEEK: Duration = Duration::days(7);

/// The body starting a review of `group` by `reviewer`, due `due`, its
/// undecided holders kept or removed as `unanswered` says.
fn review_of(group: &str, reviewer: &str, due: Duration, unanswered: &str) -> NewAccessReview {
    NewAccessReview {
        name: "Readers recertification".to_owned(),
        scope: ReviewScope {
            kind: "group".to_owned(),
            id: group.to_owned(),
        },
        reviewer_ids: vec![reviewer.to_owned()],
        due: time_after(due),
        unanswered: unanswered.to_owned(),
    }
}

/// A decision on the user `holder`.
fn decision(holder: &Person, choice: &str) -> ReviewDecision {
    ReviewDecision {
        holder_kind: USER.to_owned(),
        holder_id: holder.id().to_owned(),
        choice: choice.to_owned(),
    }
}

/// A group holding the reader role, with `pat` and `uma` in it; its id.
async fn readers_with(world: &World<'_>, pat: &Person, uma: &Person) -> String {
    let role = reader(world).await;
    let readers = group_with_role(world, "Readers", &role).await;
    add_to_group(world, &readers, pat).await;
    add_to_group(world, &readers, uma).await;
    readers
}

/// Tess starts a review of Readers with Bea deciding. Bea reads the two
/// holders, marks Pat to keep and changes her mind to remove, and marks
/// Uma to keep. Until the review completes Pat keeps reading. Tess
/// completes it: Pat is taken out of the group and may not read the
/// users, Uma still may, and the review reports one removal. The start,
/// each decision, the completion and the removal are recorded.
#[tokio::test]
async fn bea_marks_pat_to_go_and_only_pat_loses_the_place() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let bea = person(&world, "bea").await;
    let readers = readers_with(&world, &pat, &uma).await;
    reads_the_users(&world, &pat).await;

    let started = control_access::start_review(
        world.tenant(),
        &review_of(&readers, bea.id(), A_WEEK, "keep_access"),
    )
    .send(world.admin().client())
    .await
    .ok();
    assert_eq!(started.status, "open");
    assert_eq!(started.holder_count, 2);
    assert_eq!(started.pending_count, 2);
    let listed = control_access::list_reviews(world.tenant())
        .send(world.admin().client())
        .await
        .ok();
    assert!(listed.items.iter().any(|item| item.id == started.id));
    let as_bea = control_access::get_review(world.tenant(), &started.id)
        .send(bea.client())
        .await
        .ok();
    assert_eq!(as_bea.holder_count, 2, "a reviewer reads the review");
    let items = policies::review_items(world.tenant(), &started.id)
        .send(bea.client())
        .await
        .ok();
    assert_eq!(items.items.len(), 2, "a reviewer reads its holders");

    for choice in [decision(&pat, "keep"), decision(&pat, "remove")] {
        control_access::decide_review(world.tenant(), &started.id, &choice)
            .send(bea.client())
            .await
            .ok();
    }
    let after = control_access::decide_review(world.tenant(), &started.id, &decision(&uma, "keep"))
        .send(bea.client())
        .await
        .ok();
    assert_eq!(after.pending_count, 0);
    assert_eq!(
        after.remove_count, 1,
        "a later choice replaces an earlier one"
    );
    reads_the_users(&world, &pat).await;

    let completed = control_access::complete_review(world.tenant(), &started.id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(completed.status, "completed");
    assert_eq!(completed.remove_count, 1);
    comes_to_be_refused(&world, &pat, "once the review removed her").await;
    reads_the_users(&world, &uma).await;

    let members = policies::members(world.tenant(), &readers)
        .send(world.admin().client())
        .await
        .ok();
    assert!(
        members.items.iter().all(|member| member.id != pat.id()),
        "Pat is out of Readers"
    );
    control_access::complete_review(world.tenant(), &started.id)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    world
        .trail()
        .recorded("authorization.access_review_started")
        .await;
    world
        .trail()
        .recorded("authorization.access_review_completed")
        .await;
    assert_eq!(
        world
            .trail()
            .count("authorization.access_review_decided")
            .await,
        3,
        "each decision is recorded"
    );
    assert_eq!(
        world
            .trail()
            .count("authorization.group_member_removed")
            .await,
        1,
        "the removal is recorded once"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Starting a review is refused to Max, Sam and nobody signed in, and for
/// a review with no reviewer, a date already past, a reviewer nobody knows
/// or a group nobody is in. Once it runs, Max cannot find it, Uma, who
/// reviews nothing, cannot decide on it, Tess sees it but is no reviewer
/// and is refused, and Bea decides on neither her own place nor someone
/// the review does not list. Nothing was decided or recorded.
#[tokio::test]
async fn only_named_reviewers_decide_and_nobody_decides_on_themselves() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let bea = person(&world, "bea").await;
    let role = reader(&world).await;
    let empty = group_with_role(&world, "Unpopulated", &role).await;
    let readers = readers_with_bea(&world, &role, &pat, &bea).await;

    refuse_the_start(&world, &readers, &bea).await;
    let nobody_holds = review_of(&empty, bea.id(), A_WEEK, "keep_access");
    control_access::start_review(world.tenant(), &nobody_holds)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");
    let unknown_reviewer = review_of(
        &readers,
        "00000000-0000-4000-8000-000000000000",
        A_WEEK,
        "keep_access",
    );
    control_access::start_review(world.tenant(), &unknown_reviewer)
        .send(world.admin().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let review = control_access::start_review(
        world.tenant(),
        &review_of(&readers, bea.id(), A_WEEK, "keep_access"),
    )
    .send(world.admin().client())
    .await
    .ok();

    control_access::list_reviews(world.tenant())
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    control_access::get_review(world.tenant(), &review.id)
        .send(world.member().client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    refuse_deciders(&world, &review.id, &pat, &uma).await;
    control_access::decide_review(world.tenant(), &review.id, &decision(&bea, "remove"))
        .send(bea.client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    control_access::decide_review(world.tenant(), &review.id, &decision(&uma, "remove"))
        .send(bea.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");

    let untouched = control_access::get_review(world.tenant(), &review.id)
        .send(bea.client())
        .await
        .ok();
    assert_eq!(untouched.pending_count, 2, "nothing was decided");
    assert_eq!(
        world
            .trail()
            .count("authorization.access_review_decided")
            .await,
        0,
        "no refused decision is recorded"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Readers, holding `role`, with Pat and Bea in it, for a review Bea may
/// be listed in.
async fn readers_with_bea(world: &World<'_>, role: &str, pat: &Person, bea: &Person) -> String {
    let readers = group_with_role(world, "Readers", role).await;
    add_to_group(world, &readers, pat).await;
    add_to_group(world, &readers, bea).await;
    readers
}

/// Nobody may start a review who cannot assign roles, nor can anyone
/// start one naming no reviewer, or a due date already past.
async fn refuse_the_start(world: &World<'_>, readers: &str, bea: &Person) {
    let call = control_access::start_review(
        world.tenant(),
        &review_of(readers, bea.id(), A_WEEK, "keep_access"),
    )
    .call();
    Matrix::new("starting a review", call)
        .refused(world.member().client(), Status::FORBIDDEN, "forbidden")
        .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
        .refused(
            world.anonymous().client(),
            Status::UNAUTHORIZED,
            "unauthenticated",
        )
        .run()
        .await;
    let mut no_reviewers = review_of(readers, bea.id(), A_WEEK, "keep_access");
    no_reviewers.reviewer_ids.clear();
    control_access::start_review(world.tenant(), &no_reviewers)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    let past_due = review_of(readers, bea.id(), Duration::hours(-1), "keep_access");
    control_access::start_review(world.tenant(), &past_due)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
}

/// Uma, who may not see the review, finds no such review to decide on,
/// and Tess, who sees it and is no reviewer, is refused deciding on Pat.
async fn refuse_deciders(world: &World<'_>, review: &str, pat: &Person, uma: &Person) {
    let on_pat = decision(pat, "remove");
    control_access::decide_review(world.tenant(), review, &on_pat)
        .send(uma.client())
        .await
        .refused(Status::NOT_FOUND, "not_found");
    control_access::decide_review(world.tenant(), review, &on_pat)
        .send(world.admin().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
}

/// Tess starts a review and calls it off after Bea marked Pat to go;
/// Max may not call it off. Nothing changes: Pat keeps reading. Calling
/// it off again is refused, as are deciding on and completing it, and only
/// the calling off was recorded.
#[tokio::test]
async fn a_review_called_off_changes_nothing() {
    let stack = Stack::start(Profile::standard())
        .await
        .expect("the stack starts");
    let world = World::new(&stack).await;
    let pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let bea = person(&world, "bea").await;
    let readers = readers_with(&world, &pat, &uma).await;
    let review = control_access::start_review(
        world.tenant(),
        &review_of(&readers, bea.id(), A_WEEK, "keep_access"),
    )
    .send(world.admin().client())
    .await
    .ok();
    control_access::decide_review(world.tenant(), &review.id, &decision(&pat, "remove"))
        .send(bea.client())
        .await
        .ok();

    control_access::cancel_review(world.tenant(), &review.id)
        .send(world.member().client())
        .await
        .refused(Status::FORBIDDEN, "forbidden");
    let cancelled = control_access::cancel_review(world.tenant(), &review.id)
        .send(world.admin().client())
        .await
        .ok();
    assert_eq!(cancelled.status, "cancelled");
    reads_the_users(&world, &pat).await;

    control_access::cancel_review(world.tenant(), &review.id)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    control_access::decide_review(world.tenant(), &review.id, &decision(&uma, "remove"))
        .send(bea.client())
        .await
        .refused(Status::CONFLICT, "conflict");
    control_access::complete_review(world.tenant(), &review.id)
        .send(world.admin().client())
        .await
        .refused(Status::UNPROCESSABLE_ENTITY, "domain_error");
    assert_eq!(
        world
            .trail()
            .count("authorization.access_review_cancelled")
            .await,
        1,
        "the calling off is recorded once"
    );
    assert_eq!(
        world
            .trail()
            .count("authorization.access_review_completed")
            .await,
        0,
        "a review called off never completes"
    );
    stack.stop().await.expect("the stack stops cleanly");
}

/// Tess starts a review of Readers, whose undecided holders lose the
/// place at the due date, with Bea reviewing and nobody deciding; Tess
/// may not complete it before the date. Two hours past the date the sweep
/// has completed it and recorded it, and Pat, who nobody decided on,
/// signed in again, may not read the users.
#[tokio::test]
async fn a_review_past_its_date_removes_the_undecided_as_it_said_it_would() {
    let clock = Clock::controlled();
    let stack = Stack::start(Profile::standard().with("WORKER_SWEEP_TICK_SECONDS", "1"))
        .await
        .expect("the stack starts");
    let mut world = World::new(&stack).await;
    let mut pat = person(&world, "pat").await;
    let uma = person(&world, "uma").await;
    let bea = person(&world, "bea").await;
    let readers = readers_with(&world, &pat, &uma).await;

    let review = control_access::start_review(
        world.tenant(),
        &review_of(&readers, bea.id(), Duration::hours(1), "remove_access"),
    )
    .send(world.admin().client())
    .await
    .ok();
    control_access::complete_review(world.tenant(), &review.id)
        .send(world.admin().client())
        .await
        .refused(Status::CONFLICT, "conflict");

    clock.advance(StdDuration::from_secs(2 * 3600));
    world.owner_mut().sign_in(&stack).await;
    pat.sign_in(&stack).await;
    world
        .trail()
        .recorded("authorization.access_review_completed")
        .await;
    comes_to_be_refused(&world, &pat, "once the overdue review removed her").await;
    stack.stop().await.expect("the stack stops cleanly");
}
