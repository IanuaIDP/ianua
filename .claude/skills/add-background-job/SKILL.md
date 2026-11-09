---
name: add-background-job
description: Add a background job, a multi-step process or a periodic sweep to the worker, and walk it through crash, retry, lost event, last try and retention. Use when work must happen outside a request, e.g. "/add-background-job webhooks deliver" or "/add-background-job sweep expired exports".
argument-hint: <context> <job or sweep> [what it does]
---

# Add a background job

Three things run in the background and they are different. **Workflows** are
the automation product tenants build. **Jobs** are the platform's internal
work. **Tenant setup** is the steps that make a tenant usable, run as jobs.
Never call internal work a workflow.

Copy `use_cases/scheduling/remove_ended.rs` for a sweep, and
`use_cases/webhooks/delivery/` for a job.

## A job

1. Name the type in the app as a constant, such as `DELIVER_WEBHOOK_JOB`.
2. Queue a `ScheduledJob` through the `JobQueue` port. Inside a unit of work
   it is written in that unit's transaction, so a change and its job are kept
   together.
3. Key it, and choose how long the key holds:
   - `.keyed(key)` holds while the job waits or runs. The same work may be
     queued again afterwards, as a run woken twice.
   - `.keyed_once(key)` holds for as long as the row is kept. Use it for work
     done once per event, so an event the bus delivers again sends nothing.
4. Write the `JobHandler`. Answer `Handled::Done` or `Handled::Retry`. Use
   `unless_gone` when the target may have been deleted, and
   `done_unless_failed` when a refusal should end the job. A job that can
   never succeed must not fail again and again.
5. Register it in `crates/ianua-server/src/worker/handlers.rs`, and add the
   type to `QUEUED_JOB_TYPES`. Choose its lane in
   `crates/ianua-server/src/worker/jobs.rs`. Slow work goes on the long lane
   so it never holds up mail or webhooks.
6. The payload holds ids, not secrets. Dead jobs are shown to operators with
   their type and reason, never their payload.

## A sweep

Write a use case with `Caller = ()`, and add it through `Swept::of` to the
right file in `crates/ianua-server/src/worker/sweeps/`. It must be bounded:
run a limited number of rounds, as `MOST_ROUNDS` does, so a backlog drains
over several runs. A sweep across tenants reaches every tenant, deleted ones
too, whose audit trail must keep its retention.

Every sweep you write must actually be started. Cleanup code nobody calls
fails quietly.

## A multi-step process

Queue each step as a `StepJobs`, and give it a `*Start` that the reconcile
sweep calls, in `use_cases/scheduling/reconcile.rs`. Without it, one lost
event leaves the process half done for ever. `check app` holds this rule.

**Never raise an event again to restart work.** A second `tenant.provisioned`
is a false record and tells every watcher twice. Sweeps queue the work again
and record nothing.

## Walk through this before calling it done

| Case | Question |
| --- | --- |
| Worker dies mid-step | The job's lease runs out and it runs again. Is half-finished work safe to redo? |
| Lost event | What starts this work if the event never arrives? |
| Lost job | What picks it up? Name the sweep. |
| Retry after a partial step | Is it idempotent? A retry finds the work done and finishes nothing twice. |
| The last try fails | The job goes dead. Does anyone look? Does a sweep queue it for ever or notify for ever? |
| Two workers | A claim takes a job once. Does your own write need a version check? |
| Retention | Ended jobs leave after 14 days, longer than the bus keeps an event (7 days). If your key must outlive that, say so. |
| Audit | Does the record say only what happened, once? |
| Caches | Does anything read a cached copy of what this changed? |
| Time bound | Every outbound call has a timeout. |

Add the failing case as a test. A new kind of mistake earns a house rule, see
`add-house-rule`.

## Tests

Application tests use `FakeJobQueue` from `crate::test_support::scheduling`.
Test that a redelivered event queues nothing, that a gone target ends the
job, and that a retry changes nothing twice. A restart belongs in a scenario,
with `stack.restart()`.

## Check

```sh
cargo +nightly fmt -p ianua-app -p ianua-server
cargo nextest run -p ianua-app --all-features --lib -E 'test(/<name>/)'
SQLX_OFFLINE=true cargo nextest run -p ianua-server --lib -E 'test(/worker::/)'
SQLX_OFFLINE=true cargo clippy -p ianua-app -p ianua-server --all-targets --all-features -- -D warnings
cargo run --release -p ianua-audit -- check app
```
