---
name: add-scenario
description: Write an end-to-end scenario in ianua-scenarios that runs the real platform and gateway and drives it as named people. Use when a journey must be proven across the whole system, e.g. "/add-scenario operations/operate_platform an operator retries a dead job".
argument-hint: <target path> <what happens>
---

# Add a scenario

A scenario starts the real platform, gateway, database, cache and bus, and
acts only through the outside: HTTP, mail, the gateway. Docker must be
running. Copy `tests/operations/operate_platform/dead_jobs.rs`.

## Where things are

| Need | Place |
| --- | --- |
| Test target | `tests/<group>/<target>/main.rs`, with `[[test]]` in `Cargo.toml` |
| The running system | `stack::{Stack, Profile}` |
| Company, people | `world::World` |
| Calls | `api::<area>` functions returning `Request<T>` |
| Bodies | `wire::<area>`, written by hand |
| Waiting | `expect::{eventually, eventually_paced, Waiting}` |
| Who may do it | `expect::Matrix` |
| Audit records | `world.trail()`, and `expect::Trail` |
| Gateway records | `expect::Records` |
| Outside services | `upstreams::{Echo, CannedApp}`, `stack.mailbox()` |

The wire types are independent of the server's DTOs on purpose. A renamed
field must fail here. Never import `ianua-api` types.

## Shape

```rust
/// One paragraph telling the story: who does what, what must happen, and
/// what must not.
#[tokio::test]
async fn bob_retries_a_mail_given_up_on_and_it_goes_out_once() {
    let stack = Stack::start(Profile::standard()).await.expect("the stack starts");
    let world = World::new(&stack).await;

    // the journey

    stack.stop().await.expect("the stack stops cleanly");
}
```

The cast: `world.owner()`, `admin()` (Tess), `member()`, `stranger()`,
`anonymous()`, and `world.twin()`, a second tenant to prove isolation. Test
functions may be as long as the story needs. No comments inside them. Named
helper functions tell the steps. Name the status: `Status::CONFLICT`.

## Rights

Use a `Matrix` so every actor is checked and every mismatch shows at once:

```rust
Matrix::new("retrying a job", call)
    .allowed(world.owner().client())
    .refused(world.stranger().client(), Status::FORBIDDEN, "forbidden")
    .run()
    .await;
```

## Waiting

- Never sleep blindly. `eventually` asks every 100 ms for 20 seconds.
  `eventually_paced` takes its own pace and patience.
- To prove something does **not** happen, watch for several of the worker's
  rounds, and name the constant for why.
- Things that arrive later: mail, jobs, gateway route changes, records.

## Reading records

`recorded_where` returns the **first** record that matches. Polling leaves
records too, so a loose predicate finds an earlier one. Match exactly what
you need, such as the decision and the reason together.

For the audit trail, `Trail::recorded_after(&seen, event)` ignores what setup
left, and `count` proves a thing was recorded once.

## Failures and restarts

`Profile::standard().with_cuttable_parts()` then `stack.cut(Part::Mail)` for
`Database`, `Cache`, `Bus` or `Mail`. `stack.restart()` is a deploy.
`Profile::with("NAME", "1")` shortens a timing for one scenario. Prefer that
to waiting.

## Mistakes to avoid

- A tenant has limits on roles, routes, keys and groups. A refusal at a limit
  is a 403 that looks like a missing right. Two roles are seeded already.
- Mail arrives in any order. Pick a mail by what it links to.
- Setup leaves its own events. Take the trail's `ids()` before the step.
- A route may answer `404` or `503` while it arrives. Wait for the answer you
  mean before asserting anything about it.
- Every `expect` says what should have been true.

When a scenario finds a real bug, write the failing test first, then fix it
in the right layer. A failure in the setup is fixed in the setup.

## Check

```sh
cargo +nightly fmt -p ianua-scenarios
SQLX_OFFLINE=true cargo nextest run -p ianua-server -p ianua-scenarios --test <target> -E 'test(/<scenario>/)'
SQLX_OFFLINE=true cargo clippy -p ianua-scenarios --all-targets --all-features -- -D warnings
```

Naming `ianua-server` builds the program the scenarios run. Run a new
scenario a few times: one that passes only sometimes is not done.
