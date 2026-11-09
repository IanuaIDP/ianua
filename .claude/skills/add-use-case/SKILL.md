---
name: add-use-case
description: Add a command or query to ianua-app in the house shape, with its ports and tests. Use when the application needs a new operation, e.g. "/add-use-case authorization/groups archive command".
argument-hint: <area/sub-area> <snake_case_name> <command|query> [purpose]
---

# Add a use case

One file in `crates/ianua-app/src/use_cases/<area>/`, one `execute`. It
orchestrates the domain through ports and knows no adapter. Copy
`use_cases/scheduling/retry_dead.rs`, and read two neighbours in the same
folder. A neighbour wins over this page.

The file does not repeat its folder: `groups/archive.rs`. The types stay
full: `ArchiveGroupUseCase`. Past about 12 files, split the folder by topic.

## File order

1. `//!` module doc: `<Verb> <thing>: <purpose>.`
2. `<Name>Request`, unless a single id can be the `Input`. Fields are domain
   types, not raw strings.
3. `<Name>Ports` with `#[derive(ianua_macros::Fakes)]`. Every field is
   `Arc<dyn Port>`.
4. `<Name>UseCase`, with `new`, then private async steps that read ports.
5. `impl Command` or `impl Query`. The doc lists every error under
   `# Errors`.
6. Free functions: `ensure_*`, other helpers, then `*_event` builders.
7. `#[cfg(test)] mod tests`.

Store lookups live in one `lookup.rs` per folder, named `existing_<thing>` or
`owned_<thing>`. Reuse them. Shared helpers go in `crate::services`.

## What `execute` does, in order

1. Ask for the right. The caller's right comes **before** anything that can
   tell them whether a named thing exists. A name check that runs first tells
   a caller without the right which topics or schemas exist.
2. For a create, `LimitEnforcer` next.
3. `ensure_*` guards, returning early.
4. Change the aggregate through its own methods.
5. Save, with `.or_internal()?`.
6. Dispatch the events through the auditor. Save first, then dispatch. A
   failed audit write fails the operation.

Refusals use `message!`. See `translate-messages`.

## Units of work

Inside an API request the whole request is one transaction. Outside one, in
a job or a sweep, wrap each change and its record with `kept_together`.

**A worker cannot see what an open request wrote.** If the request waits on
background work, such as a before rule that a workflow must answer, keep that
work with `services::kept_together::kept_apart`. Otherwise the request waits
for a run that nobody can read, and it times out.

A change to who can do what must ask
`services::guarded::ensure_admin_rules_allow`. Every path that assigns a role
or adds a group member asks it, so no path goes around the rule. Add yours.

## When a house rule refuses it

`crates/ianua-audit/src/conventions/app/security.rs` lists the exceptions,
each with its reason: `LATE_CHECKS_ALLOWED`, `SILENT_COMMANDS_ALLOWED` and
others. Add an entry only when the exception is true, such as a sweep that
runs for nobody. Fix the code otherwise.

## Tests

Application tests use the in-memory fakes in `crate::test_support`, never a
mocking framework. One `make_uc` helper fills
`<Name>Ports { port_under_test, ..<Name>Ports::fakes() }`.

Cover:

- The happy path: state changed and the event name recorded.
- Each refusal, by error kind.
- A refused call records no event.
- A caller without the right learns nothing about the target.
- A create with a limit: `<name>_rejects_when_limit_reached` using
  `RejectingLimitEnforcer`.

Names state the behaviour: `archiving_an_unknown_group_is_not_found`.

## Register

Add `pub mod <name>;` to the area's `mod.rs`. To serve it, use
`add-endpoint`, and build it in `crates/ianua-assembly/src/<context>.rs`.

## Check

```sh
cargo +nightly fmt -p ianua-app
cargo nextest run -p ianua-app --all-features --lib -E 'test(/<name>/)'
cargo clippy -p ianua-app --all-targets --all-features -- -D warnings
cargo run --release -p ianua-audit -- check app
```
