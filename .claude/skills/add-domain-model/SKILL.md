---
name: add-domain-model
description: Add or change a domain aggregate, value object or event in ianua-domain, with its row, reconstitute and tests. Use when a new business concept or rule belongs in the domain, e.g. "/add-domain-model oauth/clients ApiKey pausing".
argument-hint: <context path> <type> [what changes]
---

# Add a domain model

The domain is pure Rust. It holds the rules and knows nothing of tokio, sqlx
or HTTP. Copy these:

- Aggregate: `crates/ianua-domain/src/domains/oauth/clients/api_key.rs`
- Value object: `crates/ianua-domain/src/types/branding/hex_color.rs`
- Events: `crates/ianua-domain/src/domains/operator/events.rs` and
  `crates/ianua-domain/src/types/event_type/operator.rs`

Read the whole context folder first. A neighbour wins over this page when
they differ.

## A value object

Use `text_value!` for text, and `impl TextValue` for its `FIELD`, `rules` and
`normalized`. Use `text_value! { redacted ... }` for a secret: its `Debug`
prints only the name.

Check with `shared::validation::Validator` and `numeric::validate_range`.
Never write `trim().is_empty()` or a length check by hand. Ids come from
`uuid_id!`. Any primitive with a meaning gets a type.

## An aggregate

1. Private fields, with `raised: Raised<T>` and a `T: TenantScope` parameter
   for a tenant's aggregate.
2. A fallible constructor that takes a `New<Thing>` struct and the caller's
   control, such as `ApiKey::create(key, &control)`. Rights are asked through
   the context's `control.rs`.
3. A public `<Thing>Row` and `fn reconstitute(row) -> Result<Self, DomainError>`.
   It checks the invariants again with `shared::model::row_check::RowCheck`.
   A broken row is refused through `DomainError::corrupt_row`. It is never
   repaired. An unknown stored enum value is `DomainError::Infrastructure`,
   not `Validation`.
4. Mutators keep the invariants or return an error. A boolean pair is an enum.
5. Every refusal is `message!("<context>-<words>", "text")`. See the
   `translate-messages` skill.

## An event

1. Add the variant to `event_types!` in `types/event_type/<context>.rs`. Its
   `///` line is the description shown to people, and is translated.
2. Add the struct and `tenant_event!`, `organization_event!` or
   `platform_event!` in the context's `events.rs`. The payload is `EventData`.
   Never a secret, a token, or a job's contents.
3. **Decide `is_notifiable()`.** Every event reaches colleagues' notifications
   unless excluded. An event that only records someone's own activity, such
   as a sign-in step or an export, must be excluded and tested.
4. Refresh the snapshots on purpose (see the last section).

The audit tool keeps lists in
`crates/ianua-audit/src/conventions/domain/lists.rs`, such as methods that
are observed and event fields. When a house rule names a new method or
field, add it there with its reason.

## Rules this project learned the hard way

- Read time through `crate::shared::clock::now()`, in tests too.
  `OffsetDateTime::now_utc()` is refused by the linter. Use `clock::freeze`
  to fix the time in a test.
- Subtract two instants with `clock::between(earlier, later)`. Plain `-` on
  times fails the arithmetic lint.
- A limit set on a parent must hold when the child is made, not only when it
  is read. A child stored past its parent's limit breaks `reconstitute` and
  turns every later listing into a 500.
- Two values that mean the same must compare equal. Workflow data compares
  maps without regard to field order, so a reordered document still matches
  its approval.
- Check whether the operation is possible on the current state before
  checking its details. Report the first true problem.
- A function is at most 30 lines and four inputs besides `self`. Split it
  rather than silencing the lint. Move a run of checks into one `ensure_*`.

## Tests

`#[cfg(test)] mod tests` in the same file. Plain `#[test]`, no mocks, no I/O,
no async. One behaviour each, named for it:
`a_paused_key_does_not_sign_in`. Every test has a doc comment, using the
`write-domain-docs` skill. Cover each refusal, each `corrupt_row` case, and
that a refused change raises no event. Use `proptest` for parsers.

## Check

```sh
cargo +nightly fmt -p ianua-domain
IANUA_WRITE_SNAPSHOTS=1 cargo nextest run -p ianua-domain --lib
git diff --stat
cargo clippy -p ianua-domain --all-targets --all-features -- -D warnings
cargo run --release -p ianua-audit -- check domain
```

Read the snapshot diff before keeping it. A name or payload key that changed
without a reason is a bug. When the change adds an event field,
`IANUA_WRITE_SNAPSHOTS=1 cargo run --release -p ianua-audit -- check domain`
rewrites the payload keys.
