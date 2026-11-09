---
name: write-domain-docs
description: Write or rewrite doc comments in ianua-domain so they read like a person explaining the code. Use when documenting or cleaning up docs under one domain path, e.g. "/write-domain-docs domains/authorization".
argument-hint: <path under crates/ianua-domain/src>
---

# Write domain docs

Changes only `///` and `//!` comments under one path of
`crates/ianua-domain/src`. Never code, names or test bodies.

The reader is a developer new to the project, opening one file. They know
Rust. They do not know the project's history or why a rule exists. Each doc
answers, in order:

1. What it is or does, in one plain sentence.
2. The rule it keeps, if any.
3. Why, as a short example with a named person, only when the reason is not
   obvious.

## How to write

- Lead with the point. The first sentence says what the item is or returns.
- One idea per sentence, about 20 words at most.
- Everyday words. "refuses", "keeps", "gives". Not "ensures", "enforces the
  invariant that", "leverages".
- No em dashes. No chains of semicolons. No clauses in brackets.
- No metaphors such as "gate" or "hole", unless that is the type's name.
- No history. Not "used to", "no longer", "this replaced", "deliberately".
  Say what is true now.
- No filler. Cut "simply", "just", "note that", "in order to".
- Say what the name does not. Never "Its id." or "The operation.". Write
  where the id is shown or what the operation is for.
- Do not repeat the signature. Name a parameter only to say what its type
  cannot.
- `# Errors` and `# Panics` stay, at most five lines, alike cases grouped on
  one line: the variant, then when.
- Keep every intra-doc link working. Prefer a link to a sentence describing
  the type.

## People in examples

Use the same small cast: Ann owns a company, Bob runs the platform, Tess
administers a tenant, Pat is a user, Mallory attacks.

> Tess may edit roles but not give refunds. Without this check, Tess adds
> "give refunds" to a role and takes it.

## Tests

Every test has one to three sentences saying the situation and what must
happen. Add what the name leaves out. A test that stops an attack starts with
`Stops:` and gives the case.

```rust
/// Stops: Ann approves "delete order 1". Meanwhile the run swaps it for
/// "delete every order". Ann's approval must not run the new call.
#[test]
fn a_decision_covers_only_the_call_it_was_made_about() {
```

## Before and after

```rust
// Before
/// The subject is a PrincipalRef rather than a UserId because a user is not
/// the only thing that holds authority, which is what forced every other
/// kind to carry a private grant list of its own.

// After
/// Gives a role to a person, an agent or a machine in one tenant.
///
/// Every kind of caller gets its rights the same way, through a role. So
/// "what may this caller do" has one answer for all of them.
```

## Steps

1. Read the whole file, code included, so each doc says what the code does.
   A module doc can be wrong. Where a doc claims something is checked or
   refused, confirm it in the method, and in the use case that calls it.
2. Rewrite each doc by these rules. Leave one alone if it already follows
   them.
3. If the code does not do what the doc claims, fix the doc and report it.

## Check

```sh
cargo +nightly fmt -p ianua-domain
cargo clippy -p ianua-domain --all-targets --all-features -- -D warnings
cargo doc -p ianua-domain --no-deps
cargo run --release -p ianua-audit -- check domain
cargo run --release -p ianua-audit -- check plain
```
