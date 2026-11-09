---
name: add-house-rule
description: Add a checked house rule to ianua-audit with a planted break that proves it finds what it exists to find. Use when a class of mistake was made once and must never come back, e.g. "/add-house-rule app a sweep records nothing".
argument-hint: <layer> <the rule in one sentence>
---

# Add a house rule

House rules are small programs that read the source and refuse a shape of
code. They need no build of the checked crates, so they also read code that
does not compile. Each one stands for a mistake made once.

The rules live in `crates/ianua-audit/src/conventions/`, by layer: `domain`,
`app`, `infra`, `api`, `integrations`, `plain`.

Copy `conventions/app/recovery.rs` for a rule with a reason, and
`every_event_check_finds_its_planted_break` in `conventions/app/events.rs` for
the planted break.

## Is it a rule?

A rule fits when a machine can tell right from wrong by reading the code, and
the mistake would be silent otherwise. Put it in code when a type or the
compiler can hold it instead. A type that cannot be built wrongly beats any
check.

## Steps

1. **State the rule** in the file's `//!`, with the mistake it stands for, in
   plain words. Say what is true, not who made the mistake.
2. **Write the check.** Layers share readers in their `source.rs`:
   `app_files` and `SourceFile`, which holds the parsed `syntax` and the text.
   Prefer the parsed syntax to text search. Use `file.code()` when test code
   must not count.
   ```rust
   /// A sweep records nothing: it queues the work again.
   #[cfg_attr(test, test)]
   pub(crate) fn no_sweep_raises_an_event() { /* panics naming the file */ }
   ```
   The name is the rule as a sentence. A check stops on the first break and
   names the file and what is wrong, so the fix is obvious.
3. **Plant a break.** Write a test that runs the check over a made-up file
   with `SourceFile::planted("use_cases/planted.rs", PLANTED)` and asserts it
   is found. A check without a planted break can rot into one that passes
   always. If the file already has a `every_*_finds_its_planted_*` check and a
   `CHECKS` table, add yours to the table.
4. **Prove it reads real code.** A check that reads nothing passes for ever.
   Assert it found some known real item, as
   `the_reference_kinds_are_read` does.
5. **Register it** in `conventions/registry.rs`, with its `layer`, `name` and
   `run`, in the order of its file. Register the planted check too.
6. **Run it over the code.** Fix the code it finds. When an exception is
   truly needed, add it to the file's `*_ALLOWED` list with the reason as a
   named constant, for example `DIRECTORY_TOKEN` in `app/security.rs`.

## Keep the check honest

- Name the finding in plain words. Someone new reads it first.
- Do not write review labels or ticket numbers into a rule or its message.
- Do not weaken a check to make it pass. Fix the code, or add one named
  exception.
- A rule that refuses a whole family of code needs its own reason in the
  module doc, because someone will one day want to remove it.

## Layout rules the checks already hold

Before writing one, list what exists:

```sh
cargo run -p ianua-audit -- checks
grep -n 'name:' crates/ianua-audit/src/conventions/registry.rs
```

## Check

```sh
cargo +nightly fmt -p ianua-audit
cargo nextest run -p ianua-audit
cargo clippy -p ianua-audit --all-targets --all-features -- -D warnings
cargo run --release -p ianua-audit -- check <layer>
```
