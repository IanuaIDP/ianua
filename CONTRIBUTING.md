# Contributing to Ianua

Thank you for helping. Ianua decides who gets into other people's apps, so
changes are held to a high bar. Read this page before opening a pull request.

## Before you start

- **Outside contributions need a signed [contributor agreement](CLA.md).** We
  cannot merge outside code until you have signed it, because Ianua is
  [fair-code](README.md#license) and the agreement is what lets us offer it under
  commercial terms. You keep your copyright. A bot asks you to sign on your first
  pull request.
- For anything larger than a small fix, open an issue first so we can agree on
  the approach.
- Found a security problem? Do not open an issue. See [SECURITY.md](SECURITY.md).

## Setting up

You need Docker, the Rust toolchain in `rust-toolchain.toml`, nightly `rustfmt`,
`cargo-nextest`, `sqlx-cli` and `cargo-hakari`. For the dashboard you need Node
20.9 or later.

[README.md](README.md) explains how to run everything locally.

## How we work

[CLAUDE.md](CLAUDE.md) holds the engineering rules, for people and AI assistants
alike. The ones that matter most:

- Dependencies point inward: domain, then application, then adapters.
- The gateway denies by default. A missing or failed decision is a refusal.
- Tokens, sessions and secrets are never logged.
- Every feature has tests, and a bug fix starts with a failing test.

If you use AI tools, read
[Using AI in your contributions](docs/src/content/docs/contributing/ai-assisted-contributions.mdx).
You are responsible for every line you send.

The skills in `.claude/skills/` walk through common work step by step.

## Checking your change

```sh
cargo +nightly fmt --all
SQLX_OFFLINE=true cargo clippy --all-targets --all-features -- -D warnings
SQLX_OFFLINE=true cargo nextest run --workspace --exclude ianua-scenarios
cargo run --release -p ianua-audit -- check
```

To run an end-to-end scenario:

```sh
SQLX_OFFLINE=true cargo nextest run -p ianua-server -p ianua-scenarios --test <target>
```

For the dashboard, in `dashboard/`:

```sh
npm run check-messages && npm run lint && npm run type-check && npm run format:check
```

## Pull requests

Fill in the template. Keep each pull request to one change, and update `docs/`
for anything a reader would notice.

People who help build Ianua get something back: see
[Contributor perks](docs/src/content/docs/contributing/perks.mdx).
