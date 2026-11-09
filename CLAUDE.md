# ianua

ianua is a source-available identity provider with zero-trust access. A gateway
terminates traffic and forwards it under policy. Workflows and agents act for
people under the same rules.

These are the rules for changing the code, for people and for AI assistants.
An AI-assisted change must also follow
`docs/src/content/docs/contributing/ai-assisted-contributions.mdx`.

The skills in `.claude/skills/` walk through common work step by step, such as
`add-use-case`, `add-endpoint`, `add-store`, `add-background-job`,
`add-gateway-stage`, `add-integration`, `add-scenario` and `add-house-rule`.

## How to work

- Read the code before changing it: the file, its callers, its module and the
  traits it implements. A neighbour shows the shape to follow.
- Fix the cause in the right layer. A problem in test setup is fixed in the
  test setup, never with a new platform setting.
- If you change a public API, update every call site in the same change.
- Before removing something as unused, search every crate and the dashboard.
- A refactor never changes the API's JSON.
- Something built ahead of its user is dead code. Do not merge it, and never
  add `#[allow(dead_code)]`.
- A change to behaviour, endpoints, names, paths or settings updates the docs
  pages that describe it, in the same change.
- Stored rows and a running bus already exist. Anything touching them works on
  what is there, with a migration path.

## Layers

Large changes go layer by layer, from the inside out.

| Layer | Crates | Holds |
| --- | --- | --- |
| Domain | `ianua-domain` | Aggregates, value objects, events, rules. Pure Rust. |
| Application | `ianua-app` | Use cases and the ports they need. |
| Adapters | `ianua-api`, `ianua-infra`, `ianua-ldap`, `ianua-grpc`, `integrations/*` | HTTP, storage, the bus, outside services. |
| Composition | `ianua-assembly`, `ianua-server`, `ianua-boot` | Wires adapters into ports. |
| Data plane | `ianua-zero`, `ianua-egress`, `ianua-runner`, `ianua-connector`, `ianua-dns` | The gateway and its companions. |
| Tooling | `ianua-scenarios`, `ianua-audit`, `ianua-schema`, `ianua-translate` | End-to-end tests, house rules, migrations, translations. |

- Dependencies point inward only. Adapters know nothing of each other.
- No infrastructure type crosses a port: no `sqlx::Error`, `reqwest::Error`,
  `hyper::Error` or `serde_json::Value`. If the domain seems to need an
  infrastructure crate, a port is missing.
- DTOs live in adapters. The domain does not derive anything to please HTTP.
- Handlers only orchestrate. Parsing goes to `extractors/`, mapping to `dto/`,
  extra reads into the use case's result.
- Adapters and settings are named by role, never by product: `cache/`, `bus/`,
  `CACHE_URL`. A stand-in for a provider not set up is `No` plus the port, as
  in `NoGeolocator`.

## Domain

- Value objects are newtypes with private fields and a fallible constructor,
  validated with `shared::validation::Validator` and
  `numeric::validate_range`.
- Aggregates protect their invariants. Constructors are fallible, and public
  methods keep the invariants or return an error.
- `fn reconstitute(row) -> Result<Self, DomainError>` checks a stored row again
  and refuses a broken one with `DomainError::corrupt_row`. It never repairs
  silently. An unknown stored enum value is `DomainError::Infrastructure`.
- Domain errors are domain concepts, never transport or storage errors.
- Read time through `shared::clock::now()`, in tests too.
- Domain tests are pure: no async, no mocks, no I/O.

## Use cases

- One `execute` per use case. Store lookups go in one `lookup.rs` per folder
  (`existing_<thing>`, `owned_<thing>`). Refusing checks are `ensure_*`. Events
  are built by a private `<subject>_<past>_event`. Shared helpers go in
  `crate::services`.
- Ask for the caller's right before anything that reveals whether a named
  thing exists.
- A create asks `LimitEnforcer`, with a rejection test using
  `RejectingLimitEnforcer`.
- Commands save first, then dispatch.
- Application tests use the in-memory fakes in `crate::test_support`.

## Events

- Use cases send events through the `EventDispatcher` port. A failed audit
  write fails the operation. A bus that is down delays events and loses none.
- Bus subjects are `ianua.tenant.{uuid}.{event_type}`, the UUID without hyphens.
- Every event reaches colleagues' notifications unless `is_notifiable()`
  excludes it. An event that only records someone's own activity is excluded.
- Never raise an event again to restart work. That writes a false record.

## Background work

Workflows are the automation product tenants build. Jobs are the platform's
internal work. Tenant setup is the steps that make a tenant usable, run as
jobs. Never call internal work a workflow.

Before calling background work done, walk through: a worker restarting
mid-step, a lost event, a lost job, a retry after a partial step, the last try
failing, retention, the audit trail, caches and other sweeps.

## Gateway

The gateway is an adapter. It asks the application through a port and enforces
the answer. It holds no authorization logic of its own.

- **Deny by default.** A missing, ambiguous or failed decision is a deny. Never
  fail open to keep traffic flowing.
- Authentication and authorization are separate steps.
- Headers from clients are untrusted. Identity headers the gateway sets are
  stripped from the request first. Identity going upstream is signed or carried
  over mutual TLS.
- Upstream services are untrusted too. Do not reflect their answers into
  sign-in flows.
- Tokens, sessions and cookies are never logged, never in errors, never in span
  attributes.
- Every proxied request leaves a structured record: subject, resource, action,
  decision, policy, correlation id.
- Token checks verify the signature, `iss`, `aud`, `exp`, `nbf` and `iat` skew.
  Reject `alg: none` and pin the expected algorithm.
- Decide on metadata and stream the body. Every outbound call has a timeout.
  Every channel and queue is bounded.

## Code shape

- Return early. No `if` nested more than one level. Prefer `let ... else` and
  `match`. Avoid `else` after a return.
- Functions do one thing, at most 30 lines and four inputs besides `self`.
  Never pass an unnamed tuple to get under the limit.
- Two booleans that belong together are an enum. No boolean parameters.
- A function that changes something is named by its plain verb. A function that
  only gives back a value is named by that value.
- No comments inside function bodies. A comment elsewhere says what the code
  cannot. No emoji in source files.
- Files do not repeat their folder (`executions/rerun.rs`). Past about 12 files
  a folder is split by topic.

## Rust

- `?` for errors. No `unwrap`, `expect`, `panic!`, `todo!` or `dbg!` outside
  tests, unless a case is provably infallible and says why.
- `thiserror` in libraries with concrete variants. Keep causes with `#[source]`.
- `pub(crate)` over `pub`. Every public item has a `///` that says what the
  name does not. `# Errors` and `# Panics` are at most five lines.
- Newtype any primitive with a meaning. Never derive `Debug` on a type holding
  a secret.
- Clones are deliberate. `unsafe` needs a `// SAFETY:` comment.
- Do not silence Clippy without a comment giving the reason.

## Database

- Change `crates/ianua-infra/schema/`, then run
  `cargo run -p ianua-schema -- diff <name>`. Never write a migration by hand.
  A released migration is never edited.
- No functions, procedures, triggers or `DO` blocks. Logic lives in Rust.
- Every id column is a foreign key or says `-- no foreign key: why`.

## Tests

- Unit tests live in the file they test. Integration tests in `tests/` use only
  the public API. Names describe the behaviour.
- A bug fix starts with a failing test. Every feature has tests.
- Adapter tests use the real thing or are not written.
- Gateway and policy tests include explicit denies: missing token, expired
  token, wrong audience, unknown subject, policy store unreachable.
- Use `proptest` for parsers, token validators and policy evaluators.
- A new class of mistake earns a house rule in `ianua-audit`, with a planted
  break that proves it finds what it exists to find.

## Messages

Every message people read has a key and a translation in each language. See
`translate-messages`. Integration crates use no keys.

## Docs

The site is in `docs/`. Every claim needs evidence in the code that runs it.
Use plain short English, no em dashes. Docs describe the product, not pricing.
Concept pages are text only, and screenshots belong in guides.

## Dashboard

`dashboard/` is a Next.js app. Backend calls go through a typed service in
`src/lib/api/services` and a proxy route in `src/app/api`. Components never
`fetch` platform data, and field names come from the API's OpenAPI document.
Tenant screens exist under both `/tenants/{tenant}/...` and
`/organizations/{org}/tenants/{tenant}/...`. Every visible string goes through
next-intl. Run `npm run check-messages`, `npm run lint`, `npm run type-check`
and `npm run format:check` in `dashboard/`.

## Build and test

You need Docker, the toolchain in `rust-toolchain.toml`, nightly `rustfmt`,
`cargo-nextest`, `sqlx-cli` and `cargo-hakari`.

```sh
cargo +nightly fmt --all
SQLX_OFFLINE=true cargo clippy --all-targets --all-features -- -D warnings
SQLX_OFFLINE=true cargo nextest run --workspace --exclude ianua-scenarios
SQLX_OFFLINE=true cargo nextest run -p ianua-server -p ianua-scenarios --test <target>
cargo run --release -p ianua-audit -- check
```

Use `cargo nextest run`, not `cargo test`. Scope the build with `--lib` or
`--test <target>`, since `-E` only filters which tests run.

After a schema change, migrate a development database and refresh the query
metadata:

```sh
sqlx migrate run --source crates/ianua-infra/migrations
cargo sqlx prepare --workspace -- -p ianua-infra --all-targets --all-features
```

After adding a dependency, run `cargo hakari generate` and
`cargo hakari manage-deps --yes`.

## Git

Stage explicit paths. Never skip the secret-scanning hook, and make test values
not key-shaped instead. Never commit secrets or `.env` files.
