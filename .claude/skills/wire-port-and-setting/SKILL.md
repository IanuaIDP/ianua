---
name: wire-port-and-setting
description: Connect a port to its adapter through ianua-assembly and ianua-server, and add a configuration setting from the environment to the type it configures. Use when a new adapter or environment variable must reach a use case, e.g. "/wire-port-and-setting EmbeddingModel" or "/wire-port-and-setting setting WORKFLOW_RUNS_KEPT_DAYS".
argument-hint: <port name> | setting <NAME>
---

# Wire a port or a setting

Dependencies point inward. The domain knows nothing of the app, the app
nothing of adapters, and adapters nothing of each other. Only the composition
roots know everything: `crates/ianua-assembly`, `crates/ianua-server`, and
`crates/ianua-zero/src/boot` for the gateway.

## A port

1. **Define it next to who needs it**, in
   `crates/ianua-app/src/ports/<context>`. It uses `#[async_trait]` and speaks
   domain types and `DomainError` only. No `sqlx::Error`, no
   `reqwest::Error`, no `serde_json::Value`.
2. **Add a fake** in `crates/ianua-app/src/test_support/<context>`.
3. **Write the adapter** in `ianua-infra`. Folders and types are named by
   role, never by product: `cache/`, `bus/`, `CacheTokenLookup`,
   `BusMessagePublisher`. A server that speaks the protocol can be swapped.
   A stand-in for a provider not set up is `No` plus the port, as
   `NoGeolocator` and `NoPaymentProvider`. A stand-in answers honestly: a
   refused checkout is a `Conflict`, not a 500.
4. **Every outbound call has a timeout.** Every channel and queue is bounded.
5. **Add a field** to `Adapters` in `crates/ianua-assembly/src/deps.rs`, one
   field per port, named after it.
6. **Use it** in the use case's `<Name>Ports`, built in
   `crates/ianua-assembly/src/<context>.rs`.
7. **Fill it** once in `crates/ianua-server/src/assembly/adapters.rs`. Worker
   parts are in `crates/ianua-server/src/worker/parts.rs`, and the gateway's
   in `crates/ianua-zero/src/boot/`.

Something built ahead of its user is dead code. Do not merge it unused, and
never add `#[allow(dead_code)]`.

## A setting

1. **Read it** in `crates/ianua-server/src/config/serving/<topic>.rs`
   through `ianua_boot::env::Env`. The reader names its source:
   `vars.seconds("JOB_TIMEOUT_SECONDS", MINUTE)`. Others are `number_in`,
   `days`, `required`, `optional`, `parsed`. Refuse a value that can do harm,
   as `workflow_runs_kept` in `serving/worker.rs` refuses too few days.
2. **A bad value stops startup**, naming the variable. It is never replaced
   by the default.
3. **Turn it into the domain's type** in
   `crates/ianua-server/src/assembly/settings.rs`, and refuse with
   `ConfigError::rejected` if that type refuses it.
4. **Secrets** may also come from `NAME_FILE`. A refusal never repeats one.
   A process reads only the secrets it needs: the gateway never reads
   `EVENT_SIGNING_SECRET`.
5. **Name it by role**: `CACHE_URL`, `BUS_URL`.
6. **Tell operators.** Add it to
   `docs/src/content/docs/reference/configuration.mdx`, and to
   `deploy/helm/ianua` and `deploy/compose` when an install must set it.
   A default that deletes data needs a note for people upgrading.

Fail closed. A setting left out must never open anything: a certificate
authority that cannot be read stops startup rather than trusting everything.

A problem in test setup is fixed in the test setup. Do not add a platform
setting to make a test easier. Test values go in
`crates/ianua-scenarios/src/stack/settings.rs`, or through
`Profile::with("NAME", "value")` for one scenario.

## Check

```sh
cargo +nightly fmt -p ianua-assembly -p ianua-server
SQLX_OFFLINE=true cargo nextest run -p ianua-server --lib -E 'test(/config/)'
SQLX_OFFLINE=true cargo clippy -p ianua-app -p ianua-assembly -p ianua-infra -p ianua-server --all-targets --all-features -- -D warnings
cargo run --release -p ianua-audit -- check infra
cargo run --release -p ianua-audit -- check app
```

Add a scenario when the setting changes what someone sees.
