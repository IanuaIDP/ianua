---
name: add-gateway-stage
description: Add or change a stage in the gateway's request pipeline in ianua-zero, deny by default, with its domain kind, dispatch and deny tests. Use when a route needs a new check or transformation, e.g. "/add-gateway-stage GeoFence".
argument-hint: <StageKind name> [what it decides]
---

# Add a gateway stage

The gateway terminates the connection, finds who is calling, asks the policy
and enforces the answer. It holds no authorization logic of its own. A stage
is a thin call into a domain rule or a use case.

Copy the `GeoFence` stage, and `Waf` for a body check, in
`crates/ianua-zero/src/pipeline/stages/checks.rs`.

## Steps

1. **Domain.** Add the kind to `StageKind` in
   `crates/ianua-domain/src/domains/proxy/stages/stage/kind.rs`, its settings
   type beside it, and its name in `kind_name.rs`. The rule itself lives in
   `domains/proxy/stages/`. Its `match` arms have no catch-all, so the
   compiler lists every place that needs the new kind.
2. **Group.** Add a method to one of the five groups under
   `pipeline/stages/`: `checks`, `counters`, `identity`, `policy`, `response`.
   It returns a `StageDecision`.
3. **Dispatch.** Add the arm in `pipeline/executor/request.rs` (`decided`), or
   `response.rs` for a stage that acts on the upstream's answer.
4. **Build.** Give the group anything new in `boot/stages.rs`. Outside
   services go through an app port.
5. **API.** The stage's settings travel through `StageConfig` in
   `crates/ianua-api/src/dto/proxy.rs`. Check the contract snapshot.

## Deny by default

Any path where the decision is missing, ambiguous or errored returns deny.
Never allow on error. Each of these is a refusal:

- A lookup that fails or does not answer in time. Use `tokio::time::timeout`.
- A body the stage needed and was not given.
- A body it cannot read.
- Settings that leave it nothing to check.

A deny carries a reason for the record. The client sees only the status.

## Trust boundaries

- Client headers are untrusted. Headers the gateway sets for upstreams are
  stripped from the request first, and identity going upstream is signed.
- Upstreams are untrusted too. Do not reflect their answers into sign-in.
- Decide on metadata. Read only the bounded body prefix the pipeline asks
  for. Never buffer a whole body.
- Counters, queues and concurrency are bounded. A hung upstream never holds
  a connection for ever.
- Tokens, sessions and cookies are never logged and never in a span.

## What the gateway may write

It connects as a role with almost no rights, listed in
`crates/ianua-infra/src/postgres/foundation/roles.rs`. It inserts its request
records and its inbox events, and changes only the few columns its checks
mark. It never writes the audit trail or the outbox. Events go through the
`gateway_events` inbox. New writes use `ON CONFLICT DO NOTHING`, since the
role cannot read the tables it writes to.

Each proxied request leaves one structured record: subject, resource, action,
decision, policy, correlation id.

A cached session or decision must not outlive what it was made from. Limit
any cache by the end of the session or token behind it.

## Tests

Unit tests sit beside the group, as in `stages/checks/tests.rs`. Write the
explicit deny cases:
missing token, expired token, wrong audience, unknown subject, policy store
unreachable, plus your stage's own failure and timeout. Each returns deny.

Then a scenario under `crates/ianua-scenarios/tests/gateway/`. See
`add-scenario`. Use `eventually` for route changes to arrive, and read the
record with a precise predicate: while a route is arriving, polls leave
`no_route` records too.

## Check

```sh
cargo +nightly fmt -p ianua-domain -p ianua-zero
cargo nextest run -p ianua-domain --lib -E 'test(/proxy::stages/)'
SQLX_OFFLINE=true cargo nextest run -p ianua-zero --lib -E 'test(/pipeline::/)'
SQLX_OFFLINE=true cargo nextest run -p ianua-server -p ianua-scenarios --test gateway
SQLX_OFFLINE=true cargo clippy -p ianua-domain -p ianua-zero --all-targets --all-features -- -D warnings
cargo run --release -p ianua-audit -- check domain
```
