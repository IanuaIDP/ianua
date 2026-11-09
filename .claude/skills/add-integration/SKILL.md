---
name: add-integration
description: Add a step to a workflow integration or add a new outside service under integrations/, described with the integrations SDK. Use when workflows need a new operation or service, e.g. "/add-integration step github lock-issue" or "/add-integration service zendesk".
argument-hint: step <service> <operation-key> [what it does] | service <name>
---

# Add an integration

Read `integrations/README.md` end to end. It is the full guide and holds the
table of published API descriptions. `integrations/github/` is the example to
copy. The SDK in `integrations/core/src/rest/` is what every service is
described with: `service/` for the whole integration, `operation.rs` for a
step, `access/` for how an account reaches the service.

## Look first

For each call, read the service's own API documentation: the verb and path,
which parameters are required, what success looks like, and how it says no.
Never guess a parameter or a path. Where the service publishes an OpenAPI
description, download it. The check against it settles what the documentation
leaves open.

## A step

1. **Choose its `effect` honestly.** `DeclaredAction::Declared(ActionClass::...)`
   with `Read`, `Write`, `Communicate`, `Delete`, `Configure`, `Financial` or
   `Admin`. Use `DeclaredAction::Undeclared` when the effect depends on
   something else, such as starting a pipeline. High-risk kinds need an
   approval before them in a workflow, so a wrong kind removes a safeguard.
2. **Add the `Operation`** to the topic file in
   `integrations/<service>/src/operations/`: key in lowercase words with
   dashes, title, description, verb, path, each field with its place, kind,
   `sent_as` name and meaning, and outputs at their paths.
3. **Test the request** in `operations/mod.rs`: the exact address and body
   from sample inputs, and one refusal. The `misdescribed` test holds it to
   the SDK's rules.
4. **Refresh the description extract**, where the service publishes one, as
   the README's step 4 says. Commit it with the step.
5. **Prove it end to end** when it matters: a scenario in
   `crates/ianua-scenarios/tests/accounts/automate_work/integrations/` against
   an `upstreams::CannedApp` stand-in that answers the service's probe.
6. **Document it** in the service's table in
   `docs/src/content/docs/architecture/infrastructure/integrations.mdx`.

## A service

Follow "Adding a service" in the README in order:

1. Copy `github/` to `integrations/<service>/`, rename the crate
   `ianua-integration-<service>`, and add it to the workspace.
2. Fill `RestServiceParams` in `src/lib.rs`: `profile`, `access`, `headers`,
   `probe` (the cheapest request that proves a credential), `answers`.
   `assets/icon.svg` holds shapes only.
3. Write its steps and the `misdescribed` test, plus the API description
   check when one is published.
4. In `crates/ianua-server`: a feature and optional dependency, settings in
   `src/config/serving/integrations.rs`, and a line in `outside_services` in
   `src/platform/providers.rs`.
5. Run `cargo fetch` once for a new dependency, then
   `cargo hakari generate` and `cargo hakari manage-deps --yes`.
6. Document its settings in `docs/src/content/docs/reference/configuration.mdx`.

Only a service that is not REST implements `Integration` itself.

## Rules every step keeps

- Deny by default. Anything missing, of the wrong kind or unsafe to place
  fails before a call is sent.
- The token goes only to the service's own API, from settings, or to a site
  the deployment allows. A step never names an address. No redirect is
  followed. The token header is sensitive and never logged.
- Turned away only when nothing happened (`429`, `503`). Anything that may
  have acted fails. A `203` sign-in page is never success.
- Reasons are the integration's own words. No `message!` keys in these
  crates.
- Every public item has a doc comment. No comments inside function bodies.

## Check

```sh
cargo +nightly fmt -p ianua-integration -p ianua-integration-<service>
cargo nextest run -p ianua-integration -p ianua-integration-<service> --lib
SQLX_OFFLINE=true cargo nextest run -p ianua-server -p ianua-scenarios --test automate_work -E 'test(/integrations::/)'
cargo clippy -p ianua-integration -p ianua-integration-<service> --all-targets --all-features -- -D warnings
cargo run --release -p ianua-audit -- check integrations
```
