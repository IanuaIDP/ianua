---
name: add-endpoint
description: Serve a use case over HTTP in ianua-api - handler, path and body extractors, DTO, route, OpenAPI entry and contract snapshot. Use when a use case needs an endpoint, e.g. "/add-endpoint operator POST /operators/dead-jobs/{id}/retry".
argument-hint: <context> <METHOD> <path>
---

# Add an endpoint

The API maps HTTP to a use case and back. It holds no rule and asks no right.
Copy `crates/ianua-api/src/handlers/operator/jobs.rs`, the `dead-jobs` lines in
`routes/operator.rs`, `DeadJobPath` in `extractors/paths/operator.rs`, and
`DeadJobResponse` in `dto/operator.rs`.

## Steps

1. **Build the use case.** Add a field and its construction to the group's
   state in `crates/ianua-assembly/src/<context>.rs`.
2. **Path.** A struct in `extractors/paths/<context>.rs` with private fields
   and a method returning the domain type. A value that does not parse is a
   `422` through `ApiError::validation`.
3. **DTO** in `dto/<context>.rs`. Request and response types live here, and
   the domain never derives for HTTP. Map with `From` or `TryFrom`. Secrets
   appear in a response once, when made, and never in `Debug`. Times use
   `#[serde(with = "time::serde::rfc3339")]`.
4. **Handler** in `handlers/<context>/`:
   - `#[utoipa::path(...)]` with every status it can answer.
   - The `///` is the API reference. First line a short title, then what it
     returns, what each refusal means, what it records, and who may call it.
   - The body only extracts, calls `execute`, and maps. No loose functions in
     `handlers/`: parsing goes to `extractors/`, mapping to `dto/`, extra
     reads into the use case's result.
   - Take bodies with `crate::extractors::json::Json`, and queries and forms
     with the platform's extractors. The framework's own are refused.
   - The caller comes from `extractors/callers.rs`.
5. **Route.** Add `.route(...)` in `routes/<context>.rs` and the handler to
   `paths(...)` in that file's `#[openapi]`, with new schemas in `components`.
6. **Lists** take `Paging`, and answer `PageResponse` with `next_cursor`.
   Never offsets.
7. **Docs.** Fix the pages under `docs/src/content/docs/` that describe the
   behaviour. Every claim needs evidence in the handler or use case that
   runs it.

## Errors

`crates/ianua-api/src/error/mod.rs` maps every `AppError` to a status and a
code. `NotFound` is 404, `Conflict` is 409. Do not map errors in a handler.

A refused request and an absent one must look alike when the difference
tells a stranger something. The use case decides this. The handler does not
soften or sharpen it.

Never build an error body from a token, a session or an upstream's answer.

## Keep the JSON

A refactor never changes the API's JSON. A field renamed or an enum value
dropped breaks every client, even when all server tests pass.
`crates/ianua-api/tests/contract/public.json` holds the whole document. A
diff there is a change to the public API, so read it line by line. Rewrite it
only when the change is the one you meant.

Before removing anything as unused, search every crate and the dashboard.

## Tests

HTTP tests live in `crates/ianua-api/tests/api/`, grouped by context, and
cover the status, the JSON and one refusal for each kind. For a journey
across the whole platform, use the `add-scenario` skill.

## Check

```sh
cargo +nightly fmt -p ianua-api
IANUA_WRITE_SNAPSHOTS=1 cargo nextest run -p ianua-api --test contract
git diff --stat crates/ianua-api/tests/contract
cargo nextest run -p ianua-api --test api
cargo clippy -p ianua-api --all-targets --all-features -- -D warnings
cargo run --release -p ianua-audit -- check api
```
