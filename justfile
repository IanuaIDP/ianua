# Justfile for the ianua workspace.
#
# Install `just` (https://just.systems) then run `just` to list recipes.
# The test recipes mirror the CI jobs exactly, so green locally means green in CI.

set shell := ["bash", "-c"]
set dotenv-load := true

# Nextest profile for the e2e suite (one shared container, oversubscribed threads).
e2e_profile := "ci-e2e"

# Kubernetes namespaces for the cluster recipes.
ns := "ianua"
gt_ns := "glitchtip"

# List all recipes (default).
default:
    @just --list

# ── Setup ─────────────────────────────────────────────────────────

# Install the dev tooling this repo expects.
[group('setup')]
install-tools:
    cargo install cargo-nextest --locked

# ── Test ──────────────────────────────────────────────────────────

# Workspace tests except e2e — mirrors the CI `test` job.
[group('test')]
test:
    cargo nextest run --workspace --exclude ianua-scenarios

# End-to-end scenarios against the shared Postgres, cache and bus — mirrors the CI `test-e2e` job.
[group('test')]
test-e2e:
    cargo nextest run -p ianua-scenarios --profile {{e2e_profile}}

# Everything: workspace tests, then e2e.
[group('test')]
test-all: test test-e2e

# Only the ianua-infra integration (repo) tests.
[group('test')]
test-infra:
    cargo nextest run -p ianua-infra

# Tests of a single crate, e.g. `just test-crate ianua-domain`.
[group('test')]
test-crate crate:
    cargo nextest run -p {{crate}}

# Tests whose name matches a regex, e.g. `just test-one rotate_key`.
[group('test')]
test-one pattern:
    cargo nextest run -E 'test(/{{pattern}}/)'

# Re-run workspace tests on every change (needs `cargo-watch`).
[group('test')]
watch:
    cargo watch -x 'nextest run --workspace --exclude ianua-scenarios'

# ── Quality ───────────────────────────────────────────────────────

# Format the whole workspace.
[group('quality')]
fmt:
    cargo fmt --all

# Check formatting only — mirrors the CI `fmt` job.
[group('quality')]
fmt-check:
    cargo fmt --all --check

# Lint with all warnings denied — mirrors the CI `clippy` job.
[group('quality')]
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Type-check the whole workspace without building binaries.
[group('quality')]
typecheck:
    cargo check --workspace --all-targets

# Auto-fix what clippy and rustfmt can.
[group('quality')]
fix:
    cargo clippy --all-targets --all-features --fix --allow-dirty --allow-staged
    cargo fmt --all

# Quick pre-commit gate: format check, lint, non-e2e tests.
[group('quality')]
pre-commit: fmt-check lint test

# Full CI gate locally: format check, lint, all tests including e2e.
[group('quality')]
ci: fmt-check lint test test-e2e

# ── Build & run ───────────────────────────────────────────────────

# Build the whole workspace (debug).
[group('build')]
build:
    cargo build --workspace

# Build optimized release binaries.
[group('build')]
release:
    cargo build --release

# Serve in a given MODE (api|worker|all); defaults to all. One-off commands
# run as `cargo run -p ianua-server -- migrate|install|demo`.
[group('build')]
run mode="all":
    MODE={{mode}} cargo run -p ianua-server

# Build and open the workspace docs.
[group('build')]
doc:
    cargo doc --no-deps --open

# ── Docker / test database ────────────────────────────────────────

# Remove the shared test Postgres container left behind after a test run.
[group('docker')]
clean-db:
    -docker ps -aq --filter "label=ianua-test=1" | xargs -r docker rm -f
    -docker ps -aq --filter "label=ianua-e2e=1"  | xargs -r docker rm -f
    @echo "test containers removed"

# ── Cluster (kubectl / helm) ──────────────────────────────────────

# Port-forward the API server to http://localhost:PORT (service :80).
[group('cluster')]
pf-api port="8080":
    @echo "API → http://localhost:{{port}}  (docs at /api/v1/reference)"
    kubectl -n {{ns}} port-forward svc/ianua-server {{port}}:80

# Port-forward the GlitchTip error UI to http://localhost:PORT.
[group('cluster')]
pf-glitchtip port="8080":
    @echo "GlitchTip → http://localhost:{{port}}"
    kubectl -n {{gt_ns}} port-forward svc/glitchtip-web {{port}}:80

# Tail logs for a component (server|worker|zero); defaults to server.
[group('cluster')]
logs component="server":
    kubectl -n {{ns}} logs -f deploy/ianua-{{component}}

# Tail only ERROR lines — every 5xx, panic, and internal error.
[group('cluster')]
logs-errors component="server":
    kubectl -n {{ns}} logs -f deploy/ianua-{{component}} | grep '"level":"ERROR"'

# Install or upgrade the self-hosted GlitchTip error UI.
# e.g. `just glitchtip-deploy glitchtip.ianua.io $(openssl rand -hex 32) $(openssl rand -hex 16)`
[group('cluster')]
glitchtip-deploy domain secret_key postgres_password:
    helm upgrade --install glitchtip deploy/helm/glitchtip \
        -n {{gt_ns}} --create-namespace \
        --set domain={{domain}} \
        --set secretKey={{secret_key}} \
        --set postgres.password={{postgres_password}} \
        --wait

# ── Maintenance ───────────────────────────────────────────────────

# Remove cargo build artifacts.
[group('maintenance')]
clean:
    cargo clean

# Remove build artifacts and leftover test containers.
[group('maintenance')]
clean-all: clean clean-db
