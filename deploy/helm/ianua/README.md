# Ianua Helm chart

Deploys Ianua to Kubernetes (tested against Linode LKE and DigitalOcean DOKS):

- **server**: the control-plane API (`MODE=api`), behind an Ingress
- **worker**: jobs, sweeps, the outbox relay and the event consumers
  (`MODE=worker`); its probes and metrics are on the internal port
- **zero**: the zero-trust data-plane gateway, behind a cloud LoadBalancer
- hook Jobs running the server's one-off commands: **migrate** (`ianua
  migrate`) always, **install** (`ianua install`) for a self-hosted
  installation, **first-operator** (`ianua operator create --email ...`) and
  **demo** (`ianua demo`) when turned on
- bundled **NATS** (JetStream, the bus) and **Redis** (the cache); optional
  bundled **Postgres**; a volume for the file store

## Prerequisites

- A Kubernetes cluster (LKE or DOKS) and `kubectl` + `helm` 3.
- An **Ingress controller** (e.g. ingress-nginx) for the admin API. The gateway
  uses a `LoadBalancer` Service directly — on LKE/DOKS that provisions a Linode
  NodeBalancer / DigitalOcean Load Balancer automatically, no ingress needed.
- **cert-manager** (for automatic TLS certificates) if you want Let's Encrypt
  certs issued for you. See "Internet access & TLS" below.
- **Postgres.** Either a **managed** database (create one in the Linode or
  DigitalOcean console and set `secrets.databaseUrl`), or the **bundled
  CloudNativePG** cluster (`postgresql.enabled=true`). The bundled option needs
  the CloudNativePG operator installed once per cluster:

  ```sh
  kubectl apply --server-side -f \
    https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.25/releases/cnpg-1.25.1.yaml
  ```

  CNPG then provisions the database, handles failover and rolling upgrades, and
  publishes the connection string the app reads automatically — no manual DB
  config. When enabled, leave `secrets.databaseUrl` empty.

## 1. Generate secrets

Each key is exactly 32 random bytes, as 64 hex characters or base64. Left
empty, the chart generates them and keeps them on upgrade.

```sh
HMAC=$(openssl rand -hex 32)
EVENTS=$(openssl rand -hex 32)           # must differ from HMAC
ENC=$(openssl rand -hex 32)
```

## 2. Write a values file

```yaml
# my-values.yaml
image:
  tag: "<commit-sha>"        # pin to an immutable tag, not "latest"

config:
  baseDomain: ianua.io
  webauthn:
    rpId: ianua.io
    rpOrigin: https://ianua.io
  email:
    from: noreply@ianua.io
    fromName: Ianua
    provider: mailgun
    mailgun:
      domain: ianua.io   # your Mailgun sending domain
      region: eu         # us | eu — match your Mailgun account region

secrets:
  # The app's role: owns nothing, confined by row-level security.
  databaseUrl: "postgres://ianua_app:pass@managed-db-host:25060/ianua?sslmode=require"
  # The database owner: migrates and makes the roles. Worker and jobs only.
  migrationDatabaseUrl: "postgres://doadmin:pass@managed-db-host:25060/ianua?sslmode=require"
  # The audit purge's own role, which the migration makes. Worker and jobs only.
  auditPurgeDatabaseUrl: "postgres://ianua_audit_purge:pass@managed-db-host:25060/ianua?sslmode=require"
  hmacSecret: "<paste $HMAC>"
  eventSigningSecret: "<paste $EVENTS>"
  encryptionKey: "<paste $ENC>"
  mailgunApiKey: "<your Mailgun API key>"

firstOperator:
  enabled: true
  email: you@example.com

server:
  ingress:
    host: api.ianua.io
    tls:
      secretName: ianua-api-tls
```

## 3. Install

```sh
helm upgrade --install ianua deploy/helm/ianua \
  -n ianua --create-namespace \
  -f my-values.yaml
```

Helm runs the migrate Job, then the first-operator Job, and rolls out the
deployments. Read the first operator's generated password:

```sh
kubectl get secret -n ianua ianua-first-operator \
  -o jsonpath='{.data.OPERATOR_PASSWORD}' | base64 -d; echo
```

Once they have signed in, set `firstOperator.enabled=false`.

## 4. DNS

```sh
# Gateway load-balancer address (live tenant traffic):
kubectl get svc -n ianua ianua-zero -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

Point a wildcard `*.<baseDomain>` record at the gateway LB, and the
`server.ingress.host` record at your ingress controller.

## Internet access & TLS

There are two public entry points, with different TLS handling.

**Admin API (`server`) — via Ingress + cert-manager.** It is exposed through an
Ingress on a single host (`server.ingress.host`). Install an ingress controller
and cert-manager once per cluster:

```sh
helm upgrade --install ingress-nginx ingress-nginx \
  --repo https://kubernetes.github.io/ingress-nginx -n ingress-nginx --create-namespace

helm upgrade --install cert-manager cert-manager \
  --repo https://charts.jetstack.io -n cert-manager --create-namespace \
  --set crds.enabled=true
```

Create a ClusterIssuer (Let's Encrypt HTTP-01), then set
`server.ingress.certManagerClusterIssuer=letsencrypt-prod`. cert-manager issues
the cert into `server.ingress.tls.secretName` automatically. Point DNS for the
host at the ingress controller's LoadBalancer address.

To skip the ingress entirely, set `server.ingress.enabled=false` and
`server.service.type=LoadBalancer` — the API gets its own cloud LB (you then
terminate TLS yourself).

**Gateway (`zero`) — LoadBalancer, wildcard TLS.** It serves per-tenant traffic
on `*.<baseDomain>` through its own cloud LoadBalancer (no ingress). For HTTPS it
needs a **wildcard** certificate, which HTTP-01 cannot issue — use cert-manager
with a **DNS-01** solver for your DNS provider (or supply a wildcard cert). Put
it in a TLS secret and set:

```yaml
zero:
  tls:
    secretName: ianua-wildcard-tls   # contains tls.crt / tls.key for *.baseDomain
  service:
    port: 443
```

The gateway then terminates TLS itself. Point a wildcard `*.<baseDomain>` DNS
record at the gateway LoadBalancer address.

## Operations

```sh
# Upgrade (re-runs migrations via the pre-upgrade migrate Job):
helm upgrade ianua deploy/helm/ianua -n ianua -f my-values.yaml

# Render manifests without applying:
helm template ianua deploy/helm/ianua -f my-values.yaml

# Uninstall (managed/bundled Postgres data is NOT deleted automatically):
helm uninstall ianua -n ianua
```

## Notes

- **Postgres**: use a managed database, or the bundled CloudNativePG cluster
  (`postgresql.enabled=true`, defaults to 3 HA instances — set
  `postgresql.instances=1` for evaluation). CNPG requires its operator (see
  Prerequisites). With CNPG enabled, `DATABASE_URL` is sourced from the
  operator-generated `*-pg-app` Secret automatically.
- **Logins:** API pods hold only `DATABASE_URL`. `MIGRATION_DATABASE_URL`
  and `AUDIT_PURGE_DATABASE_URL` go to the worker and the hook Jobs alone, and
  the server refuses to start an API pod that holds them. With `dns.enabled`,
  `NAMESERVER_DATABASE_URL` goes to the worker and the Jobs, which make its
  role, and to the nameserver pods, which hold no other login and none of the
  chart Secret's keys. With an external database set
  `secrets.nameserverDatabaseUrl`.
- **Code steps:** with `codeSandboxes.enabled=true`, each run of a
  workflow's code step gets a pod of its own in a namespace holding nothing
  else (`<release namespace>-code` unless `codeSandboxes.namespace` names
  one). The chart makes that namespace at the `restricted` pod security
  level, a network policy letting no traffic in or out, a quota over every
  run together, and an account of the worker's own that may only create,
  get, list, update, attach to and delete pods there; the API servers keep
  the shared account. Each worker keeps `codeSandboxes.warm.perKind` pods
  of each runtime and memory size waiting once it has run (2 by default,
  0 for none), for up to `codeSandboxes.warm.minutes`; they count against
  the quota. With `codeSandboxes.network.enabled=true`, a version naming
  allowed hosts reaches them through the network filter (the
  `sandbox-proxy` deployment), and nothing else: its pods may reach the
  filter alone, and the filter reaches public addresses on port 443 alone.
  The chart makes the key the worker and the filter share. Install gVisor on the nodes and its RuntimeClass first
  (`codeSandboxes.runtimeClassName`, `gvisor` by default): in production
  the server refuses to run code without one. The CNI must enforce
  NetworkPolicy. Without this, code steps fail as `code_not_run`.
- **Files:** exports and logos live on the `files` volume by default, which
  the server and the worker share. With more than one server replica, use a
  `ReadWriteMany` volume or `files.store=objects`.
- **File links** are made under `config.appBaseUrl` at `/api/v1/files/...`, so
  whatever serves that address must send `/api/v1` to the API.
- **TLS:** the API Ingress expects the TLS secret named in
  `server.ingress.tls.secretName`. Use cert-manager or provide it manually.
- See [`values.yaml`](values.yaml) for every option.
