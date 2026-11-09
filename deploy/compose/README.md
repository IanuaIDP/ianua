# Self-hosting Ianua with Docker Compose

One machine, one organization. The `install` service makes the organization,
its first tenant and its owner from `.env`; there is no public signup.

## What you need

- A Linux machine with Docker, reachable on ports 80 and 443, and on 8444
  if connectors in other networks are to reach it.
- DNS records pointing at it:
  - `IANUA_DASHBOARD_HOST` (for example `ianua.example.com`)
  - `IANUA_API_HOST` (for example `api.ianua.example.com`)
  - `*.IANUA_APPS_DOMAIN` (for example `*.apps.example.com`), for the apps you
    put behind the proxy
- An SMTP server for invitation and password-reset emails.

## Start

```sh
cp .env.example .env
# fill in .env; generate each secret with: openssl rand -hex 32
docker compose up -d
```

The `install` service runs `ianua install` and exits. The first time, it prints
a one-time setup token that confirms the owner's address. Read it, and send it
to the API within a day:

```sh
docker compose logs install
curl -X POST https://IANUA_API_HOST/api/v1/users/confirm-installer \
  -H 'Content-Type: application/json' -d '{"token": "<the token>"}'
```

Then open `https://IANUA_DASHBOARD_HOST` and sign in as `INSTALL_OWNER_EMAIL`
with `INSTALL_OWNER_PASSWORD`. Change the password in the dashboard afterwards.

The first start builds the dashboard for your API host, which takes a few
minutes. To build the server images from this repository instead of pulling
them, run `docker compose up -d --build`.

## What runs

| Service     | What it does                                                        |
|-------------|---------------------------------------------------------------------|
| `traefik`   | Takes ports 80 and 443 and sends each request to the right service. |
| `dashboard` | The web dashboard.                                                  |
| `install`   | Makes the organization, then exits. Runs again safely.             |
| `ianua`     | The API, identity provider and background worker (`MODE=all`).      |
| `zero`      | The zero-trust proxy in front of your apps.                         |
| `postgres`  | All data.                                                           |
| `nats`      | The bus: events between the API, the worker and the proxy.          |
| `redis`     | The cache: counts and cache versions the server and proxy share.    |
| `egress`    | Only with `--profile agents`: the one way out for the services your agents call. |
| `runner`    | Only with `--profile agents`: holds one agent's key; the agent sends every request to it. |
| `connector-pki` | Makes the connector authority and the certificate of zero's connector listener on first start, then exits. |
| `connector` | Only with `--profile connector`: a connector beside the platform, to try reaching a private app. |
| `sandbox-gate` | Only with `--profile code`: the one service holding Docker, starting locked-down containers for workflows' code steps. |
| `sandbox-proxy` | Only with `--profile code`: the network filter code reaches its version's allowed hosts through. |

## Connectors

zero takes connectors' links on port 8444. A connector in another network
dials `IANUA_CONNECTOR_HOST:8444`, so point that name at this machine
before the first start: the listener's certificate names it, and it is made
once. To try one here, create a connector in your tenant, set
`CONNECTOR_TENANT`, `CONNECTOR_ENROLLMENT_CODE` and
`CONNECTOR_ALLOWED_TARGETS` in `.env`, and run
`docker compose --profile connector up -d`. To run one in another network,
see `deploy/connector/README.md`.

## Agents

`docker compose --profile agents up -d` starts the egress gateway and one
runner beside them. Before that:

1. `GATEWAY_DATABASE_PASSWORD` in `.env`, which zero needs anyway, is the
   password of the role the egress gateway signs in as too.
2. Put the egress gateway's certificate and key in `egress/tls.crt` and
   `egress/tls.key`, and the authority your services' client certificates
   chain to in `egress/ca.crt`. A service with no certificate from it is
   refused.
3. Enrol a key on the agent's credential, put its private half in
   `runner/key.pem`, and set `RUNNER_AGENT_ID`, `RUNNER_KEY_ID`,
   `RUNNER_ORGANIZATION`, `RUNNER_TENANT`, `RUNNER_UPSTREAM_HOST` (the app's
   host the agent calls) and `RUNNER_GRANTED` (what it asks for, as JSON) in
   `.env`.

Give your agent no other way out than `http://runner:8480`. Copy the `runner`
service for each further agent.

## Code steps

Workflows' code steps run in containers the `sandbox-gate` service starts.
It is the only service given Docker's socket: the server can only ask it
for a run, and it decides the locks itself. Each container has no network,
a read-only root, no rights, runs as nobody, and is held to the version's
time and memory. The gate starts only the runtimes' own images.

1. Install gVisor on this machine and register its `runsc` runtime with
   Docker (see gVisor's Docker guide). The gate refuses to start without a
   runtime. To use another runtime, set `SANDBOX_CONTAINER_RUNTIME`.
2. Set `SANDBOX_GATE_SOCKET=/run/ianua-sandbox/gate.sock` in `.env`.
3. Make the network filter's key with `openssl rand -hex 32`, and set it as
   `SANDBOX_PROXY_KEY` in `.env`, with
   `SANDBOX_PROXY_ADDRESS=172.31.0.2:3128`.
4. Run `docker compose --profile code up -d`.

Without these steps, code steps fail at once as not run.

A version reaches no network unless it names its allowed hosts. Its code
then reaches those hosts, and only those, through the `sandbox-proxy`
service: over encrypted connections to port 443, never to a private
address. Code containers join a network that reaches nothing but that
service. Without step 3, a version naming hosts does not run.

## Your own domains

`TRUSTED_DOMAINS` lists domains you own. Any name at or beneath one of them can
be added to a tenant in the dashboard and is trusted at once, with no DNS record
to prove ownership. Names outside the list still ask for the usual `TXT` record.

Once a name is added and points at this machine, a certificate for it is
requested from Let's Encrypt, which needs to reach it on port 80. On a network
Let's Encrypt cannot reach, use the `IANUA_APPS_DOMAIN` names instead and replace
the proxy's default certificate with a wildcard for that domain (see below).

## The proxy's default certificate

`zero` answers every name it has no certificate for with a self-signed default,
made once into the `zero-certs` volume. To use a real wildcard certificate for
`*.IANUA_APPS_DOMAIN`, copy it and its key over the default:

```sh
docker run --rm -v ianua_zero-certs:/certs -v "$PWD":/in alpine \
  sh -c 'cp /in/wildcard.crt /certs/default.crt && cp /in/wildcard.key /certs/default.key'
docker compose restart zero
```

## Things that are read once

`INSTALL_*` settings are read by the `install` service alone, to make the
organization. Every other command refuses them, so the compose file gives them
to `install` only, and the owner's first password never stays in the server's
environment. Changing them later does nothing; change the owner and names in
the dashboard.

Exports and logos live in the `files` volume. Back it up with the database.

`ENCRYPTION_KEY` must never change after first start. It encrypts stored keys
and certificates, and a different key cannot read them.

## Backups

Everything worth keeping is in the `postgres` volume:

```sh
docker compose exec postgres pg_dump -U ianua ianua > ianua.sql
```

Keep `.env` with it — the backup is unreadable in places without
`ENCRYPTION_KEY`.
