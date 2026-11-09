# The ianua connector

The connector is a small program you run inside your own network. It lets
people reach a private app, such as a wiki at `10.0.0.5`, through the ianua
gateway. Nothing in your network has to accept a connection from the
internet: the connector dials out to the gateway and holds that link open.
The gateway sends each connection for your app back down the link, and
the connector opens it to your app from inside.

The connector only ever opens connections to the targets you list. It
refuses everything else, private addresses included.

## Before you start, in ianua

1. Open your tenant in the dashboard and go to **Connectors**.
2. Add a connector. Give it a name, and the networks and names it may be
   asked to reach.
3. Copy the one-time enrollment code. It is shown once and is good for one
   hour.
4. Point the service for your app at the connector.

You also need three values from whoever runs your ianua platform:

- the API address, such as `https://api.ianua.example`
- your organization and tenant slugs, such as `acme/main`
- the gateway's connector address, such as `connect.ianua.example:8444`

## Run it with Docker

```sh
docker volume create ianua-connector

docker run -d --name ianua-connector --restart unless-stopped \
  --read-only --tmpfs /tmp \
  -v ianua-connector:/var/lib/ianua-connector \
  -e CONNECTOR_API_URL=https://api.ianua.example \
  -e CONNECTOR_TENANT=acme/main \
  -e CONNECTOR_GATEWAY_ADDRESS=connect.ianua.example:8444 \
  -e CONNECTOR_ENROLLMENT_CODE='the code you copied' \
  -e CONNECTOR_ALLOWED_TARGETS=wiki.corp.internal:443,10.0.0.5:443 \
  ghcr.io/ianuaidp/ianua-connector:latest
```

The volume keeps the connector's key and certificate. Keep it: without it
the connector cannot prove who it is, and you must add a new connector.

Once the connector has enrolled, the code is spent. You can remove
`CONNECTOR_ENROLLMENT_CODE` from later starts.

## Run it with systemd

Copy the `ianua-connector` binary to `/usr/local/bin`, then create a user
and a settings file:

```sh
useradd --system --home /var/lib/ianua-connector --shell /usr/sbin/nologin ianua-connector
install -d -m 700 -o ianua-connector -g ianua-connector /var/lib/ianua-connector
install -m 600 -o root -g root /dev/null /etc/ianua-connector.env
```

`/etc/ianua-connector.env`:

```sh
CONNECTOR_API_URL=https://api.ianua.example
CONNECTOR_TENANT=acme/main
CONNECTOR_GATEWAY_ADDRESS=connect.ianua.example:8444
CONNECTOR_ENROLLMENT_CODE=the code you copied
CONNECTOR_ALLOWED_TARGETS=wiki.corp.internal:443,10.0.0.5:443
```

`/etc/systemd/system/ianua-connector.service`:

```ini
[Unit]
Description=ianua connector
Wants=network-online.target
After=network-online.target

[Service]
User=ianua-connector
EnvironmentFile=/etc/ianua-connector.env
ExecStart=/usr/local/bin/ianua-connector
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ianua-connector
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now ianua-connector
journalctl -u ianua-connector -f
```

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `CONNECTOR_API_URL` | none, required | The ianua API. It must use HTTPS, unless the API runs on the same machine. |
| `CONNECTOR_TENANT` | none, required | Your organization and tenant slugs, as `organization/tenant`. |
| `CONNECTOR_GATEWAY_ADDRESS` | none, required | The gateway's connector address, as `host:port`. The gateway's certificate is checked against this host. |
| `CONNECTOR_ENROLLMENT_CODE` | none | The one-time code. Needed only until the connector has enrolled. |
| `CONNECTOR_ENROLLMENT_CODE_FILE` | none | A file holding the code, instead of the setting above. |
| `CONNECTOR_ALLOWED_TARGETS` | none, required | The only targets the connector opens connections to. See below. |
| `CONNECTOR_STATE_DIR` | `/var/lib/ianua-connector` | Where the key and certificate are kept. |
| `CONNECTOR_MAX_LINKS` | `8` | The most gateway addresses linked at once. |
| `CONNECTOR_MAX_STREAMS` | `256` | The most connections carried at once on one link. |
| `CONNECTOR_DIAL_TIMEOUT_SECONDS` | `10` | How long opening a connection to a target may take. |
| `CONNECTOR_IDLE_TIMEOUT_SECONDS` | `300` | A connection that carries nothing for this long is closed. |
| `CONNECTOR_HANDSHAKE_TIMEOUT_SECONDS` | `10` | How long reaching the gateway and the TLS handshake may take. |
| `CONNECTOR_REQUEST_TIMEOUT_SECONDS` | `30` | How long one call to the API may take. |
| `CONNECTOR_RESOLVE_SECONDS` | `30` | How often the gateway's name is looked up again. |
| `CONNECTOR_BACKOFF_MAX_SECONDS` | `60` | The longest wait before trying again after a failure. |
| `CONNECTOR_SHUTDOWN_GRACE_SECONDS` | `10` | How long a stop waits for open connections. |
| `LOG_LEVEL` | `info` | What is logged. |
| `LOG_FORMAT` | `json` | `json` or `text`. |
| `APP_ENV` | `production` | `production` or `development`. |

The connector refuses to start if it is given any secret of the ianua
platform itself, such as `HMAC_SECRET`, `ENCRYPTION_KEY`, a database login,
`BUS_URL`, `CACHE_URL` or the connector authority's key. None of them
belongs in your network.

## The allow list

`CONNECTOR_ALLOWED_TARGETS` is a comma-separated list. Each entry has a
port, and only that port is allowed:

- a name: `wiki.corp.internal:443`
- an address: `10.0.0.5:443`, or `[fd00::5]:443` for IPv6
- a network: `10.0.0.0/24:8080`

The rules:

- A target that is not on the list is refused, and nothing is dialled.
- An address is allowed only when it is listed, or inside a listed
  network. Listing `wiki.corp.internal:443` does not allow `10.0.0.5:443`,
  even if the wiki lives there.
- A listed name may lead to any address, except loopback, link-local
  (such as `169.254.169.254`), unspecified and multicast addresses. Those
  are allowed only when the address itself is listed.
- The gateway also holds its own list for the connector, the scope you set
  in the dashboard. A connection must pass both.

## What is in the state folder

| File | What it is |
| --- | --- |
| `key.pem` | The connector's private key. It is made on the first start, never leaves the machine, and is never replaced. |
| `certificate.pem` | The certificate for that key, signed by the platform. It lasts one day. |
| `authority.pem` | The platform's connector authority. The gateway's certificate is checked against it. |
| `connector.json` | Which connector this is, and when its certificate ends and should be renewed. |

The folder and the key must be readable by the connector's user alone. The
connector refuses to start if other users can read them.

## Renewal

Each certificate lasts one day. In its last eight hours the connector asks
the API for a new one, for the same key. If the API cannot be reached, the
connector tries again, waiting longer each time. Links already open keep
running. If the certificate runs out before a renewal works, the connector
opens no new links until one does.

## Revocation

When you revoke the connector in the dashboard, the gateway closes its
links within seconds, and your app behind it can no longer be reached.
At its next renewal the API refuses the connector, and it stops with a
message saying so. A revoked connector is never trusted again: add a new
one and enroll it with a new code.

## When something goes wrong

- **"the API refused the enrollment"**: the code was used already, is
  older than an hour, or its connector was revoked. Make a new code.
- **"the connector has not enrolled yet"**: set the enrollment code.
- **"can be read by other users"**: run `chmod 700` on the folder and
  `chmod 600` on `key.pem`.
- **"the TLS handshake with the gateway failed"**: check the gateway
  address. The host must be the name the gateway's certificate was made
  for.
