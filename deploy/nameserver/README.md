# Running the nameservers on their own hosts

Two small instances answering DNS for every hostname tenants have delegated,
fed by the control plane over a mutually authenticated gRPC stream. The
stream sends only the zones whose delegation was proved, the same ones the
in-cluster nameservers answer for.

Nothing here is automated. These hosts sit outside the cluster and nothing in
it manages them — which is the trade for not paying $300/mo in premium
NodeBalancers to get UDP into Kubernetes.

## What talks to what

```
             ┌──────────────── cluster ────────────────┐
             │                                         │
  Postgres ──┼──► ianua-server ──► gRPC listener :50051│
             │                            │            │
             └────────────────────────────┼────────────┘
                                          │  mutual TLS, private CA
                            ┌─────────────┴─────────────┐
                            ▼                           ▼
                      ns1 (Nanode)               ns2 (Nanode)
                            │                           │
                            └──────► :53 UDP + TCP ◄─────┘
                                          ▲
                                          │
                                    the open internet
```

Reading it as a sequence:

```
tenant edits a DNS record
  → ianua-server writes it to Postgres
  → the gRPC listener notices within 2s
  → pushes the whole catalog down both open streams
  → each nameserver swaps its catalog atomically
  → next query gets the new answer
```

And when a nameserver starts:

```
ianua-dns starts
  → binds :53 immediately, refusing every query
  → dials the control plane, presenting its client certificate
  → control plane checks our authority issued it
  → first catalog arrives
  → starts answering
```

It binds before it has any zones on purpose. A closed port reads to the
outside as the whole delegation having vanished; REFUSED is a resolver's cue
to try the other nameserver and come back.

## What each host holds

Only what it needs to answer DNS:

| | |
|---|---|
| `/usr/local/bin/ianua-dns` | the binary |
| `/etc/ianua/dns.env` | its configuration |
| `/etc/ianua/pki/nsN-cert.pem` + `-key.pem` | this host's identity |
| `/etc/ianua/pki/ca-cert.pem` | who it trusts |

No database credential, no NATS credential, nothing that reads anything but
DNS records. That is the point of the gRPC link rather than a VPN back to
Postgres: this host answers the open internet unauthenticated over UDP, so if
it is ever taken, what the attacker gains is a copy of public DNS data.

## Before you start

- Two instances, on **different addresses**. A registrar rejects a delegation
  whose nameservers resolve to one IP, and rightly — it is not redundancy.
  A 1GB Nanode each is enough; this process holds the zones in memory and
  answers from them.
- A **reserved, static** IP for each. Glue records hard-code them and are not
  re-read.
- A **reserved, static** IP for the cluster's gRPC Service, for the same
  reason: `/etc/ianua/dns.env` names it by hand.

## 1. Generate the PKI, once

On your workstation, not on any of these hosts, with the server's own image:

```sh
mkdir pki
docker run --rm --user "$(id -u)" -v "$PWD/pki:/pki" \
  ghcr.io/ianuaidp/ianua-server:latest \
  link-pki --server-name grpc.ianua.io --nameservers ns1,ns2 --out /pki
```

`--server-name` must be the name the nameservers will dial. It goes into the
server certificate and is what they check it against; an address works too,
such as `203.0.113.10`, and is written as an address entry.

This writes an authority (`ca-cert.pem`, `ca-key.pem`), the listener's
certificate (`server-cert.pem`, `server-key.pem`), and one certificate per
nameserver (`ns1-cert.pem`, `ns1-key.pem` and so on), the keys readable by you
alone, and prints the settings each end takes. Run it once: it refuses to
write over any of these files, because making the authority again would
leave every certificate issued under it unaccepted, and the symptom is
nameservers that stop connecting some time after whoever did it stopped
watching.

To add a nameserver to an existing authority later, sign its certificate with
`ca-key.pem`, with OpenSSL 3, in the `pki` folder:

```sh
NS=ns3
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=$NS" -keyout "$NS-key.pem" -out "$NS.csr"
openssl x509 -req -in "$NS.csr" -CA ca-cert.pem -CAkey ca-key.pem -days 365 \
  -set_serial "0x$(openssl rand -hex 16)" -out "$NS-cert.pem" \
  -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=clientAuth\n' "$NS")
rm -f "$NS.csr"
```

`pki/ca-key.pem` signs all of it. It belongs in your password manager or an
offline volume — **not** on the cluster and **not** on either nameserver.
Nothing running needs it; it is needed again only to issue a third nameserver.

## 2. Give the cluster its half

```sh
kubectl create secret generic ianua-grpc-pki \
  --from-file=tls.crt=pki/server-cert.pem \
  --from-file=tls.key=pki/server-key.pem \
  --from-file=ca.crt=pki/ca-cert.pem
```

Then turn the listener on:

```yaml
grpc:
  enabled: true
  tls:
    existingSecret: ianua-grpc-pki
  service:
    loadBalancerIP: "203.0.113.10"   # reserved, static
    sourceRanges:                    # once the nameservers are static
      - 203.0.113.20/32
      - 203.0.113.21/32
```

`sourceRanges` is not what makes this safe — the listener demands a client
certificate from our authority regardless. It just means the rest of the
internet cannot complete a TCP handshake.

Point `grpc.ianua.io` at that address. This is a TCP balancer and must stay
one: the connection is mutually authenticated end to end, so anything that
terminated TLS in the middle would have to hold the control plane's key, and
the client certificate would stop there instead of reaching the code that
checks it.

## 3. Put the binary on each host

Take it out of the published image rather than installing a Rust toolchain on
a host that faces the internet:

```sh
docker create --name extract ghcr.io/ianuaidp/ianua-dns:latest
docker cp extract:/usr/local/bin/ianua-dns ./ianua-dns
docker rm extract
scp ianua-dns root@ns1.example:/usr/local/bin/ianua-dns
```

It needs no packages. The binary links libc, libm and libgcc and nothing else —
TLS is rustls, Postgres is sqlx, both pure Rust — so any distribution with a
glibc at least as new as the image's (Debian bookworm, 2.36) runs it. Ubuntu
24.04 is fine. On each host:

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin ianua
chmod 0755 /usr/local/bin/ianua-dns
```

## 4. Configure and start it

**Ordinarily you do not.** The `deploy-nameservers` job in CI runs this same
script against both hosts after every deploy to `main`, one at a time, with the
binary from the image that deploy built. It needs two repository secrets:

| secret | what it is |
|---|---|
| `NAMESERVER_SSH_KEY` | base64 of a private key with root on both hosts |
| `NAMESERVER_PKI` | base64 of `tar -cz` over `ns1-cert.pem ns1-key.pem ns2-cert.pem ns2-key.pem ca-cert.pem` — **not** `ca-key.pem`; the job refuses the bundle if it is there |

That job exists because for a while nothing deployed these hosts at all. They
fell a whole redesign behind, answered with the wrong nameserver names, and
every delegation sent to them failed to verify with nothing reporting it.

Run it by hand for a first install, or when CI cannot reach the hosts — from
your workstation, one host at a time:

```sh
cp dns.env.example dns.env.ns1     # edit: endpoint, and the ns1 paths
cp dns.env.example dns.env.ns2     # edit: endpoint, and the ns2 paths
./install.sh ns1 root@203.0.113.20 ~/ianua-pki
./install.sh ns2 root@203.0.113.21 ~/ianua-pki
```

Never both at once. It stops the service to replace the binary, and the other
host is what answers meanwhile.

The script pulls the binary out of the published image, uploads it with this
host's certificate, installs the unit, runs `systemd-analyze verify` on it, and
starts it. `dns.env.*` is gitignored. By hand instead:

```sh
install -d -m 0750 -o root -g ianua /etc/ianua /etc/ianua/pki

# ns1's own identity, and the authority — never ca-key.pem
scp pki/ns1-cert.pem pki/ns1-key.pem pki/ca-cert.pem root@ns1.example:/etc/ianua/pki/
chmod 0640 /etc/ianua/pki/*.pem
chown root:ianua /etc/ianua/pki/*.pem

cp dns.env.example /etc/ianua/dns.env   # edit it
chmod 0640 /etc/ianua/dns.env
chown root:ianua /etc/ianua/dns.env

cp ianua-dns.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ianua-dns
```

On ns2 the file is identical except the two certificate paths. Neither host is
configured with any nameserver names: each zone arrives carrying its own, named
after the registration that opened it, which is what makes an `NS` record proof
of *whose* delegation it is.

## 5. Check it before delegating anything

```sh
systemctl status ianua-dns          # expect "dns listening on udp" and "…tcp"
journalctl -u ianua-dns -f          # a refused stream says so here
```

From somewhere else, against each host in turn:

```sh
dig @203.0.113.20 auth.sometenant.example A +norecurse
dig @203.0.113.21 auth.sometenant.example A +norecurse
```

Both must give the **same** answer. Then confirm TCP works — resolvers fall
back to it whenever an answer does not fit in a UDP packet, and a firewall
that allows only UDP/53 is the classic way to half-break a delegation:

```sh
dig +tcp @203.0.113.20 auth.sometenant.example A
```

An answer of REFUSED means the process is up but has no catalog: look at
whether the stream connected. `SERVFAIL` or no answer at all means something
between you and the port.

## 6. Glue records at the registrar

Last, because until the two hosts answer correctly this takes the delegation
live against nothing. At the registrar holding `ianua.io`, register the two
nameserver hosts and their addresses:

```
ns1.ianua.io → 203.0.113.20
ns2.ianua.io → 203.0.113.21
```

This is the step that makes the names resolvable at all. Without it a tenant's
delegation points at a name nothing can look up, because the only thing that
could answer for it is the server being delegated to.

## Rotating a certificate

The leaves are good for a year, the authority for ten.

To replace one host's identity, issue a new leaf under the same authority and
restart that host. The other one keeps answering throughout — which is the
other reason there are two.

Replacing the **authority** is not a rolling operation: every certificate under
it stops being accepted at the moment the control plane starts using a new one.
Issue the whole set, distribute it, then switch the cluster's Secret and
restart both hosts.

## What it costs

| | |
|---|---|
| 2 × 1GB Nanode | $10/mo |
| 1 common NodeBalancer for gRPC | $10/mo |
| **total** | **$20/mo** |

Against the in-cluster alternative (`dns.enabled` in the chart): two premium
NodeBalancers at $150/mo each, because a common one does not do UDP at all.
