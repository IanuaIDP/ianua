#!/usr/bin/env bash
#
# Installs one nameserver, from your workstation, over ssh.
#
#   ./install.sh ns1 root@203.0.113.20 ~/ianua-pki
#
# The first argument is the client name the PKI was made for (README.md,
# step 1), and decides which certificate this host receives. Everything else
# about the two hosts is
# identical — they answer for the same zones and must give the same answers.
#
# Re-runnable: it replaces the binary and configuration and restarts the
# service. The other nameserver keeps answering throughout, which is what
# having two is for. Never run it against both at once.

set -euo pipefail

readonly IMAGE="${IANUA_DNS_IMAGE:-ghcr.io/ianuaidp/ianua-dns:latest}"

usage() {
    echo "usage: $0 <client-name> <ssh-target> <pki-dir>" >&2
    echo "   eg: $0 ns1 root@203.0.113.20 ~/ianua-pki" >&2
    exit 64
}

[ $# -eq 3 ] || usage

readonly CLIENT="$1"
readonly TARGET="$2"
readonly PKI="$3"
readonly HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# One file for both hosts. The only thing that ever differed between them was
# the two certificate paths, and those are `$CLIENT` — so a per-host file was a
# copy that could drift, and a copy that has to be gitignored is a copy CI
# cannot see. The paths are appended at install time instead; see below.
#
# `IANUA_DNS_ENV` still overrides, for a host configured differently on purpose.
readonly ENV_FILE="${IANUA_DNS_ENV:-$HERE/dns.env}"

for f in "$PKI/$CLIENT-cert.pem" "$PKI/$CLIENT-key.pem" "$PKI/ca-cert.pem" "$ENV_FILE"; do
    [ -f "$f" ] || { echo "missing: $f" >&2; exit 66; }
done

if [ -f "$PKI/ca-key.pem" ] && grep -q "ca-key.pem" "$ENV_FILE"; then
    echo "$ENV_FILE references ca-key.pem — that key signs every certificate" >&2
    echo "in this deployment and must never reach a host that faces the internet." >&2
    exit 65
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# CI already holds the binary: it built the image minutes ago and its registry
# is plain HTTP on loopback, which needs pull flags that make no sense on a
# workstation. Rather than teach this script about that, let a caller that has
# already sorted it out hand the binary over.
if [ -n "${IANUA_DNS_BINARY:-}" ]; then
    echo "==> using the binary at $IANUA_DNS_BINARY"
    cp "$IANUA_DNS_BINARY" "$work/ianua-dns"
else
    echo "==> extracting the binary from $IMAGE"

    # The images are built for amd64 and the hosts are amd64, but an Apple
    # Silicon workstation defaults to pulling arm64 and gets "no matching
    # manifest". Naming the platform is about the *binary being installed*, not
    # this machine, so it is correct everywhere rather than a local workaround.
    docker pull --quiet --platform linux/amd64 "$IMAGE" >/dev/null
    container="$(docker create --platform linux/amd64 "$IMAGE")"
    docker cp "$container:/usr/local/bin/ianua-dns" "$work/ianua-dns" >/dev/null
    docker rm "$container" >/dev/null
fi

echo "==> uploading to $TARGET"
scp -q "$work/ianua-dns" "$TARGET:/tmp/ianua-dns"
scp -q "$PKI/$CLIENT-cert.pem" "$PKI/$CLIENT-key.pem" "$PKI/ca-cert.pem" "$TARGET:/tmp/"
# This host's identity, named rather than configured. Getting it from `$CLIENT`
# is what makes the two hosts indistinguishable in configuration and distinct
# in identity — a hand-edited path that named the other host's certificate
# would work, and would make the control plane's logs unable to tell them apart.
{
    cat "$ENV_FILE"
    printf '\nCONTROL_PLANE_CLIENT_CERT=/etc/ianua/pki/%s-cert.pem\n' "$CLIENT"
    printf 'CONTROL_PLANE_CLIENT_KEY=/etc/ianua/pki/%s-key.pem\n' "$CLIENT"
} > "$work/dns.env"

scp -q "$work/dns.env" "$TARGET:/tmp/dns.env"
scp -q "$HERE/ianua-dns.service" "$TARGET:/tmp/"

echo "==> installing"
ssh "$TARGET" CLIENT="$CLIENT" 'bash -seuo pipefail' <<'REMOTE'
# Nothing to install. The binary links libc, libm and libgcc and no more —
# TLS is rustls and Postgres is sqlx, both pure Rust — so it runs on any
# glibc at least as new as the image it came out of. Naming distribution
# packages here would only make this fail on the next distribution: Debian's
# libssl3 is Ubuntu's libssl3t64, and neither is needed.

id -u ianua >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ianua

# Ubuntu ships systemd-resolved with a stub listener on 127.0.0.53:53. This
# binds 0.0.0.0:53, which overlaps it, so the bind fails — on a host that
# otherwise looks perfectly healthy. Debian does not do this, which is why it
# only appears on some hosts.
#
# The stub goes; resolved stays. The host still has to resolve names — this
# process cannot reach the control plane otherwise — so /etc/resolv.conf is
# pointed at the upstream servers resolved already knows, instead of at the
# stub that is being turned off.
readonly STUB_OFF=/etc/systemd/resolved.conf.d/ianua-dns.conf

if systemctl is-active --quiet systemd-resolved && ! grep -qs 'DNSStubListener=no' "$STUB_OFF"; then
    echo "freeing port 53 from systemd-resolved"
    mkdir -p "$(dirname "$STUB_OFF")"
    printf '[Resolve]\nDNSStubListener=no\n' > "$STUB_OFF"
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
fi

install -d -m 0750 -o root -g ianua /etc/ianua /etc/ianua/pki

# Stopped first: the binary is replaced in place, and writing over a running
# executable is what ETXTBSY exists to prevent.
systemctl stop ianua-dns 2>/dev/null || true

install -m 0755 -o root -g root /tmp/ianua-dns /usr/local/bin/ianua-dns
install -m 0640 -o root -g ianua /tmp/dns.env /etc/ianua/dns.env
install -m 0640 -o root -g ianua "/tmp/${CLIENT}-cert.pem" "/etc/ianua/pki/${CLIENT}-cert.pem"
install -m 0640 -o root -g ianua "/tmp/${CLIENT}-key.pem" "/etc/ianua/pki/${CLIENT}-key.pem"
install -m 0640 -o root -g ianua /tmp/ca-cert.pem /etc/ianua/pki/ca-cert.pem
install -m 0644 -o root -g root /tmp/ianua-dns.service /etc/systemd/system/ianua-dns.service

rm -f /tmp/ianua-dns /tmp/dns.env /tmp/ca-cert.pem /tmp/ianua-dns.service /tmp/*-cert.pem /tmp/*-key.pem

systemd-analyze verify /etc/systemd/system/ianua-dns.service
systemctl daemon-reload
systemctl enable --now ianua-dns
REMOTE

echo "==> checking it bound"
sleep 3

# "active" is not the check. The process starts, spawns its listeners, and
# stays up whether or not they bound — so a host with port 53 already taken
# reports a healthy service and answers nothing. Look at the port instead.
ssh "$TARGET" 'bash -seuo pipefail' <<'VERIFY'
if ! ss -lnupH 'sport = :53' | grep -q ianua-dns; then
    echo "ianua-dns is not listening on udp/53:" >&2
    ss -lntup 'sport = :53' >&2
    journalctl -u ianua-dns -n 20 --no-pager >&2
    exit 1
fi

if ! ss -lntpH 'sport = :53' | grep -q ianua-dns; then
    echo "ianua-dns is listening on udp/53 but not tcp/53 — truncated answers" >&2
    echo "will go unanswered, which fails only for the larger replies." >&2
    exit 1
fi

echo "listening on udp/53 and tcp/53"
journalctl -u ianua-dns -n 8 --no-pager -o cat
VERIFY

cat <<EOF

Installed. Check it answers the same as the other one, over both transports:

  dig @<this host> auth.<a tenant>.example A +norecurse
  dig +tcp @<this host> auth.<a tenant>.example A

REFUSED means it is up but has no catalog yet — look at whether the stream
reached the control plane.
EOF
