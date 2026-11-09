# ── Toolchain base ───────────────────────────────────────
# Pinned to the version in rust-toolchain.toml, not the floating `1` tag.
# Floating meant every upstream 1.x publish invalidated this layer and, with
# it, the whole dependency cache below — a full cold rebuild at a moment
# nothing in the repository had changed. It also made the base ship one
# toolchain while rustup downloaded another over the top.
FROM rust:1.99.1-bookworm AS chef

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked

# ── Dependency plan ──────────────────────────────────────
#
# `prepare` reduces the workspace to a recipe describing only its dependency
# graph. The recipe changes when Cargo.toml or Cargo.lock does — not when a
# source file does — which is what keeps the expensive `cook` layer below
# cached across ordinary commits.
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Build ────────────────────────────────────────────────
FROM chef AS builder

# The compile-time-checked queries resolve against the committed .sqlx data;
# there is no database to reach from inside the build.
ENV SQLX_OFFLINE=true

COPY --from=planner /build/recipe.json recipe.json

# Dependencies only. This replaces the previous stub-source trick, which ended
# in `2>/dev/null || true` — so when it broke, it broke silently and every
# image rebuilt the entire dependency graph with nothing to say so. A failure
# here now fails the build.
#
# Scoped to the five binaries, as the final build is. Unscoped, `cook` would
# compile every workspace dependency including the e2e dev-dependencies
# (testcontainers, wiremock) that no image has ever needed.
RUN cargo chef cook --release --recipe-path recipe.json \
    -p ianua-server -p ianua-zero -p ianua-dns -p ianua-runner -p ianua-egress \
    -p ianua-connector

COPY . .
RUN cargo build --release -p ianua-server -p ianua-zero -p ianua-dns \
        -p ianua-runner -p ianua-egress -p ianua-connector \
    && strip target/release/ianua target/release/ianua-zero target/release/ianua-dns \
        target/release/ianua-runner target/release/ianua-egress target/release/ianua-connector

# ── Cloud command-line tools ────────────────────────────
#
# Placing a tenant in a customer's own cloud is driven by the vendor CLIs, so
# a cloud whose tool is absent from this image cannot be served at all. It is
# not served *badly* — the registry checks for each program at startup and
# declines to offer clouds it cannot drive, so a missing tool is "Azure is not
# available in this deployment" rather than a 500 from a failed spawn.
#
# Which is why this is a build argument. The tools are large and lopsided —
# azure-cli alone is ~570 MB installed, more than the other three together —
# and most operators need one or two. Name the ones this image should carry:
#
#   --build-arg CLOUD_CLIS="aws,digitalocean"
#   --build-arg CLOUD_CLIS="all"
#   --build-arg CLOUD_CLIS="none"
#
# `wireguard` is separate from the clouds: it is what reaches a database once
# built, not what builds it, and it costs about a megabyte. `kubernetes` is
# kubectl, for customers who grant us a namespace in their own cluster rather
# than a role in their cloud account.
FROM debian:bookworm-slim AS cloud-clis

ARG CLOUD_CLIS="aws,digitalocean,kubernetes,wireguard"
ARG DOCTL_VERSION=1.109.0
ARG KUBECTL_VERSION=v1.31.4

# Installed to the paths it will occupy in the final image, not to a staging
# directory. The AWS installer writes absolute symlinks into its bin directory,
# so a tree assembled under /out and copied elsewhere yields an `aws` that
# resolves to nothing. Both output directories are created unconditionally,
# because a COPY whose source is missing fails the build — and "this image
# carries no cloud tools" has to remain a legal choice.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg unzip; \
    mkdir -p /usr/local/aws-cli /usr/local/cloud-bin; \
    wanted() { case ",$CLOUD_CLIS," in *,all,*) return 0 ;; *",$1,"*) return 0 ;; *) return 1 ;; esac; }; \
    if wanted aws; then \
      curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o /tmp/aws.zip; \
      unzip -q /tmp/aws.zip -d /tmp; \
      /tmp/aws/install --install-dir /usr/local/aws-cli --bin-dir /usr/local/cloud-bin; \
    fi; \
    if wanted digitalocean; then \
      curl -fsSL "https://github.com/digitalocean/doctl/releases/download/v${DOCTL_VERSION}/doctl-${DOCTL_VERSION}-linux-$(dpkg --print-architecture).tar.gz" -o /tmp/doctl.tgz; \
      tar -xzf /tmp/doctl.tgz -C /usr/local/cloud-bin doctl; \
    fi; \
    if wanted kubernetes; then \
      curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/$(dpkg --print-architecture)/kubectl" \
        -o /usr/local/cloud-bin/kubectl; \
      chmod 0755 /usr/local/cloud-bin/kubectl; \
    fi; \
    rm -rf /tmp/aws* /tmp/doctl.tgz /var/lib/apt/lists/*

# ── Runtime stage (ianua-server) ────────────────────────
FROM debian:bookworm-slim AS server

ARG CLOUD_CLIS="aws,digitalocean,kubernetes,wireguard"

# gcloud and azure-cli come from vendor apt repositories rather than a copied
# directory: both drag a Python runtime and a tree of shared libraries behind
# them, and lifting that out of another stage by hand is how an image ends up
# with a tool that runs until the first call that needs a library nobody copied.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates libssl3 libpq5 dnsutils curl gnupg; \
    wanted() { case ",$CLOUD_CLIS," in *,all,*) return 0 ;; *",$1,"*) return 0 ;; *) return 1 ;; esac; }; \
    if wanted wireguard; then \
      apt-get install -y --no-install-recommends wireguard-tools iproute2; \
    fi; \
    if wanted gcp; then \
      curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
        | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg; \
      echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
        > /etc/apt/sources.list.d/google-cloud-sdk.list; \
      apt-get update; \
      apt-get install -y --no-install-recommends google-cloud-cli; \
    fi; \
    if wanted azure; then \
      curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg; \
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ bookworm main" \
        > /etc/apt/sources.list.d/azure-cli.list; \
      apt-get update; \
      apt-get install -y --no-install-recommends azure-cli; \
    fi; \
    apt-get purge -y --auto-remove curl gnupg; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system ianua; \
    useradd --system --gid ianua --no-create-home ianua; \
    install -d -o ianua -g ianua /var/lib/ianua/files

COPY --from=cloud-clis /usr/local/aws-cli/ /usr/local/aws-cli/
COPY --from=cloud-clis /usr/local/cloud-bin/ /usr/local/bin/

COPY --from=builder /build/target/release/ianua /usr/local/bin/ianua

# FILES_DIR defaults to `files` under the working directory.
WORKDIR /var/lib/ianua
USER ianua
EXPOSE 3000
ENTRYPOINT ["ianua"]

# ── Runtime stage (ianua-zero) ──────────────────────────
FROM debian:bookworm-slim AS zero

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system ianua \
    && useradd --system --gid ianua --no-create-home ianua

COPY --from=builder /build/target/release/ianua-zero /usr/local/bin/ianua-zero

USER ianua
EXPOSE 8080
ENTRYPOINT ["ianua-zero"]

# ── Runtime stage (ianua-runner) ────────────────────────
#
# The runner beside an agent's sandbox. It holds the agent's key and talks
# only to the ianua API and the gateway, so the image carries no database
# client and no shell tools beyond the base.
FROM debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system ianua \
    && useradd --system --gid ianua --no-create-home ianua

COPY --from=builder /build/target/release/ianua-runner /usr/local/bin/ianua-runner

USER ianua
ENTRYPOINT ["ianua-runner"]

# ── Runtime stage (ianua-egress) ────────────────────────
#
# The only way out for services agents can reach. Reads egress policies as
# the data plane's database role and lets a service connect only where the
# one policy written for it lists. The database is reached over rustls, so
# the image needs no TLS or Postgres client library.
FROM debian:bookworm-slim AS egress

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system ianua \
    && useradd --system --gid ianua --no-create-home ianua

COPY --from=builder /build/target/release/ianua-egress /usr/local/bin/ianua-egress

USER ianua
EXPOSE 3128 9902
ENTRYPOINT ["ianua-egress"]

# ── Runtime stage (ianua-connector) ─────────────────────
#
# Runs inside a tenant's own network: dials out to the gateway's connector
# listener and opens connections only to the targets it is told to allow.
# Holds no platform secret and no database login, and listens on nothing.
FROM debian:bookworm-slim AS connector

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system ianua \
    && useradd --system --gid ianua --no-create-home ianua \
    && install -d -m 700 -o ianua -g ianua /var/lib/ianua-connector

COPY --from=builder /build/target/release/ianua-connector /usr/local/bin/ianua-connector

USER ianua
VOLUME ["/var/lib/ianua-connector"]
ENTRYPOINT ["ianua-connector"]

# ── Runtime stage (ianua-dns) ───────────────────────────
#
# The authoritative nameservers for hostnames tenants have delegated. Reads
# zones from Postgres as its own role, which reads nothing else, and answers
# queries; it writes nothing, which is why it is a separate image from the
# control plane rather than another MODE of it. TLS is rustls and Postgres is
# sqlx, so it needs no system library beyond the certificate roots.
FROM debian:bookworm-slim AS dns

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system ianua \
    && useradd --system --gid ianua --no-create-home ianua

COPY --from=builder /build/target/release/ianua-dns /usr/local/bin/ianua-dns

USER ianua

# Not 53. Binding a port below 1024 needs root or CAP_NET_BIND_SERVICE, and
# neither is worth granting a process that faces the open internet — DNS is
# reachable by anyone, unauthenticated, over UDP. The Service maps 53 to this,
# so resolvers still find it where they expect. Override with DNS_BIND.
EXPOSE 5353/udp 5353/tcp
ENTRYPOINT ["ianua-dns"]
