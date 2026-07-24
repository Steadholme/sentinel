# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
# Multi-stage build for Sentinel (watchtower audit + hindsight RCA vhost demux).
FROM rust:1.96-slim@sha256:31ee7fc65186be7e0e0ccb3f2ca305f14e4739e7642a1ae65753aa5d7b874523 AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates ./crates
RUN cargo build --release --locked --bin sentinel \
    && strip target/release/sentinel

FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS runtime
ARG VCS_REF=unknown
LABEL org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://git.w33d.xyz/git/w33d/sentinel.git"

# Bootstrap HTTPS from the CA bundle in the pinned builder. The exact snapshot package replaces
# this copied bundle, while peer and host verification remain mandatory throughout bootstrap.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN <<'EOF'
set -eux
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources
cat > /etc/apt/sources.list.d/debian-snapshot.sources <<'SOURCES'
Types: deb
URIs: https://snapshot.debian.org/archive/debian/20260720T000000Z
Suites: trixie
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
SOURCES
cat > /etc/apt/apt.conf.d/99bootstrap-ca <<'APT'
Acquire::https::CaInfo "/etc/ssl/certs/ca-certificates.crt";
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";
APT
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates=20250419 \
    libssl3t64=3.5.6-1~deb13u2 \
    openssl=3.5.6-1~deb13u2 \
    openssl-provider-legacy=3.5.6-1~deb13u2
rm -f /etc/apt/apt.conf.d/99bootstrap-ca
rm -rf /var/lib/apt/lists/*
EOF

RUN groupadd --system --gid 10001 sentinel \
    && useradd --system --uid 10001 --gid 10001 --no-create-home \
        --shell /usr/sbin/nologin sentinel
COPY --from=builder /build/target/release/sentinel /usr/local/bin/sentinel
USER sentinel
ENV BIND_ADDR=0.0.0.0:8500
EXPOSE 8500
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["sentinel", "healthcheck"]
CMD ["sentinel"]
