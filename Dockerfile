# syntax=docker/dockerfile:1
# Multi-stage build for Sentinel (watchtower audit + hindsight RCA vhost demux).
FROM rust:1.96-slim AS builder
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
COPY crates ./crates
RUN cargo build --release --bin sentinel \
    && strip target/release/sentinel

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --user-group --no-create-home sentinel
COPY --from=builder /build/target/release/sentinel /usr/local/bin/sentinel
USER sentinel
ENV BIND_ADDR=0.0.0.0:8500
EXPOSE 8500
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["sentinel", "healthcheck"]
CMD ["sentinel"]
