# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.92.0

FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /usr/src/lightbringer

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      clang \
      cmake \
      git \
      libclang-dev \
      libssl-dev \
      libudev-dev \
      pkg-config \
      protobuf-compiler \
      zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY pb ./pb
COPY src ./src

RUN cargo build --release --bin lightbringer

FROM builder AS tester

COPY decoded_shreds.json stored_shreds.json ./

RUN cargo test --all-targets

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      libgcc-s1 \
      libnghttp2-14 \
      libssl3 \
      libstdc++6 \
      libudev1 \
      zlib1g \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /var/lib/lightbringer --shell /usr/sbin/nologin lightbringer \
    && mkdir -p /var/lib/lightbringer/shred-store \
    && chown -R lightbringer:lightbringer /var/lib/lightbringer

COPY --from=builder /usr/src/lightbringer/target/release/lightbringer /usr/local/bin/lightbringer

USER lightbringer
WORKDIR /var/lib/lightbringer

ENTRYPOINT ["lightbringer"]
