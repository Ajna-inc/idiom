# Stage 1: Build the ported idiom mediator_server
FROM rustlang/rust:nightly-bookworm AS builder

WORKDIR /build

# Build deps: libpq for aries-askar's postgres feature, git for git-based
# cargo deps (Ajna forks of askar / didcomm-rust, anoncreds).
RUN apt-get update && apt-get install -y libpq-dev git && rm -rf /var/lib/apt/lists/*

# idiom is fully self-contained (no external blockchain workspace).
COPY src/ ./src/

WORKDIR /build/src
RUN cargo build -p mediator_server --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libsqlite3-0 \
    libpq5 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/src/target/release/mediator-server /usr/local/bin/mediator-server

# Fresh Fly volumes mount /data root-owned; run as root so the process can
# create /data/mediator.db (isolated Firecracker microVM — safe).
RUN mkdir -p /data
WORKDIR /data

ENV MEDIATOR_HOST=0.0.0.0
ENV MEDIATOR_PORT=3000
ENV DATABASE_URL=sqlite:///data/mediator.db
ENV RUST_LOG=info

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

ENTRYPOINT ["mediator-server"]
