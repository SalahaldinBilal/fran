# Build from the repo root, the server needs crates/sync-proto:
#   docker build --file server/Dockerfile --tag fran-sync-server .

FROM rust:1-bookworm AS build
WORKDIR /src
COPY crates/sync-proto crates/sync-proto
COPY server server
WORKDIR /src/server
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/server/target \
    cargo build --release --locked \
    && cp target/release/fran-sync-server /fran-sync-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data --create-home fran
COPY --from=build /fran-sync-server /usr/local/bin/fran-sync-server
USER fran
WORKDIR /data
# Environment to give at run time:
#   SERVER_KEY    required, 64 hex characters (openssl rand -hex 32). Keep it for as long as the database lives.
#   DATABASE_URL  optional, mysql://user:password@host:port/database for MySQL or MariaDB.
#                 Without it the database is SQLite in /data, so mount a volume there to keep it.
# The rest (SIGNUP, limits, TRUST_PROXY, TLS) is optional and listed in server/README.md.
ENV BIND=0.0.0.0:8787
EXPOSE 8787
# The server stops on Ctrl+C. This makes `docker stop` send the same signal.
STOPSIGNAL SIGINT
ENTRYPOINT ["fran-sync-server"]
