# Sync server

`fran-sync-server` stores end-to-end encrypted records for Fran's cloud sync. It only ever sees ciphertext, an auth key (itself an Argon2id output) and wrapped keys it can't open.

## Building and tests

- This crate is not in the repo's Cargo workspace. sqlx's SQLite driver and the app's rusqlite need different `libsqlite3-sys` versions, and one workspace can only link SQLite once. Run every cargo command from `server/`. It has its own `Cargo.lock` and `target/`.
- `cargo test` runs the unit tests and `tests/api.rs`, which starts the real router on a 127.0.0.1 port and talks to it over HTTP and a WebSocket.
- Every scenario in `tests/api.rs` runs on SQLite, MySQL and MariaDB. The MySQL and MariaDB ones print "skipped" and pass unless `FRAN_SYNC_MYSQL_URL` or `FRAN_SYNC_MARIADB_URL` names a running server without a database name (`mysql://root:secret@127.0.0.1:3306`). Each test makes its own database there. The tests never start Docker themselves.
- The request and response types are in `crates/sync-proto`, shared with the app. Change the wire format there, and bump `PROTOCOL_VERSION` when an old client would misread it.

## Packaging

- Linux only, as a Docker image and a Nix package. No binaries are published, and the server's code has nothing OS specific in it. Keep it that way: the image sets `STOPSIGNAL SIGINT` and the NixOS unit `KillSignal=SIGINT` so the server only has to handle Ctrl+C.
- `Dockerfile` builds from the repo root (`docker build --file server/Dockerfile .`), since the crate needs `crates/sync-proto`. `Dockerfile.dockerignore` keeps everything else out of the build.
- `README.md` is the self-hosting guide. Its settings table has to match `src/config.rs`.
- This crate is versioned on its own, `npm run version:bump` leaves it alone. Bump `Cargo.toml` by hand and run `cargo check` here so `Cargo.lock` follows (the image builds with `--locked`), then push an `sv<version>` tag to publish the image.

## Database

- SQLite or MySQL, picked by the `DATABASE_URL` scheme, through sqlx's `Any` driver. Every query is in `src/store.rs` and has to run on both, so: `?` placeholders, BIGINT for every number and flag, BLOB for bytes, no NULLs, no upserts, no `SELECT ... FOR UPDATE`, no SUM (MySQL returns a DECIMAL that `Any` can't read).
- A schema change is a new file in both `migrations/sqlite` and `migrations/mysql`, with the same tables and columns. A test compares them.
- `push` starts its transaction with a write on the account's row. That is what keeps two pushes for one account from interleaving on both databases, so keep a write first.
- `sqlite://C:/path` is turned into `sqlite:C:/path` before connecting, since the URL parser reads the drive letter as a host.

## Owner and admin

- Accounts have a `role` (`user`, `admin`, `owner`, one owner). Admin calls are under `/v1/admin` (`src/api/admin.rs`) and check the role on every call. Only the owner changes roles or hands over.
- While nobody owns the server, `AppState` holds a setup code made at start and `cli::serve` prints it to stderr. It claims through `POST /admin/claim`, or as the invite of the first sign-up. `/info` sends `owned: false` only then.
- Effective settings (`src/settings.rs`) are the config with anything saved in the `settings` table on top. The environment is only the starting value, a change from the app wins. Read them through `state.settings()`, never `config.signup` or `config.limits`, so changes from the app apply at once. A second server process on the same database only picks up changes on restart.
- `POST /records` reads its own body, limited by that account's allowance (`users.quota_bytes`, else the default), so the router has no body limit there.
- Every admin change goes into `admin_log`. Its ids start with the time in nanoseconds so they sort in order. Never put codes, keys or passwords in it.

## Rules

- Never log request bodies, tokens, auth keys or ciphertext. Internal error details go to stderr, the client gets a generic message.
- Only the SHA-256 of a session token is stored. The auth key and the recovery auth key are stored as Argon2id hashes.
- Sign-in, recovery and the password checks give the same answer for an unknown account and a wrong key, and count failures per account and per address in `login_attempts`.
- The WebSocket sends cursors only, never records.
