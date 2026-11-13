# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

Fran (formerly Fran DB) is a desktop database, SSH and VPN client built with Tauri 2 (Rust backend) and SolidJS + TypeScript (frontend). MySQL, PostgreSQL, SQLite and Cloudflare D1 are supported, and VPNs are OpenVPN and WireGuard. Every database-specific piece sits behind a per-kind module so another database can be added without touching generic code.

Details live next to the code, in CLAUDE.md files that load when you work in that folder:

- `src-tauri/CLAUDE.md`: Rust tests, transports, secrets, vault and app lock, cloud sync, app data files
- `src-tauri/src/db/CLAUDE.md`: drivers, sessions and contexts, generated SQL and DDL
- `src-tauri/src/ssh/CLAUDE.md`: SSH logins, host keys, routes, terminals, forwards, SFTP
- `src-tauri/src/agent/CLAUDE.md`: the MCP server for agents
- `src/CLAUDE.md`: frontend state, UI rules, Home, settings, editor, row editing
- `server/CLAUDE.md`: the sync server, its database rules and tests
- `.github/CLAUDE.md`: the release pipeline

## Commands

- `npm run tauri dev` runs the full app (Vite on port 1430 plus the Rust backend)
- `npm run dev` runs the frontend alone (Tauri APIs unavailable)
- `npm run tauri build` makes a release bundle
- The repo is a Cargo workspace: `src-tauri` (the app), `crates/vpn-proto` (frames shared with the VPN worker) and `crates/vpn-worker` (the `fran-vpn` sidecar, the only crate that builds OpenVPN 3). `target/` and `Cargo.lock` are at the root.
- `crates/sync-proto` (API types shared with the sync server) is in the workspace too. `server/` (the sync server) is not: it has its own `Cargo.lock` and `target/`, so its cargo commands run from `server/`.
- `cargo check` / `cargo test` compile or test the Rust side, `cargo build -p vpn-worker` builds the sidecar into the same `target/` folder, where the app finds it in dev. The e2e tests are in `src-tauri/CLAUDE.md`.

No frontend tests or linters are configured.

## Rules that apply everywhere

- User-facing changes go under `## [Unreleased]` in `CHANGELOG.md` (Keep a Changelog, `### Added` / `### Changed` / `### Fixed` with `- ` bullets). Those notes are shown in the app's update panel.
- Never branch on database kind in generic code. Rust goes through `DatabaseSession` and the `match` arms in `db/mod.rs`, the frontend through `withDatabaseModule`.
- Secrets go from the frontend to Rust and never back. The one exception is `vault/reveal.rs`: `reveal_secret` returns a password after the OS confirms the user, and `reveal_all_secrets` returns all of them while the Passwords page is unlocked (5 minutes after one confirm). Private keys and TLS keys never come back, they're only exported to a file after the same check. A sync account's recovery key is returned once, by `fran_server_create_account` and `fran_server_new_recovery_key`, to be shown, and is never stored.
- Never branch on cloud kind in generic code. Rust goes through the `Provider` trait and `sync::providers::opener`, the frontend through `withCloudModule` (`src/clouds/`).
- Every backend call goes through `safeInvoke`. A new or changed `#[tauri::command]` is registered in `lib.rs` and in the `Commands` map in `src/helpers/safeInvoke.ts`.
- The desktop app never creates or alters schema in any datastore on its own. Schema changes only happen as SQL the user reviews and runs. This doesn't apply to the sync server, which runs its own migrations.

## Conventions

- Default to no comments. One short line only for a non-obvious constraint.
- Rust structs crossing IPC use `#[serde(rename_all = "camelCase")]`. On tagged enums, struct variants with multi-word fields need their own `#[serde(rename_all = "camelCase")]`, the enum-level one only renames variant tags.
- Every derived reactive value in a Solid component is a `createMemo`, not a plain arrow function. This includes conditional props passed to components (`editing={cond ? a : b}`): Solid compiles those into a getter that creates a memo on each read, and reading it from an event handler logs "computations created outside a `createRoot`".
- Multi-line functions use `function` declarations, not `const` arrows.
