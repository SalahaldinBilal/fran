# SSH

## Logins and host keys

- SSH logs in with a password, a key file, or the SSH agent (`SshAuthMethod::Agent`, which offers each agent key in turn). The agent is `SSH_AUTH_SOCK` on Unix and the OpenSSH pipe, then Pageant, on Windows. `agentSocket` overrides it.
- Host keys are checked against `known_hosts.json` in the app data dir, on every hop. An unknown or changed key fails the connect with `unknownHostKey` / `hostKeyChanged` carrying the SHA256 fingerprint and the hop. The frontend asks the user and calls `trust_host_key` (which never overwrites a different key) or `replace_host_key` (which needs the typed host name), then retries. OpenSSH's `~/.ssh/known_hosts` is only read, to say in the prompt that OpenSSH already trusts a key.
- `preferred()` drops SHA-1 kex, `ssh-rsa` and CBC.

## Saved hosts and routes

- Saved SSH hosts, identities, key metadata, proxies, forward rules and the host group order live in `ssh.json` (`src-tauri/src/ssh_store/`, `states/sshState.ts` in the frontend). `SshOptions.hostId` points a database connection at a saved host.
- `connections::prepare::prepare_connect` resolves the route (`route.rs`: the first jump host is reached through its own route, like OpenSSH's ProxyJump, at most 8 hops, no cycles) and every secret on it before the driver runs, and drivers open the tunnel with `SshAccess::tunnel`. Inline SSH options are a one-hop route.
- Hop 1 can go through a SOCKS5 or HTTP CONNECT proxy (`proxy.rs`), later hops are `direct-tcpip` channels on the previous one.

## Terminals and forwards

- Terminals (`terminal.rs`, `states/terminalState.ts`, `pages/Terminal/`): `TerminalManager` keeps connections and their panes. Split panes are more session channels on one connection. Output streams as raw bytes over a `Channel`. With `settings.terminal.logOutput`, `PaneLog` (`terminal_log.rs`) saves what the pane prints, batched about every second, never what's typed. `terminal_type_password` writes the host identity's saved password from the vault straight into the pane's channel, without Enter, so it never crosses IPC.
- Forwards (`forwards.rs`): saved rules run on their own SSH connection each. `ChannelPolicy` (`policy.rs`) on the last hop accepts forwarded-tcpip only for registered remote forwards, agent channels only when the host forwards the agent, and refuses every other server-opened channel. Dynamic forwards are a SOCKS5 server of our own (`socks.rs`).

## SFTP

- `sftp/` with `states/sftpState.ts` and `pages/Sftp/` in the frontend. `SftpConn` is one russh-sftp session, and its operations are methods the commands wrap.
- `sftp_open` borrows a terminal's connection when one is given (`TerminalManager::borrow`, the connection stays up while borrowed), otherwise logs in along the host's route, and reports a dropped connection over its `Channel`.
- `transfer.rs` copies in 256 KiB chunks, up to `MAX_TRANSFERS` per connection, scanning folders first. Name clashes pause the transfer until `sftp_answer_conflict`. An overwrite writes `.<name>.<tag>.part` and swaps it in when complete.
- Safety: a name from the server is only joined into a local path after `paths::local_name_problem` (separators, `..`, NUL, control characters, and on Windows colons, reserved names and trailing dots or spaces). Links inside folders are never followed, a link picked on its own is followed only to a file. Downloads are created with the default mode. Local paths only come from the local pane or from files dropped on the window (`onDragDropEvent`).

## Agents

Agents have no SSH surface. `agent/tests.rs` pins the exact tool list.
