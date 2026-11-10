# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.0] - 2026-11-10

### Added

- Saved passwords can be shown again. Every password field has a Show button, and the Keychain tab, now called Secrets, lists every secret in the vault. Unlock its passwords once to see all of them for 5 minutes, with Copy on each. Your system confirms it's you first: Touch ID or your password on macOS, Windows Hello or your Windows password on Windows, and your desktop's password prompt on Linux. A shown password hides after 30 seconds, and a copied one is cleared from the clipboard after 30 seconds. If your account has no password, Fran doesn't ask, or asks for the app lock password when the lock is on.
- VPN profiles can be exported as an .ovpn with their keys inside, from the Secrets page, to use on another computer. Exporting an SSH key now asks your system to confirm it's you too.
- Slow queries, from the gauge button next to a connection's name. History lists the statements the server has seen from every client, not just Fran, grouped by shape with calls, total, mean and max time and rows, slowest on average first. It loads the top 200 by the column you sort by. When the server has more, changing the sort offers a reload to fetch the top 200 by the new column. Running now shows what's running at the moment and for how long, updated every 3 seconds. MySQL reads performance_schema, MariaDB reads it or the slow query log when performance_schema is off, Postgres reads pg_stat_statements and pg_stat_activity, and Cloudflare D1 reads the last 24 hours of query insights. When the server isn't collecting this or the login can't read it, the tab says what's missing and gives the SQL or setting to copy, and whether the server needs a restart. Fran never changes the server's settings itself. Click a statement to see all of it, copy it or open it in a query tab.
- Agents can read the slow query history with the new `slow_queries` tool, sorted by mean time unless they ask for total, max, calls or rows. They only see statements from the databases a connection shares with them.

- Results can be selected many rows or cells at a time. Click or drag across row numbers to pick rows, Shift+click for a range, Ctrl+click to add or remove one, drag across cells for a block, click a column header for the whole column, and Ctrl+A for everything. Shift+arrows extend the selection and Esc goes back to one cell.
- Ctrl+C copies the selection as tab-separated text that pastes into spreadsheets, and Ctrl+Shift+C adds the column names. The right-click menu also copies as CSV, JSON, a Markdown table or SQL INSERT statements. INSERT needs every column to come from one table.
- Delete row and Restore row work on every selected row at once.
- The connection editor fills itself in from a connection string. Paste one into the new Connection string field, or straight into Host. It reads `mysql://`, `mariadb://`, `postgres://`, `postgresql://` and their `jdbc:` and `+driver` forms, libpq `key=value` strings, and SQLite `sqlite:` and `file:` URLs or file paths, including SSL modes, certificate files, timeouts and sockets. A string for another database type switches the form to it. The password goes to the vault on save, and options Fran doesn't use are listed instead of dropped silently.
- Port forwards can listen on all networks (0.0.0.0) instead of only this computer, so WSL, containers and other machines can use them. It's a switch in the port forward dialog, off by default and saved with the connection.
- A welcome screen asks what you use Fran for, the database client, the SSH client or both, and shows where saved passwords are kept. Existing installs see it once, with the database client already picked.
- The Connections tab is now Home, a set of panels you can arrange: Databases (the connection cards, as before), SSH hosts, Recent (connections and hosts you opened lately), Port forwards and Snippets. Drag a panel by its header onto a side of another panel to dock it there, onto its middle to swap the two, or onto an edge of the page for a full-height or full-width panel. Drag the gaps to resize. The Panels menu shows or hides each panel and resets the layout, and the layout is remembered. Ctrl+F (⌘F on macOS) jumps to the search box, which filters every panel.
- Settings has a General page that turns the database client and the SSH client on or off. A part that's off is hidden everywhere: its tabs close, its settings pages go away, and turning off the database client hides the Agents button and stops the MCP server. Nothing saved is removed.
- Saved SSH hosts, in a new SSH hosts panel on Home. A host has an address, a login (an identity), jump hosts it's reached through and an optional SOCKS5 or HTTP proxy for the first hop. The editor shows the whole route. Home's New button adds a database connection or an SSH host.
- MySQL and Postgres connections can tunnel through a saved SSH host, with its jump hosts and proxy, instead of SSH details typed into the connection. "Save as an SSH host" turns a connection's own SSH settings into a saved host. Connections set up the old way keep working as they are.
- A Keychain tab, from the key button in the title bar. Keys: generate Ed25519, ECDSA or RSA keys into the vault, import keys by pasting them (straight into the vault) or from key files (copied into the vault or kept as files), copy the public key, and export a private key to a file with a new passphrase. Identities: a user and how it logs in, shared by every host that uses it. Proxies: SOCKS5 and HTTP CONNECT, with an optional login. Known hosts: every trusted server key, with search and forget.
- Import hosts from `~/.ssh/config`, from the SSH hosts panel or the welcome screen. `ProxyJump` becomes jump hosts and `IdentityFile` a key that keeps using the file. Patterns and `Match` blocks are skipped, hosts already saved aren't added twice, and the file is never written.
- Terminals. With the SSH client on, clicking a saved host opens a terminal tab through its route. Split right or down to get more shells on the same connection without logging in again, and drag panes around like Home's panels. A dropped connection says why, and Enter or Reconnect logs back in. The status bar shows the verified host key, the login and the keepalive. Terminal tabs aren't reopened on restart, the Recent panel lists the hosts you opened.
- Snippets, for commands you run often. Run sends one with Enter, Type it puts it at the prompt without pressing Enter, and snippets marked "Ask first" confirm before running. They're in a drawer in every terminal and in a Snippets panel on Home. A host can type one at the prompt after login.
- Saved port forwards through SSH hosts: local, remote (the server listens and sends connections back to this computer) and dynamic (a SOCKS5 proxy). Start and stop them from the new Port forwards panel, a host's menu or a terminal's top bar. Local and dynamic forwards listen on 127.0.0.1 unless you turn on all networks. Running forwards stop when Fran closes.
- Login password in the snippets drawer, for sudo prompts. It types the host login's saved password at the prompt without pressing Enter. The password goes from the vault to the server and never passes through the window.
- A Terminal page in Settings for the font, size, cursor, scrollback and copy on select.
- Terminal safety, on by default. Pasting text with line breaks shows what will run and waits for a click, and bracketed paste markers are stripped from the clipboard text. Links open in your browser only after a confirm, and only `http` and `https` ones. A server can write to the clipboard (OSC 52, for tmux and vim) only if that host allows it, and can never read it. Scrollback stays in memory.
- Agent forwarding per host, off by default, with a warning in the host editor and the terminal's status bar while it's on.
- Files over SFTP. Open them from a terminal's Files button, or a host's card or menu. This computer is on the left and the server on the right. Drag files between the two, onto a folder to put them there, or use Upload and Download. Rename, delete, new folder, permissions and copy path are in the right-click menu, and server files up to 1 MiB can be previewed as text. When a terminal to the host is open, its connection is reused, so there's no second login.
- A transfer queue under the file panes with progress, speed, cancel and try again. Folders copy with everything in them, and up to 3 transfers run at once per server. When a file is already there it asks whether to overwrite, skip or keep both, optionally for the rest of the transfer. An overwrite writes the new copy next to the old file and only swaps it in once it's complete. Cancelling deletes the half-copied file, closing the tab with transfers running asks first, and a dropped connection shows right away.
- Drop files from Explorer or Finder onto the server pane to upload them. Columns sort by name, size or modified, with folders kept on top. On Windows a Drives button switches the local pane to another drive.
- App lock, in Settings > Security. With a password set, the vault key is no longer kept in the OS keychain: it's wrapped with a key derived from the password (Argon2id, 64 MiB, 3 passes), so saved passwords and keys can only be read after you unlock. Fran locks when it starts and after 5, 15 or 60 minutes idle, or from the lock button in the title bar. Terminals, sessions and port forwards keep running while it's locked, and agent changes waiting for approval don't time out behind the lock screen. If you forget the password, the lock screen can reset the vault.
- Terminal logs, off by default, in Settings > Terminal. What terminals print is saved encrypted, one file per day, and kept 7, 30, 90 or 365 days. What you type is never saved. Saved logs can be read from the same page, as plain text, or deleted.
- Search on Home lists matching connections, SSH hosts, port forwards and snippets as you type. Arrow keys pick one and Enter opens it.
- SSH hosts can be put in order and moved between groups by dragging, and groups can be added, renamed and removed, the same way as connections.
- File transfer safety. Names from the server that would land outside the chosen folder, like `../evil` or ones with slashes, a drive letter or a reserved Windows name, are skipped with the reason shown in the queue. Links inside folders aren't followed. Downloads never keep setuid, setgid or the executable bit. Deleting a folder says how many files go before it runs.
- A VPN client, turned on in Settings > General or on the welcome screen. Import an OpenVPN profile (.ovpn) or set one up by hand in the new VPN panel on Home, which shows VPNs as cards like SSH hosts, or as one-line rows in its compact view, and sits under Recent in the default layout and is added to your own layout when you turn the VPN client on. A login in the profile, inline or in a file next to it, is imported too: the user name goes in the profile, and the password goes to the vault with the client and TLS keys. Scripts, plugins and compression in a profile are left out, and the editor lists what was used, left out and not needed.
- MySQL and Postgres connections, and SSH hosts, can go through a VPN. Fran opens its own tunnel when you connect, with OpenVPN 3 running in a separate process and a network stack of its own, so it needs no admin rights and nothing else on the computer uses the VPN. Everything using one VPN shares its tunnel, and it closes 30 seconds after the last one is done. A one-time code is asked for on each connect and never saved.
- A VPN can be turned on for the whole computer, with the switch on its row in the VPN panel or from the shield in the title bar, which turns green while one is on. Fran runs the installed OpenVPN 2.6 or newer for it: through OpenVPN's Interactive Service on Windows, where your account has to be an administrator or in the "OpenVPN Administrators" group, and after your admin password on macOS and Linux. The client key stays in Fran, which signs for OpenVPN, and the login goes over OpenVPN's management connection, never to a file. OpenVPN connects to Fran, which checks it's the OpenVPN it started before saying anything, and OpenVPN stops by itself if Fran closes or crashes. While it's on, Fran's own connections through that VPN can only leave through its adapter, look names up with the VPN's own DNS servers, and work over IPv6 too. Connections and terminals using the VPN move over by themselves, and back to Fran's own tunnel when you turn it off. The confirm lists what's using it. A new one-time code, a wrong password or a second sign-in step from the server is asked for in the window while it stays on. Profiles marked "Needs system mode", like ones with legacy ciphers, a TAP adapter, or an HTTP or SOCKS proxy, work this way, and so does a legacy fallback cipher. Ed25519 client keys work both ways. The VPN editor has two settings for it: send all traffic through the VPN, and use the VPN's DNS. Turning off the VPN client turns these VPNs off too.
- Settings > VPN, with the OpenVPN program and its version, how long an own tunnel stays open after its last connection (30 seconds, 2 or 10 minutes), and how long a connect waits for a VPN. On Windows it shows the program the Interactive Service runs and whether your sign-in may start it with Fran's settings.
- Open now lists running VPNs with Disconnect, or Turn off for ones on for the computer.
- VPNs can be put in order and moved between groups by dragging, and groups can be added, renamed and removed, the same way as SSH hosts.
- Fran keeps running in the tray when you close the window, so VPNs, port forwards, terminals and the MCP server keep going. It's on by default, and can be turned off in Settings > General. The tray menu opens Fran, turns each VPN on or off for the computer, stops running port forwards and locks the app. The icon gets a green dot while a VPN is on for the computer. Quitting asks first when something is running, for example "2 VPNs, 1 port forward and 3 terminals stop". The first time the window goes to the tray, a notification says Fran is still running. On macOS the Dock icon goes away while the window is hidden. On a desktop without a tray, closing the window asks the same before quitting.
- Profiles that keep their key elsewhere work too. A PKCS#12 file is read on import after asking for its password, and its key goes to the vault like any other, so it works both ways. A key in the Windows certificate store is used by OpenVPN while the VPN is on for the computer. A smartcard works while it's on for the computer once you choose its PKCS#11 library in the VPN's settings, and its PIN is asked for in the window. Fran never takes that library from the file, since it runs inside OpenVPN as admin. Static key profiles are left out with the reason: they'd need the key in a file on disk, and OpenVPN 2.7 removed that mode.
- After turning a VPN off for the computer, one that asks for a one-time code asks for a new one, so what was using it moves back to Fran's own tunnel right away.
- Fran's own VPN service, on Windows, macOS and Linux, turns VPNs on for the whole computer without the installed OpenVPN and without asking for the admin password each time. Set it up once in Settings > VPN or on the welcome screen, which asks for admin rights once. Choose who may use it: everyone signed in at this computer, or only you and administrators. It sets the computer's address, routes and DNS from what the server pushes, keeps the VPN server itself outside the tunnel, and removes all of it when the VPN goes off, when Fran closes and after a crash. An OpenVPN client key stays in Fran. A WireGuard key is handed to the service while the VPN is on, since WireGuard has no way to keep it out, and is never written to disk there. Update and Remove are on the same page, and uninstalling Fran removes it too. On NixOS it's turned on with `programs.fran.vpnService`.
- VPNs turn on for this computer through Fran's VPN service. Turning one on before the service is set up offers to set it up. Settings > VPN can send OpenVPN profiles to the installed OpenVPN instead. Profiles Fran's engine can't run, like TAP, legacy ciphers and proxies, use the installed OpenVPN either way, and say "Needs the installed OpenVPN". On Windows an Install OpenVPN button runs winget, on macOS it runs Homebrew, and on Linux the command for your distribution is shown to copy.
- WireGuard profiles, as an own tunnel or on for the whole computer through Fran's VPN service. Import a wg-quick .conf or fill one in, with the private key pasted or generated in Fran and kept in the vault. Only its public key is shown, to give to the server. Scripts in the file never run. A file with more than one peer is refused, since a VPN in Fran is one peer. Export writes a standard .conf with the keys inside, after your system confirms it's you.
- While a database, terminal or file browser waits for its VPN to connect, it says so. The time the VPN takes no longer counts toward the SSH connect timeout.

### Changed

- Fran DB is now called Fran. It installs as a new app, and on its first start it copies your connections, saved passwords, settings, saved queries, open tabs and agent history from Fran DB. Fran DB itself is left as it was, so you can uninstall it once Fran has everything. On NixOS the flake's package and the input in the examples are now `fran`.
- The prompt for a new SSH host key shows where to check the fingerprint on the server, which hop of a longer route it's for, and whether OpenSSH on this computer already trusts the key.
- A changed SSH host key can no longer be accepted with one click. The warning shows the old and new fingerprints and only replaces the trusted key after you type the host name.
- SSH connections no longer offer SHA-1 key exchange, `ssh-rsa` SHA-1 signatures, DSA or CBC ciphers.
- SSH connections refuse every channel a server tries to open unless Fran asked for it, such as X11, agent or forwarded port channels.
- Home is tighter, with less space between and inside panels, and its default layout has three panels: Databases and SSH hosts on the left, Recent on the right. Port forwards and Snippets are in the Panels menu. A layout you arranged yourself stays as it is.
- SSH hosts show as cards, like database connections, with the login, a Browse files button and Open terminal. The button in the panel header switches to a compact one-line view.
- Database cards and the rows in Home's panels share the same icon tiles and badges, and host rows get the color fill too when it's on.

## [0.1.5] - 2026-11-01

### Added

- MySQL and Postgres connections can reach a database in a Kubernetes cluster through `kubectl port-forward`. The connection form lists the contexts in your kubeconfig and always uses the one you pick, whatever kubectl's current context is.
- Connections can be put in groups. The connection editor has a Group field that suggests existing groups, and the Connections tab shows a section per group. Edit groups on the Connections tab adds, renames and removes groups, and shows handles for reordering groups and connections by dragging. Dragging a connection into another group moves it there.

## [0.1.4] - 2026-10-27

### Added

- Query tabs have a Format button (Shift+Alt+F) that tidies up the SQL, or only the selected part, in the connection's dialect. Settings > Formatting sets the letter case of keywords, functions and data types, the indent, where AND and OR go, how long an expression stays on one line and the blank lines between statements, with a live preview.
- Settings > Results has a default row limit that new query tabs start with. Changing the limit in a tab only affects that tab, and each tab remembers its own.

### Changed

- Settings open in their own tab instead of a dialog.
- The row limit now stops the server from sending more rows than the limit, for every query, not only the ones Fran DB writes. Before, the whole result was sent and the extra rows thrown away, which made big tables slow to open.
- Agent queries now time out after 60 seconds instead of 30, and the timeout can be changed on the Agents tab's Server page.
- Query table puts the row limit in the SELECT itself. Changing the tab's limit updates the LIMIT too, as long as you haven't edited the query.

### Fixed

- "No limit" returned no rows on SQLite and Cloudflare D1.

## [0.1.3] - 2026-10-26

### Added

- Each database (or schema on PostgreSQL) shows its total size next to its name in the tree.
- Query results that can be edited have an Add row button, including results from an empty table.
- Query results from Cloudflare D1 can be edited when the query reads one table and lists its columns by name or with `*`.
- Connection tabs and the tabs inside a database can be reordered by dragging them.
- Coding agents like Claude Code, Cursor and VS Code can use your connections through an MCP server built into Fran DB. The robot button in the title bar opens the Agents tab, where you turn the server on and copy the JSON to add it to an agent. Its Access page sets what agents may do with each connection: nothing (the default), read, or read and ask before changing anything, optionally limited to some databases. Agents get tools to explore the schema and read rows, so they rarely need their own SQL. Every change they want to make opens a review in Fran DB showing each row's current and new values, the SQL and the agent's request, and only runs after you approve it. The Activity page lists open and closed agent sessions and every call with the SQL it ran and what the agent got back, kept encrypted and browsable by day. The Server page has switches to turn off raw SQL or changes for every agent and to stop keeping history.

### Changed

- When you run several statements, each one shows up in Messages, and its results in their own tab, as soon as it finishes instead of all at the end. Messages stays in front while they come in.
- Tinting the whole tab and connection card with the connection's color is now one switch in Settings > Appearance, on by default, instead of a setting on each connection.
- The separate table data view is gone. Double-clicking a table, or Query table in its menu, opens a query tab with a SELECT for it and runs it. If that table already has a tab whose SELECT you haven't changed, that tab comes to the front instead. Settings > Results has a switch to open the SELECT without running it.

## [0.1.2] - 2026-10-25

### Added

- Port forwarding for SSH tunnel connections. The cable button on a connection card, or in the schema browser header once connected, opens a dialog where you pick a local port. While the forward runs, other programs on your machine reach the database at `127.0.0.1:<port>` through the tunnel, with or without a session open. Stop it from the same dialog. The port you used last is remembered per connection, but a forward never starts on its own.
- SQLite databases. Open a database file, optionally read only, browse and edit its tables, and run queries. Attached databases show in the tree next to `main`. Foreign keys are enforced by default, and you can turn that off per connection. When a change fails because an index or trigger calls a function that only the app that created the database has, the error names that index or trigger and explains why.
- Cloudflare D1 databases, through Cloudflare's API with an account ID and an API token. Browse, query and edit them like SQLite, and switch to the account's other D1 databases without reconnecting. D1 doesn't allow BEGIN and COMMIT, so saved edits are sent as one batch that applies all together or not at all.
- The table designer works with SQLite tables. It can rename tables and columns, add and drop columns, and change indexes. SQLite can't change a column's type, NULL setting or default in place, so the designer tells you when a change would mean rebuilding the table.
- Connections can use a custom color, picked with the eyedropper swatch after the presets.
- A connection's color can tint its whole tab and connection card instead of just the dot and icon.

## [0.1.1] - 2026-10-24

### Added

- SSH tunnels can log in with your SSH agent. It uses `SSH_AUTH_SOCK` on macOS and Linux, and the OpenSSH agent or Pageant on Windows. Agents with their own socket, like 1Password, can be set per connection.
- Nix flake with a dev shell and a Linux package. Nix installs say when an update is out but leave installing it to Nix.

### Changed

- The tabs now sit in the window's title bar, with the window buttons next to them. There's always some empty space before the buttons for dragging the window, and double-clicking it maximizes. On macOS the usual window buttons stay where they are.
- Opening Fran DB while it's already running brings the open window to the front instead of starting a second copy.

### Fixed

- The app no longer opens to a blank white window while it starts. A small loading window shows instead, and the app replaces it once it's ready. You can drag the loading window around, and closing it quits the app.

## [0.1.0] - 2026-10-23

- Initial release
