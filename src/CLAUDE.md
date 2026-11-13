# Frontend

## State and calls

- Global state is `createRoot(useXStateInner)` singletons in `states/`. `workspaceState` holds the global tabs (Home, sessions, terminals, file browsers and the single tabs like Settings) and, per session, a tab scope per database. Workspace and tab components stay mounted while hidden so editors keep their state.
- Tab kinds whose state lives elsewhere close through `registerTabCloser(kind, close, guard)`. The optional guard is asked before the tab closes (SFTP asks when transfers are running).
- Every backend call goes through `safeInvoke` (`helpers/safeInvoke.ts`), typed by the `Commands` map.
- The `@core` alias maps to `src/`.

## Databases

- `databases/` holds a `DatabaseModule` per kind (connection form, defaults, connection string parser, CodeMirror dialect, SQL helpers). `parseConnectionString` in `databases/index.ts` tries the form's kind first, then the others. Use `withDatabaseModule(profile, (module, options) => ...)` to keep kind and options paired. Never branch on `kind === "mysql"` in generic UI.

## UI rules

- Context menus go through `contextMenuState.openContextMenu(event, items)` (items can have `children` for submenus). The webview's native menu is suppressed globally in `helpers/globalContextMenu.ts`, text fields get a Cut/Copy/Paste menu there. Clipboard access goes through `helpers/clipboard.ts` (Tauri clipboard plugin).
- Icons are imported from `@core/icons` (`src/icons.ts`), never from `lucide-solid`, whose barrel makes the dev server load every icon. A new icon gets one line there, from its own `lucide-solid/icons/<name>` path.
- Tooltips are `Button`'s `tooltip` prop, or `ref={element => tooltip(element, () => text)}` (`components/Tooltip/Tooltip.tsx`) on any other element, shown by the one `TooltipHost`. Never use the native `title` attribute.
- Anything that needs the OS to confirm the user (`reveal_secret`, `copy_secret`, exports) goes through `withUserCheck` in `helpers/revealSecret.ts`, which handles a cancelled prompt, the app lock fallback and the one-time polkit setup. `SecretField` shows a stored value when its `SecretEditor` has an `owner`. Copy is only on the Secrets page (`pages/Secrets/`, tab kind `secrets`). Shown values hide after 30 seconds and when the app locks. The Passwords page unlocks every value at once for 5 minutes (`savedSecretsState`, the window's length comes from Rust), and hides them while the tab isn't shown.
- Every `Modal` is mounted once at start, so mount order can't decide which is on top. Each one takes a layer from `modalState.nextLayer()` when shown, so the one opened last is.
- Confirmations, text prompts, credential prompts and host key prompts go through `promptState`. Connect-like calls go through `withConnectPrompts` (`helpers/connectFlow.ts`).
- Colors, radii, font sizes and shadows come from the tokens in `styles/global.scss`. Don't hardcode hex values in component styles except for syntax highlight colors.
- The UI should look polished and intentionally designed, not like a generic template. Avoid stock patterns such as an accent stripe on the active tab or on cards, but don't strip styling to get there.
- Cards and panel rows build on `components/ItemParts` (`ItemIcon`, `ItemBadge`), so they stay one family.

## Window

- There's no native title bar. The global `TabStrip` is the title bar (`dragRegion`), with `WindowControls` on Windows/Linux and the native traffic lights on macOS (`tauri.macos.conf.json`, which replaces the whole `windows` list, so keep both window entries in sync). Nothing may block dragging it: modal backdrops start below `--titlebar-height`, and while any `Modal` is open (`modalState`) the tabs and the settings button ignore the mouse so presses on them drag instead. Check the OS with `IS_MAC` (`helpers/platform.ts`, OS plugin).
- The main window starts hidden. A splash window (`public/splash.html`, `src-tauri/src/splash.rs`) shows until `App` calls `show_main_window` after its first paint.
- `LockScreen` covers everything below the title bar while the app lock is on and locked, above modals, so anything it needs to confirm happens inside it. `lockState` locks after `settings.lockAfterMinutes` idle (0 means only at start).

## Features, Home and onboarding

- The database client, the SSH client and the VPN client can each be turned off (`settings.features`, at least one stays on). VPN profiles stay pickable in the host and connection editors with the VPN client off, and their own tunnels keep working, but turning the VPN client off stops the VPNs that are on for the computer. Turning one on or off goes through `setVpnOnComputer` in `helpers/vpnActions.ts` (confirm listing `vpnUserNames`, then `withConnectPrompts`, then reconnecting the terminals, file tabs and forwards that dropped). `watchVpnPrompts` asks for whatever a VPN on for the computer needs mid-session. The tray menu, its events and the quit confirm are in `helpers/tray.ts`. A database module says what a VPN would carry with `vpnLeg`. Generic UI asks `featureOn` and `tabFeature` in `helpers/features.ts` instead of reading the setting, and turning a part off goes through `setFeatures`, which closes its tabs (with a confirm) and stops the MCP server when the database client goes. Settings pages carry a `feature`.
- Home is a set of panels in a tiling layout (`components/Tiling/TileLayout`, tree helpers in `helpers/tiling.ts`). The layout is a binary tree of splits, saved in `settings.homeLayout`. `TileLayout` draws every panel as one flat, absolutely placed list keyed by panel name, so docking, swapping and resizing only change styles and never remount a panel. Panels live in `pages/Home/panels/` (registry in `index.ts`, each draws itself in `PanelFrame`), and a panel whose part is off is pruned at render time without leaving the saved tree.
- Home's search filters every panel, and `SearchResults` lists matches from both halves (connections, hosts, forwards, snippets) for the keyboard.
- The welcome screen (`pages/Onboarding/`) picks the parts. It covers the content area while `settings.onboardingVersion` is below `ONBOARDING_VERSION`, or after Settings > General > Show again (`onboardingState`), and waits for settings and connections to load. It never shows when settings failed to load.

## Settings and saved state

- App settings belong to the frontend (`states/settingsState.ts` owns the shape and defaults, Rust only stores the JSON). Unknown or missing keys fall back to the defaults in `fromStored`.
- Settings is a global tab (`pages/Settings/`), opened from the gear at the right of the top tab bar. Its side menu lists one page per area (`sections` in `Settings.tsx`), each built from `SettingsPage`, `SettingGroup` and `SettingRow` in `SettingsLayout.tsx`.
- Open tabs persist per connection in `tab_state.json`. The frontend owns the shape (`PersistedSession` in `workspaceState.ts`, versioned) and writes it about 400ms after any tab change or keystroke. Live query text lives in `queryTexts`, outside the store.
- Saved queries and tabs are separate. Opening a saved query puts a copy of its SQL in a new tab, and nothing in a tab ever changes a saved query. Ctrl+S in a tab saves its text as a new saved query. Saved queries are only edited in `SavedQueryEditor`, from the Saved queries panel.

## Query tabs and editing

- There's no separate table data view. Double-clicking a table, or Query table in its menu, calls `workspaceState.queryTable`: it opens a query tab with `selectRowsSql`, or focuses one whose text is still that SELECT (whitespace ignored), and runs it when the `runTableQueryOnOpen` setting is on (the tab's unsaved `runOnOpen` flag, so restored tabs don't rerun).
- Row editing (`helpers/rowEdits.ts`, used by query results in `QueryTab`) keeps edits client-side until they're reviewed and run. Query results are editable only when every column is a plain column (`sourceName`) of one table and that table's whole primary key (`get_primary_key`) is selected. SQL is written with `sourceName`, so aliases are fine. The check also runs on empty results, so "Add row" works on an empty table.
- Slow queries is a database tab of kind `activity` (`pages/tabs/ActivityTab/`), one per session, opened by `workspaceState.openActivity` from the gauge in the schema browser header when `info.activity` has a part. Running now refreshes every 3 seconds only while the tab is the one showing.
- Query results filter client-side (`ResultGrid` with `filter`), and the grid maps display positions to source rows so edits keep working. Selection and copy formats are in `helpers/copyRows.ts`.
- `ValueViewer` picks a view by column: dates and times (`views/temporal.ts` also reads pasted Unix time, ISO 8601 and other formats, zoned input becomes UTC), numbers, binary, JSON, text, and ENUM/SET values from `get_column_choices`. Whether a cell edits inline or in the viewer by default is the `cellEditMode` setting.

## Editor

- `SqlEditor` takes a `SchemaCatalog` (`helpers/catalog.ts`) for the schema checker (`schemaLinter.ts`) and a lang-sql namespace for completion. Both come from the session's cached `objects` and `columns`, loaded per database by `ensureCatalog` and refreshed by `refreshCatalog` after DDL.
- The checker walks lang-sql's syntax tree per statement. It must stay lenient: when any table in a statement can't be resolved (CTE, derived table, unloaded database) it skips unqualified column checks rather than guess.
