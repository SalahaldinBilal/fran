import styles from "./Home.module.scss";
import { Show, createMemo, createSignal, onCleanup, onMount } from "solid-js";
import { Dynamic } from "solid-js/web";
import { ArrowLeftRight, Check, CodeXml, Database, Download, LayoutGrid, Plus, RotateCcw, Search, Server, Shield, ShieldAlert } from "lucide-solid";
import useVpnEditorState from "@core/states/vpnEditorState";
import useSettingsState from "@core/states/settingsState";
import useHostEditorState from "@core/states/hostEditorState";
import useForwardRulesState from "@core/states/forwardRulesState";
import useSnippetsState from "@core/states/snippetsState";
import useSshImportState from "@core/states/sshImportState";
import useVaultState from "@core/states/vaultState";
import usePromptState from "@core/states/promptState";
import useWorkspaceState, { HOME_TAB_ID } from "@core/states/workspaceState";
import useModalState from "@core/states/modalState";
import useContextMenuState, { MenuItem } from "@core/states/contextMenuState";
import { featureOn } from "@core/helpers/features";
import { HOME_PANELS, defaultHomeLayout, isHomePanel } from "@core/helpers/homeLayout";
import { TileNode, addPanel, panelsIn, removePanel } from "@core/helpers/tiling";
import { IS_MAC } from "@core/helpers/platform";
import { ConnectionProfile } from "@core/types";
import Button from "@core/components/Button/Button";
import Input from "@core/components/Input/Input";
import EmptyState from "@core/components/EmptyState/EmptyState";
import TileLayout from "@core/components/Tiling/TileLayout";
import ConnectionEditor from "./ConnectionEditor/ConnectionEditor";
import { HOME_PANEL_INFO } from "./panels";
import SearchResults, { SearchResult, searchEverything } from "./SearchResults";

type EditorState = { open: false } | { open: true, profile: ConnectionProfile | null };

function Home() {
  const { settings, update } = useSettingsState;
  const vault = useVaultState;
  const { confirm } = usePromptState;
  const { openMenuAt } = useContextMenuState;
  const [search, setSearch] = createSignal("");
  const [editor, setEditor] = createSignal<EditorState>({ open: false });
  const [resultsOpen, setResultsOpen] = createSignal(false);
  const [activeResult, setActiveResult] = createSignal(0);
  const results = createMemo(() => searchEverything(search()));
  const showResults = createMemo(() => resultsOpen() && search().trim() !== "");
  let searchInput: HTMLInputElement | undefined;

  const editingProfile = createMemo(() => {
    const state = editor();
    return state.open ? state.profile : null;
  });
  const databaseOn = createMemo(() => featureOn("database"));
  const vaultProblem = createMemo(() => {
    const status = vault.status();
    return status && !status.available ? status.message ?? "" : null;
  });
  // A plain copy, since the tree helpers build new trees from it and the settings store merges values in place.
  const tree = createMemo<TileNode | null>(() => (settings.homeLayout ? JSON.parse(JSON.stringify(settings.homeLayout)) : null));

  function saveLayout(next: TileNode | null) {
    void update({ homeLayout: next });
  }

  function panelVisible(panel: string): boolean {
    return isHomePanel(panel) && featureOn(HOME_PANEL_INFO[panel].feature);
  }

  function openPanelsMenu(event: MouseEvent) {
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    const present = panelsIn(tree());
    const items: MenuItem[] = HOME_PANELS.filter(id => featureOn(HOME_PANEL_INFO[id].feature)).map(id => ({
      label: HOME_PANEL_INFO[id].title,
      icon: present.includes(id) ? Check : undefined,
      onSelect: () => saveLayout(present.includes(id) ? removePanel(tree(), id) : addPanel(tree(), id)),
    }));
    openMenuAt({ x: rect.left, y: rect.bottom + 4 }, [
      ...items,
      { separator: true },
      { label: "Reset layout", icon: RotateCcw, onSelect: () => saveLayout(defaultHomeLayout()) },
    ]);
  }

  function openNewMenu(event: MouseEvent) {
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    const items: MenuItem[] = [
      ...(databaseOn() ? [{ label: "Database connection", icon: Database, onSelect: () => setEditor({ open: true, profile: null }) }] : []),
      { label: "SSH host", icon: Server, onSelect: () => useHostEditorState.open(null) },
      { label: "Port forward", icon: ArrowLeftRight, onSelect: () => useForwardRulesState.openEditor(null) },
      ...(featureOn("ssh") ? [{ label: "Snippet", icon: CodeXml, onSelect: () => useSnippetsState.openEditor(null) }] : []),
      ...(featureOn("vpn") ? [{ label: "VPN", icon: Shield, onSelect: () => useVpnEditorState.open(null) }] : []),
      { separator: true },
      { label: "Import from ~/.ssh/config", icon: Download, onSelect: useSshImportState.open },
      ...(featureOn("vpn") ? [{ label: "Import a VPN profile", icon: Download, onSelect: () => void useVpnEditorState.importFile() }] : []),
    ];
    openMenuAt({ x: rect.left, y: rect.bottom + 4 }, items);
  }

  async function resetVault() {
    const confirmed = await confirm({
      title: "Reset the vault?",
      message: "Every saved password and passphrase will be deleted. Connections stay, you'll be asked for credentials again.",
      confirmLabel: "Reset vault",
      danger: true,
    });
    if (confirmed) await vault.reset();
  }

  function pick(result: SearchResult) {
    setResultsOpen(false);
    searchInput?.blur();
    result.run();
  }

  function onSearchKeyDown(event: KeyboardEvent) {
    const count = results().length;
    if (event.key === "ArrowDown" && count > 0) {
      event.preventDefault();
      setResultsOpen(true);
      setActiveResult((activeResult() + 1) % count);
    } else if (event.key === "ArrowUp" && count > 0) {
      event.preventDefault();
      setActiveResult((activeResult() - 1 + count) % count);
    } else if (event.key === "Enter" && showResults() && count > 0) {
      event.preventDefault();
      pick(results()[Math.min(activeResult(), count - 1)]);
    } else if (event.key === "Escape" && showResults()) {
      event.preventDefault();
      setResultsOpen(false);
    }
  }

  function onKeyDown(event: KeyboardEvent) {
    if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== "k") return;
    if (useWorkspaceState.store.activeGlobalTabId !== HOME_TAB_ID || useModalState.anyOpen()) return;
    event.preventDefault();
    searchInput?.focus();
    searchInput?.select();
  }

  onMount(() => {
    window.addEventListener("keydown", onKeyDown);
    onCleanup(() => window.removeEventListener("keydown", onKeyDown));
  });

  return (
    <div class={styles.Home}>
      <header class={styles.Header}>
        <h1>Home</h1>
        <div class={styles.Spacer} />
        <div class={styles.SearchBox}>
          <Input
            class={styles.Search}
            type="search"
            value={search()}
            onValue={value => {
              setSearch(value);
              setActiveResult(0);
              setResultsOpen(true);
            }}
            placeholder="Search"
            before={<Search size={14} />}
            after={<kbd class={styles.Kbd}>{IS_MAC ? "⌘K" : "Ctrl K"}</kbd>}
            inputRef={element => {
              searchInput = element;
              element.addEventListener("focus", () => setResultsOpen(true));
            }}
            onBlur={() => setResultsOpen(false)}
            onKeyDown={onSearchKeyDown}
          />
          <Show when={showResults()}>
            <SearchResults results={results()} active={activeResult()} onPick={pick} onHover={setActiveResult} />
          </Show>
        </div>
        <Button variant="subtle" onClick={openPanelsMenu}>
          <LayoutGrid size={14} />
          Panels
        </Button>
        <Button variant="primary" onClick={openNewMenu}>
          <Plus size={14} />
          New
        </Button>
      </header>

      <Show when={vaultProblem() !== null}>
        <div class={styles.Banner}>
          <ShieldAlert size={16} />
          <span>Saved passwords are unavailable. {vaultProblem()}</span>
          <Button size="sm" variant="subtle" onClick={resetVault}>Reset vault</Button>
        </div>
      </Show>

      <div class={styles.Body}>
        <TileLayout
          tree={tree()}
          visible={panelVisible}
          label={panel => (isHomePanel(panel) ? HOME_PANEL_INFO[panel].title : panel)}
          onChange={saveLayout}
          renderPanel={(panel, controls) => (
            <Show when={isHomePanel(panel) ? HOME_PANEL_INFO[panel] : null}>
              {info => (
                <Dynamic
                  component={info().view}
                  controls={controls}
                  search={search()}
                  onEditConnection={(profile: ConnectionProfile | null) => setEditor({ open: true, profile })}
                />
              )}
            </Show>
          )}
          empty={
            <div class={styles.Center}>
              <EmptyState
                icon={LayoutGrid}
                title="No panels"
                description="Add the ones you want from the Panels menu."
                actions={<Button variant="subtle" onClick={() => saveLayout(defaultHomeLayout())}>Reset layout</Button>}
              />
            </div>
          }
        />
      </div>

      <ConnectionEditor
        show={editor().open}
        profile={editingProfile()}
        onClose={() => setEditor({ open: false })}
      />
    </div>
  );
}

export default Home;
