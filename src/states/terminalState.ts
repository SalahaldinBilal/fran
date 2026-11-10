import { createRoot } from "solid-js";
import { createStore, produce } from "solid-js/store";
import { Channel } from "@tauri-apps/api/core";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { withConnectPrompts } from "@core/helpers/connectFlow";
import { errorMessage, isAppError } from "@core/helpers/errors";
import { generateId } from "@core/helpers";
import { SplitDir, TileNode, leaf, panelsIn, removePanel, splitPanel } from "@core/helpers/tiling";
import { Snippet, TerminalEvent, TerminalInfo } from "@core/types";
import useWorkspaceState, { registerTabCloser } from "./workspaceState";
import useSshState from "./sshState";
import useSnippetsState from "./snippetsState";
import useToastState from "./toastState";
import useSettingsState from "./settingsState";

export type PaneStatus = "connecting" | "open" | "closed";

export type PaneState = {
  status: PaneStatus,
  terminalId: string | null,
  reason: string | null,
  // Text waiting for the user to confirm a paste that would run commands.
  pendingPaste: string | null,
};

export type TerminalTab = {
  id: string,
  hostId: string,
  layout: TileNode,
  panes: Record<string, PaneState>,
  // Creation order, for pane numbers in their headers.
  order: string[],
  focus: string,
  drawer: boolean,
  connectionId: string | null,
  info: TerminalInfo | null,
  // A snippet marked "Ask first" waiting for its inline confirm.
  pendingSnippet: string | null,
};

// What a mounted pane gives the state so output and notices reach its xterm.
export type PaneSink = {
  write: (data: Uint8Array | string) => void,
  size: () => { cols: number, rows: number } | null,
  // Puts text at the prompt the way a paste would, bracketed when the shell asked for it.
  paste: (text: string) => void,
  focus: () => void,
};

const STARTUP_QUIET_MS = 300;
const encoder = new TextEncoder();

function logging(): boolean {
  return useSettingsState.settings.terminal.logOutput;
}

function dim(text: string): string {
  return `\r\n\x1b[2m${text}\x1b[0m\r\n`;
}

function useTerminalStateInner() {
  const workspace = useWorkspaceState;
  const ssh = useSshState;
  const [store, setStore] = createStore<{ tabs: Record<string, TerminalTab> }>({ tabs: {} });

  const sinks = new Map<string, PaneSink>();
  const queues = new Map<string, { buffer: number[], sending: boolean }>();
  const startupTimers = new Map<string, ReturnType<typeof setTimeout>>();
  const pendingStartup = new Map<string, string>();
  // A fresh login in progress per tab, so a split made meanwhile reuses it instead of logging in again.
  const opening = new Map<string, Promise<void>>();

  function tab(id: string): TerminalTab | undefined {
    return store.tabs[id];
  }

  function hostLabel(tabId: string): string {
    const current = tab(tabId);
    return (current && ssh.host(current.hostId)?.label) ?? "SSH host";
  }

  function newPane(): PaneState {
    return { status: "connecting", terminalId: null, reason: null, pendingPaste: null };
  }

  function open(hostId: string) {
    const host = ssh.host(hostId);
    if (!host) return;
    const id = generateId();
    const paneId = generateId();
    setStore("tabs", id, {
      id,
      hostId,
      layout: leaf(paneId),
      panes: { [paneId]: newPane() },
      order: [paneId],
      focus: paneId,
      drawer: false,
      connectionId: null,
      info: null,
      pendingSnippet: null,
    });
    workspace.addGlobalTab({ id, kind: "terminal" });
    workspace.rememberRecent(hostId, "ssh");
  }

  function setPane(tabId: string, paneId: string, patch: Partial<PaneState>) {
    if (!store.tabs[tabId]?.panes[paneId]) return;
    setStore("tabs", tabId, "panes", paneId, patch);
  }

  function attach(paneId: string, sink: PaneSink) {
    sinks.set(paneId, sink);
  }

  function detach(paneId: string) {
    sinks.delete(paneId);
    queues.delete(paneId);
    clearTimeout(startupTimers.get(paneId));
    startupTimers.delete(paneId);
    pendingStartup.delete(paneId);
  }

  function typeStartupWhenQuiet(paneId: string) {
    const command = pendingStartup.get(paneId);
    if (command === undefined) return;
    clearTimeout(startupTimers.get(paneId));
    startupTimers.set(paneId, setTimeout(() => {
      startupTimers.delete(paneId);
      pendingStartup.delete(paneId);
      sinks.get(paneId)?.paste(command);
    }, STARTUP_QUIET_MS));
  }

  // The close event can arrive before the open call returns, so it waits in `early` until the pane knows its id.
  type PaneRef = { id: string | null, early: TerminalEvent | null };

  function channels(tabId: string, paneId: string, ref: PaneRef) {
    const output = new Channel<ArrayBuffer>();
    output.onmessage = data => {
      sinks.get(paneId)?.write(new Uint8Array(data));
      typeStartupWhenQuiet(paneId);
    };
    const events = new Channel<TerminalEvent>();
    events.onmessage = event => {
      if (ref.id === null) ref.early = event;
      else paneClosed(tabId, paneId, ref.id, event);
    };
    return { output, events };
  }

  function paneClosed(tabId: string, paneId: string, terminalId: string | null, event: TerminalEvent) {
    const current = tab(tabId);
    const pane = current?.panes[paneId];
    if (!current || !pane || pane.terminalId !== terminalId) return;
    setPane(tabId, paneId, { status: "closed", terminalId: null, reason: event.reason });
    if (event.connectionLost) setStore("tabs", tabId, "connectionId", null);
    const why = event.reason ? `${event.reason}. ` : "";
    sinks.get(paneId)?.write(dim(`${why}Press Enter to reconnect.`));
  }

  async function openFresh(tabId: string, size: { cols: number, rows: number }, refs: ReturnType<typeof channels>): Promise<TerminalInfo | null> {
    const current = tab(tabId);
    if (!current) return null;
    return withConnectPrompts(
      { connectionId: null, connectionName: hostLabel(tabId) },
      secrets => safeInvoke("open_terminal", { hostId: current.hostId, ...size, log: logging(), secrets, onOutput: refs.output, onEvent: refs.events }),
    );
  }

  async function openOnConnection(connectionId: string, size: { cols: number, rows: number }, refs: ReturnType<typeof channels>): Promise<TerminalInfo | null> {
    try {
      return await safeInvoke("open_terminal_pane", { connectionId, ...size, log: logging(), onOutput: refs.output, onEvent: refs.events });
    } catch (error) {
      // The connection went away since, so the caller logs in again.
      if (isAppError(error) && error.detail.kind === "notFound") return null;
      throw error;
    }
  }

  async function connect(tabId: string, paneId: string) {
    const current = tab(tabId);
    if (!current?.panes[paneId] || current.panes[paneId].status === "open") return;
    setPane(tabId, paneId, { status: "connecting", reason: null });

    const waiting = opening.get(tabId);
    if (waiting) await waiting.catch(() => undefined);

    const size = sinks.get(paneId)?.size() ?? { cols: 80, rows: 24 };
    const ref: PaneRef = { id: null, early: null };
    const refs = channels(tabId, paneId, ref);

    let fresh = false;
    let info: TerminalInfo | null = null;
    let finish = () => {};
    try {
      const connectionId = tab(tabId)?.connectionId;
      if (connectionId) info = await openOnConnection(connectionId, size, refs);
      if (!info) {
        fresh = true;
        opening.set(tabId, new Promise(resolve => { finish = resolve; }));
        info = await openFresh(tabId, size, refs);
      }
    } catch (error) {
      setPane(tabId, paneId, { status: "closed", reason: errorMessage(error) });
      sinks.get(paneId)?.write(dim(`${errorMessage(error)}. Press Enter to try again.`));
      return;
    } finally {
      if (fresh) {
        opening.delete(tabId);
        finish();
      }
    }

    if (!info) {
      setPane(tabId, paneId, { status: "closed", reason: "Cancelled" });
      sinks.get(paneId)?.write(dim("Cancelled. Press Enter to connect."));
      return;
    }
    if (!tab(tabId)?.panes[paneId]) {
      void safeInvoke("close_terminal", { id: info.id });
      return;
    }

    ref.id = info.id;
    const opened = info;
    setStore("tabs", tabId, produce(state => {
      state.connectionId = opened.connectionId;
      state.info = opened;
      state.panes[paneId].status = "open";
      state.panes[paneId].terminalId = opened.id;
      state.panes[paneId].reason = null;
    }));
    if (ref.early) {
      paneClosed(tabId, paneId, opened.id, ref.early);
      return;
    }

    const startup = fresh ? useSnippetsState.find(ssh.host(opened.hostId)?.startupSnippetId ?? null) : undefined;
    if (startup) pendingStartup.set(paneId, startup.command);
  }

  // Keystrokes go one call at a time, since separate invokes can be handled out of order.
  async function flush(paneId: string, terminalId: string) {
    const queue = queues.get(paneId);
    if (!queue || queue.sending) return;
    queue.sending = true;
    while (queue.buffer.length > 0) {
      const data = queue.buffer.splice(0);
      await safeInvoke("terminal_input", { id: terminalId, data }).catch(() => undefined);
    }
    queue.sending = false;
  }

  function send(tabId: string, paneId: string, data: string | Uint8Array) {
    const pane = tab(tabId)?.panes[paneId];
    if (!pane) return;
    if (pane.status === "closed") {
      const text = typeof data === "string" ? data : "";
      if (text.includes("\r")) void connect(tabId, paneId);
      return;
    }
    if (pane.status !== "open" || !pane.terminalId) return;
    const bytes = typeof data === "string" ? encoder.encode(data) : data;
    const queue = queues.get(paneId) ?? { buffer: [], sending: false };
    queues.set(paneId, queue);
    for (const byte of bytes) queue.buffer.push(byte);
    void flush(paneId, pane.terminalId);
  }

  function resize(tabId: string, paneId: string, cols: number, rows: number) {
    const pane = tab(tabId)?.panes[paneId];
    if (pane?.status !== "open" || !pane.terminalId) return;
    void safeInvoke("terminal_resize", { id: pane.terminalId, cols, rows }).catch(() => undefined);
  }

  function focus(tabId: string, paneId: string) {
    if (tab(tabId)?.focus !== paneId) setStore("tabs", tabId, "focus", paneId);
  }

  function activePane(tabId: string): string | null {
    const current = tab(tabId);
    if (!current) return null;
    return current.panes[current.focus] ? current.focus : current.order.find(id => current.panes[id]) ?? null;
  }

  function split(tabId: string, dir: SplitDir) {
    const target = activePane(tabId);
    if (!target) return;
    const paneId = generateId();
    setStore("tabs", tabId, produce(state => {
      state.panes[paneId] = newPane();
      state.order.push(paneId);
      state.layout = splitPanel(state.layout, target, paneId, dir);
      state.focus = paneId;
    }));
  }

  function setLayout(tabId: string, layout: TileNode | null) {
    if (layout) setStore("tabs", tabId, "layout", layout);
  }

  function closePane(tabId: string, paneId: string) {
    const current = tab(tabId);
    const pane = current?.panes[paneId];
    if (!current || !pane) return;
    if (panelsIn(current.layout).length <= 1) {
      workspace.closeGlobalTab(tabId);
      return;
    }
    if (pane.terminalId) void safeInvoke("close_terminal", { id: pane.terminalId });
    setStore("tabs", tabId, produce(state => {
      state.layout = removePanel(state.layout, paneId) ?? state.layout;
      delete state.panes[paneId];
      state.order = state.order.filter(id => id !== paneId);
      if (state.focus === paneId) state.focus = state.order[0] ?? "";
    }));
  }

  function closeTab(tabId: string) {
    const current = tab(tabId);
    if (!current) return;
    for (const pane of Object.values(current.panes)) {
      if (pane.terminalId) void safeInvoke("close_terminal", { id: pane.terminalId });
    }
    opening.delete(tabId);
    setStore("tabs", produce(tabs => { delete tabs[tabId]; }));
  }

  async function reconnectClosed(tabId: string) {
    const current = tab(tabId);
    if (!current) return;
    for (const paneId of current.order) {
      if (tab(tabId)?.panes[paneId]?.status === "closed") await connect(tabId, paneId);
    }
  }

  function setDrawer(tabId: string, open: boolean) {
    setStore("tabs", tabId, produce(state => {
      state.drawer = open;
      state.pendingSnippet = null;
    }));
  }

  // Run sends the command with Enter, so each line runs. Type it pastes without Enter.
  function applySnippet(tabId: string, snippet: Snippet, run: boolean, confirmed = false) {
    const paneId = activePane(tabId);
    if (!paneId) return;
    const pane = tab(tabId)?.panes[paneId];
    if (pane?.status !== "open") {
      useToastState.pushToast("This terminal isn't connected", "info");
      return;
    }
    if (run && snippet.confirm && !confirmed) {
      setStore("tabs", tabId, "pendingSnippet", snippet.id);
      return;
    }
    setStore("tabs", tabId, "pendingSnippet", null);
    if (run) send(tabId, paneId, `${snippet.command.replace(/\r?\n/g, "\r")}\r`);
    else sinks.get(paneId)?.paste(snippet.command);
    sinks.get(paneId)?.focus();
  }

  // The password goes from the vault to the server in Rust, so it never passes through here or the xterm.
  async function typePassword(tabId: string) {
    const paneId = activePane(tabId);
    const pane = paneId ? tab(tabId)?.panes[paneId] : undefined;
    if (!paneId || pane?.status !== "open" || !pane.terminalId) {
      useToastState.pushToast("This terminal isn't connected", "info");
      return;
    }
    try {
      await safeInvoke("terminal_type_password", { id: pane.terminalId });
    } catch (error) {
      useToastState.pushError(error);
    }
    sinks.get(paneId)?.focus();
  }

  function cancelSnippet(tabId: string) {
    setStore("tabs", tabId, "pendingSnippet", null);
  }

  function askPaste(tabId: string, paneId: string, text: string) {
    setPane(tabId, paneId, { pendingPaste: text });
  }

  function answerPaste(tabId: string, paneId: string, accepted: boolean) {
    const text = tab(tabId)?.panes[paneId]?.pendingPaste;
    setPane(tabId, paneId, { pendingPaste: null });
    if (accepted && text) sinks.get(paneId)?.paste(text);
    sinks.get(paneId)?.focus();
  }

  function tabs(): TerminalTab[] {
    return workspace.store.globalTabs.flatMap(globalTab => (globalTab.kind === "terminal" && store.tabs[globalTab.id] ? [store.tabs[globalTab.id]] : []));
  }

  registerTabCloser("terminal", closeTab);

  return {
    store,
    tab,
    tabs,
    open,
    attach,
    detach,
    connect,
    send,
    resize,
    focus,
    activePane,
    split,
    setLayout,
    closePane,
    reconnectClosed,
    setDrawer,
    applySnippet,
    cancelSnippet,
    typePassword,
    askPaste,
    answerPaste,
  };
}

const useTerminalState = createRoot(useTerminalStateInner);
export default useTerminalState;
