import { createRoot, createSignal } from "solid-js";
import { createStore, produce } from "solid-js/store";
import { Channel } from "@tauri-apps/api/core";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { withConnectPrompts } from "@core/helpers/connectFlow";
import { errorMessage, isAppError } from "@core/helpers/errors";
import { copyText } from "@core/helpers/clipboard";
import { formatBytes, generateId, plural } from "@core/helpers";
import { ConflictChoice, Crumb, FileEntry, Listing, SftpEvent, SftpInfo, TransferDirection, TransferEvent, TreeCount } from "@core/types";
import useWorkspaceState, { registerTabCloser } from "./workspaceState";
import useSshState from "./sshState";
import usePromptState from "./promptState";
import useToastState from "./toastState";

export type Side = "local" | "remote";

export type FilePane = {
  listing: Listing | null,
  status: "idle" | "loading" | "ready" | "error",
  error: string | null,
  filter: string,
  selected: string[],
  anchor: string | null,
  editingPath: boolean,
};

export type TransferStatus = "waiting" | "scanning" | "running" | "conflict" | "done" | "failed" | "cancelled";

export type TransferItem = {
  key: string,
  transferId: string | null,
  direction: TransferDirection,
  source: string,
  targetDir: string,
  name: string,
  status: TransferStatus,
  totalBytes: number,
  totalFiles: number,
  bytes: number,
  files: number,
  current: string | null,
  conflict: { path: string, isDir: boolean } | null,
  skipped: { path: string, reason: string }[],
  error: string | null,
  // Bytes per second over the last second or so.
  speed: number | null,
};

export type PreviewState = { path: string, name: string, text: string | null, error: string | null };

export type PermissionsState = { path: string, name: string, mode: number };

export type SftpTab = {
  id: string,
  hostId: string,
  // A terminal connection to reuse, so there's no second login.
  terminalConnectionId: string | null,
  status: "connecting" | "open" | "closed",
  reason: string | null,
  info: SftpInfo | null,
  showHidden: boolean,
  local: FilePane,
  remote: FilePane,
  transfers: TransferItem[],
  preview: PreviewState | null,
  permissions: PermissionsState | null,
};

const SPEED_WINDOW_MS = 1000;

function emptyPane(): FilePane {
  return { listing: null, status: "idle", error: null, filter: "", selected: [], anchor: null, editingPath: false };
}

export function isFolder(entry: FileEntry): boolean {
  return entry.kind === "dir" || (entry.kind === "symlink" && entry.linkDir);
}

export function isFinished(item: TransferItem): boolean {
  return item.status === "done" || item.status === "failed" || item.status === "cancelled";
}

function useSftpStateInner() {
  const workspace = useWorkspaceState;
  const ssh = useSshState;
  const { pushError, pushToast } = useToastState;
  const [store, setStore] = createStore<{ tabs: Record<string, SftpTab> }>({ tabs: {} });
  const samples = new Map<string, { at: number, bytes: number }>();
  const [roots, setRoots] = createSignal<Crumb[]>([]);

  async function loadRoots() {
    if (roots().length > 0) return;
    setRoots(await safeInvoke("local_roots").catch(() => []));
  }

  function tab(id: string): SftpTab | undefined {
    return store.tabs[id];
  }

  function hostLabel(tabId: string): string {
    return ssh.host(tab(tabId)?.hostId ?? "")?.label ?? "SSH host";
  }

  function open(hostId: string, terminalConnectionId: string | null = null) {
    if (!ssh.host(hostId)) return;
    void loadRoots();
    const existing = Object.values(store.tabs).find(candidate => candidate.hostId === hostId);
    if (existing) {
      workspace.activateGlobalTab(existing.id);
      if (existing.status === "closed") {
        setStore("tabs", existing.id, "terminalConnectionId", terminalConnectionId ?? existing.terminalConnectionId);
        void connect(existing.id);
      }
      return;
    }

    const id = generateId();
    setStore("tabs", id, {
      id,
      hostId,
      terminalConnectionId,
      status: "connecting",
      reason: null,
      info: null,
      showHidden: false,
      local: emptyPane(),
      remote: emptyPane(),
      transfers: [],
      preview: null,
      permissions: null,
    });
    workspace.addGlobalTab({ id, kind: "sftp" });
    void connect(id);
  }

  async function connect(tabId: string) {
    const current = tab(tabId);
    if (!current || current.status === "open") return;
    setStore("tabs", tabId, { status: "connecting", reason: null });

    // The drop notice can come before the open call returns, so it waits until the id is known.
    let openedId: string | null = null;
    let early: SftpEvent | null = null;
    const events = new Channel<SftpEvent>();
    events.onmessage = event => {
      if (openedId === null) early = event;
      else connectionDropped(tabId, openedId, event);
    };

    let info: SftpInfo | null;
    try {
      info = await withConnectPrompts(
        { connectionId: null, connectionName: hostLabel(tabId) },
        secrets => safeInvoke("sftp_open", { hostId: current.hostId, connectionId: current.terminalConnectionId, secrets, onEvent: events }),
      );
    } catch (error) {
      if (tab(tabId)) setStore("tabs", tabId, { status: "closed", reason: errorMessage(error) });
      return;
    }

    if (!info) {
      if (tab(tabId)) setStore("tabs", tabId, { status: "closed", reason: "Cancelled" });
      return;
    }
    if (!tab(tabId)) {
      void safeInvoke("sftp_close", { id: info.id });
      return;
    }

    const opened = info;
    openedId = opened.id;
    const remotePath = tab(tabId)?.remote.listing?.path ?? opened.home;
    setStore("tabs", tabId, { status: "open", info: opened, reason: null });
    if (early) {
      connectionDropped(tabId, opened.id, early);
      return;
    }
    void load(tabId, "remote", remotePath);
    if (!tab(tabId)?.local.listing) void load(tabId, "local", null);
  }

  function connectionDropped(tabId: string, sftpId: string, event: SftpEvent) {
    if (tab(tabId)?.info?.id !== sftpId) return;
    markClosed(tabId, event.reason ?? "The connection dropped");
  }

  function markClosed(tabId: string, reason: string) {
    if (!tab(tabId)) return;
    setStore("tabs", tabId, produce(state => {
      state.status = "closed";
      state.reason = reason;
      state.info = null;
      state.terminalConnectionId = null;
    }));
  }

  // A notFound error means the connection itself is gone, not the folder.
  function connectionGone(tabId: string, error: unknown): boolean {
    if (!isAppError(error) || error.detail.kind !== "notFound") return false;
    markClosed(tabId, errorMessage(error));
    return true;
  }

  function sftpId(tabId: string): string | null {
    return tab(tabId)?.info?.id ?? null;
  }

  async function load(tabId: string, side: Side, path: string | null) {
    if (!tab(tabId)) return;
    const id = sftpId(tabId);
    if (side === "remote" && !id) return;
    setStore("tabs", tabId, side, { status: "loading", error: null });

    try {
      const listing = side === "local"
        ? await safeInvoke("local_list", { path })
        : await safeInvoke("sftp_list", { id: id!, path: path ?? "." });
      if (!tab(tabId)) return;
      const keep = tab(tabId)?.[side].listing?.path === listing.path;
      setStore("tabs", tabId, side, produce(pane => {
        pane.listing = listing;
        pane.status = "ready";
        pane.editingPath = false;
        const present = new Set(listing.entries.map(entry => entry.path));
        pane.selected = keep ? pane.selected.filter(selected => present.has(selected)) : [];
        if (!keep) {
          pane.anchor = null;
          pane.filter = "";
        }
      }));
    } catch (error) {
      if (!tab(tabId)) return;
      if (side === "remote" && connectionGone(tabId, error)) return;
      setStore("tabs", tabId, side, { status: "error", error: errorMessage(error) });
    }
  }

  function refresh(tabId: string, side: Side) {
    void load(tabId, side, tab(tabId)?.[side].listing?.path ?? null);
  }

  function up(tabId: string, side: Side) {
    const parent = tab(tabId)?.[side].listing?.parent;
    if (parent) void load(tabId, side, parent);
  }

  function openEntry(tabId: string, side: Side, entry: FileEntry) {
    if (isFolder(entry)) void load(tabId, side, entry.path);
    else if (side === "remote") void preview(tabId, entry);
  }

  function setEditingPath(tabId: string, side: Side, editing: boolean) {
    setStore("tabs", tabId, side, "editingPath", editing);
  }

  function setFilter(tabId: string, side: Side, filter: string) {
    setStore("tabs", tabId, side, "filter", filter);
  }

  function setShowHidden(tabId: string, show: boolean) {
    setStore("tabs", tabId, "showHidden", show);
  }

  // `order` is what the pane shows, so a Shift range follows the visible rows.
  function select(tabId: string, side: Side, path: string | null, mode: "single" | "toggle" | "range", order: string[]) {
    const pane = tab(tabId)?.[side];
    if (!pane) return;
    if (path === null) {
      setStore("tabs", tabId, side, { selected: [], anchor: null });
      return;
    }
    if (mode === "toggle") {
      const selected = pane.selected.includes(path) ? pane.selected.filter(item => item !== path) : [...pane.selected, path];
      setStore("tabs", tabId, side, { selected, anchor: path });
      return;
    }
    if (mode === "range" && pane.anchor && order.includes(pane.anchor)) {
      const from = order.indexOf(pane.anchor);
      const to = order.indexOf(path);
      setStore("tabs", tabId, side, "selected", order.slice(Math.min(from, to), Math.max(from, to) + 1));
      return;
    }
    setStore("tabs", tabId, side, { selected: [path], anchor: path });
  }

  function selectAll(tabId: string, side: Side, order: string[]) {
    setStore("tabs", tabId, side, { selected: [...order], anchor: order[0] ?? null });
  }

  function selectedEntries(tabId: string, side: Side): FileEntry[] {
    const pane = tab(tabId)?.[side];
    if (!pane?.listing) return [];
    const selected = new Set(pane.selected);
    return pane.listing.entries.filter(entry => selected.has(entry.path));
  }

  function patchTransfer(tabId: string, key: string, patch: Partial<TransferItem> | ((item: TransferItem) => void)) {
    if (!tab(tabId)) return;
    if (typeof patch === "function") setStore("tabs", tabId, "transfers", item => item.key === key, produce(patch));
    else setStore("tabs", tabId, "transfers", item => item.key === key, patch);
  }

  function refreshTarget(tabId: string, item: TransferItem) {
    const side: Side = item.direction === "upload" ? "remote" : "local";
    if (tab(tabId)?.[side].listing?.path === item.targetDir) refresh(tabId, side);
  }

  function onTransferEvent(tabId: string, key: string, event: TransferEvent) {
    const item = tab(tabId)?.transfers.find(candidate => candidate.key === key);
    if (!item) return;
    switch (event.kind) {
      case "waiting":
        patchTransfer(tabId, key, { status: "waiting" });
        break;
      case "scanning":
        patchTransfer(tabId, key, { status: "scanning", files: event.files, bytes: event.bytes });
        break;
      case "started":
        samples.set(key, { at: Date.now(), bytes: 0 });
        patchTransfer(tabId, key, { status: "running", totalBytes: event.totalBytes, totalFiles: event.totalFiles, bytes: 0, files: 0 });
        break;
      case "progress": {
        const now = Date.now();
        const sample = samples.get(key);
        let speed = item.speed;
        if (sample && now - sample.at >= SPEED_WINDOW_MS) {
          speed = ((event.bytes - sample.bytes) * 1000) / (now - sample.at);
          samples.set(key, { at: now, bytes: event.bytes });
        }
        patchTransfer(tabId, key, { status: "running", bytes: event.bytes, files: event.files, current: event.current, speed });
        break;
      }
      case "conflict":
        patchTransfer(tabId, key, { status: "conflict", conflict: { path: event.path, isDir: event.isDir } });
        break;
      case "skipped":
        patchTransfer(tabId, key, state => { state.skipped.push({ path: event.path, reason: event.reason }); });
        break;
      case "finished":
        samples.delete(key);
        patchTransfer(tabId, key, { status: "done", bytes: event.bytes, files: event.files, current: null, conflict: null, speed: null });
        refreshTarget(tabId, item);
        break;
      case "failed":
        samples.delete(key);
        patchTransfer(tabId, key, { status: "failed", error: event.message, current: null, conflict: null, speed: null });
        refreshTarget(tabId, item);
        break;
      case "cancelled":
        samples.delete(key);
        patchTransfer(tabId, key, { status: "cancelled", current: null, conflict: null, speed: null });
        refreshTarget(tabId, item);
        break;
    }
  }

  async function launch(tabId: string, key: string) {
    const id = sftpId(tabId);
    const item = tab(tabId)?.transfers.find(candidate => candidate.key === key);
    if (!item) return;
    if (!id) {
      patchTransfer(tabId, key, { status: "failed", error: "Not connected" });
      return;
    }
    const events = new Channel<TransferEvent>();
    events.onmessage = event => onTransferEvent(tabId, key, event);
    try {
      const transferId = await safeInvoke("sftp_transfer", {
        id,
        direction: item.direction,
        source: item.source,
        targetDir: item.targetDir,
        onEvent: events,
      });
      patchTransfer(tabId, key, { transferId });
    } catch (error) {
      connectionGone(tabId, error);
      patchTransfer(tabId, key, { status: "failed", error: errorMessage(error) });
    }
  }

  function enqueue(tabId: string, direction: TransferDirection, entry: FileEntry, targetDir: string) {
    const key = generateId();
    const item: TransferItem = {
      key,
      transferId: null,
      direction,
      source: entry.path,
      targetDir,
      name: entry.name,
      status: "waiting",
      totalBytes: entry.size ?? 0,
      totalFiles: 0,
      bytes: 0,
      files: 0,
      current: null,
      conflict: null,
      skipped: [],
      error: null,
      speed: null,
    };
    setStore("tabs", tabId, "transfers", transfers => [...transfers, item]);
    void launch(tabId, key);
  }

  // Uploads go from the local pane to the remote one, downloads the other way. A folder row can be the target.
  function transfer(tabId: string, from: Side, entries: FileEntry[], targetDir?: string) {
    const current = tab(tabId);
    if (!current || entries.length === 0) return;
    if (current.status !== "open") {
      pushToast("Not connected to the server", "info");
      return;
    }
    const to: Side = from === "local" ? "remote" : "local";
    const target = targetDir ?? current[to].listing?.path;
    if (!target) return;
    const direction: TransferDirection = from === "local" ? "upload" : "download";
    for (const entry of entries) enqueue(tabId, direction, entry, target);
  }

  function retry(tabId: string, key: string) {
    patchTransfer(tabId, key, {
      transferId: null,
      status: "waiting",
      bytes: 0,
      files: 0,
      current: null,
      conflict: null,
      skipped: [],
      error: null,
      speed: null,
    });
    void launch(tabId, key);
  }

  function cancel(tabId: string, key: string) {
    const item = tab(tabId)?.transfers.find(candidate => candidate.key === key);
    if (!item?.transferId || isFinished(item)) return;
    void safeInvoke("cancel_transfer", { transferId: item.transferId }).catch(() => undefined);
  }

  async function answerConflict(tabId: string, key: string, choice: ConflictChoice, forAll: boolean) {
    const item = tab(tabId)?.transfers.find(candidate => candidate.key === key);
    if (!item?.transferId) return;
    patchTransfer(tabId, key, { status: "running", conflict: null });
    try {
      await safeInvoke("sftp_answer_conflict", { transferId: item.transferId, choice, forAll });
    } catch (error) {
      pushError(error);
    }
  }

  function clearFinished(tabId: string) {
    setStore("tabs", tabId, "transfers", transfers => transfers.filter(item => !isFinished(item)));
  }

  async function newFolder(tabId: string, side: Side) {
    const dir = tab(tabId)?.[side].listing?.path;
    if (!dir) return;
    const name = await usePromptState.askForText({ title: "New folder", label: "Name", initial: "", confirmLabel: "Create" });
    if (!name?.trim()) return;
    try {
      const id = sftpId(tabId);
      if (side === "local") await safeInvoke("local_mkdir", { dir, name });
      else if (id) await safeInvoke("sftp_mkdir", { id, dir, name });
      refresh(tabId, side);
    } catch (error) {
      if (side === "remote" && connectionGone(tabId, error)) return;
      pushError(error);
    }
  }

  async function rename(tabId: string, side: Side, entry: FileEntry) {
    const name = await usePromptState.askForText({ title: `Rename ${entry.name}`, label: "New name", initial: entry.name, confirmLabel: "Rename" });
    if (!name?.trim() || name.trim() === entry.name) return;
    try {
      const id = sftpId(tabId);
      if (side === "local") await safeInvoke("local_rename", { path: entry.path, name });
      else if (id) await safeInvoke("sftp_rename", { id, path: entry.path, name });
      refresh(tabId, side);
    } catch (error) {
      if (side === "remote" && connectionGone(tabId, error)) return;
      pushError(error);
    }
  }

  function describeCount(count: TreeCount): string {
    const parts = [plural(count.files, "file")];
    if (count.folders > 0) parts.push(plural(count.folders, "folder"));
    return `${parts.join(" and ")} (${formatBytes(count.bytes)})`;
  }

  // Folders are counted first, so the confirm says how much a recursive delete removes.
  async function remove(tabId: string, side: Side, entries: FileEntry[]) {
    if (entries.length === 0) return;
    const id = sftpId(tabId);
    if (side === "remote" && !id) return;
    const folders = entries.filter(entry => entry.kind === "dir");

    let total: TreeCount = { files: entries.length - folders.length, folders: 0, bytes: entries.reduce((sum, entry) => sum + (entry.kind === "dir" ? 0 : entry.size ?? 0), 0) };
    try {
      for (const folder of folders) {
        const count = side === "local"
          ? await safeInvoke("local_count", { path: folder.path })
          : await safeInvoke("sftp_count", { id: id!, path: folder.path });
        total = { files: total.files + count.files, folders: total.folders + count.folders, bytes: total.bytes + count.bytes };
      }
    } catch (error) {
      if (side === "remote" && connectionGone(tabId, error)) return;
      pushError(error);
      return;
    }

    const where = side === "local" ? "from this computer" : `from ${hostLabel(tabId)}`;
    const what = entries.length === 1 ? entries[0].name : plural(entries.length, "item");
    const message = folders.length > 0
      ? `This deletes ${describeCount(total)} ${where}. It can't be undone.`
      : `This deletes ${what} ${where}. It can't be undone.`;
    const confirmed = await usePromptState.confirm({ title: `Delete ${what}?`, message, confirmLabel: "Delete", danger: true });
    if (!confirmed) return;

    for (const entry of entries) {
      try {
        const recursive = entry.kind === "dir";
        if (side === "local") await safeInvoke("local_remove", { path: entry.path, recursive });
        else await safeInvoke("sftp_remove", { id: id!, path: entry.path, recursive });
      } catch (error) {
        if (side === "remote" && connectionGone(tabId, error)) return;
        pushError(error);
        break;
      }
    }
    refresh(tabId, side);
  }

  function copyPath(entry: FileEntry) {
    void copyText(entry.path, "path");
  }

  async function preview(tabId: string, entry: FileEntry) {
    const id = sftpId(tabId);
    if (!id) return;
    setStore("tabs", tabId, "preview", { path: entry.path, name: entry.name, text: null, error: null });
    try {
      const text = await safeInvoke("sftp_preview", { id, path: entry.path });
      if (tab(tabId)?.preview?.path === entry.path) setStore("tabs", tabId, "preview", "text", text);
    } catch (error) {
      if (connectionGone(tabId, error)) {
        setStore("tabs", tabId, "preview", null);
        return;
      }
      if (tab(tabId)?.preview?.path === entry.path) setStore("tabs", tabId, "preview", "error", errorMessage(error));
    }
  }

  function closePreview(tabId: string) {
    setStore("tabs", tabId, "preview", null);
  }

  function editPermissions(tabId: string, entry: FileEntry) {
    if (entry.mode === null) return;
    setStore("tabs", tabId, "permissions", { path: entry.path, name: entry.name, mode: entry.mode & 0o7777 });
  }

  function closePermissions(tabId: string) {
    setStore("tabs", tabId, "permissions", null);
  }

  async function savePermissions(tabId: string, mode: number): Promise<boolean> {
    const id = sftpId(tabId);
    const target = tab(tabId)?.permissions;
    if (!id || !target) return false;
    try {
      await safeInvoke("sftp_chmod", { id, path: target.path, mode });
      closePermissions(tabId);
      refresh(tabId, "remote");
      return true;
    } catch (error) {
      if (connectionGone(tabId, error)) {
        closePermissions(tabId);
        return false;
      }
      pushError(error);
      return false;
    }
  }

  function closeTab(tabId: string) {
    const current = tab(tabId);
    if (!current) return;
    if (current.info) void safeInvoke("sftp_close", { id: current.info.id }).catch(() => undefined);
    for (const item of current.transfers) samples.delete(item.key);
    setStore("tabs", produce(tabs => { delete tabs[tabId]; }));
  }

  function tabs(): SftpTab[] {
    return workspace.store.globalTabs.flatMap(globalTab => (globalTab.kind === "sftp" && store.tabs[globalTab.id] ? [store.tabs[globalTab.id]] : []));
  }

  // Closing cancels what's still copying, so that's asked first.
  async function confirmClose(tabId: string): Promise<boolean> {
    const running = tab(tabId)?.transfers.filter(item => !isFinished(item)).length ?? 0;
    if (running === 0) return true;
    return usePromptState.confirm({
      title: `Close ${hostLabel(tabId)} files?`,
      message: `${plural(running, "transfer")} will be cancelled. Files being written are deleted, finished ones stay.`,
      confirmLabel: "Close and cancel",
      danger: true,
    });
  }

  registerTabCloser("sftp", closeTab, confirmClose);

  return {
    store,
    tab,
    tabs,
    roots,
    open,
    connect,
    load,
    refresh,
    up,
    openEntry,
    setEditingPath,
    setFilter,
    setShowHidden,
    select,
    selectAll,
    selectedEntries,
    transfer,
    retry,
    cancel,
    answerConflict,
    clearFinished,
    newFolder,
    rename,
    remove,
    copyPath,
    preview,
    closePreview,
    editPermissions,
    closePermissions,
    savePermissions,
  };
}

const useSftpState = createRoot(useSftpStateInner);
export default useSftpState;
