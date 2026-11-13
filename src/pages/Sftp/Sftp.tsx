import styles from "./Sftp.module.scss";
import { Match, Show, Switch as Branch, createMemo, createSignal, onCleanup, onMount } from "solid-js";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import useWorkspaceState from "@core/states/workspaceState";
import { CircleAlert, Files, Laptop, Link2, Pencil, RefreshCw, Server, ShieldCheck, SquareTerminal, User } from "@core/icons";
import useSftpState, { Side } from "@core/states/sftpState";
import useSshState from "@core/states/sshState";
import useTerminalState from "@core/states/terminalState";
import useHostEditorState from "@core/states/hostEditorState";
import useVpnState from "@core/states/vpnState";
import { plural } from "@core/helpers";
import { vpnWaitLabel } from "@core/helpers/vpn";
import { FileEntry } from "@core/types";
import RoutePreview from "@core/components/RoutePreview/RoutePreview";
import Button from "@core/components/Button/Button";
import Switch from "@core/components/Switch/Switch";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Spinner from "@core/components/Spinner/Spinner";
import FilePane, { DragState, DropTarget } from "./FilePane";
import TransferQueue from "./TransferQueue";
import { PermissionsModal, PreviewModal } from "./SftpModals";

const DRAG_THRESHOLD = 5;

function SftpPage(props: { tabId: string }) {
  const sftp = useSftpState;
  const ssh = useSshState;
  let root!: HTMLDivElement;

  const tab = createMemo(() => sftp.tab(props.tabId));
  const host = createMemo(() => ssh.host(tab()?.hostId ?? ""));
  const route = createMemo(() => (host() ? ssh.route(host()!.id) : []));
  const proxy = createMemo(() => (host() ? ssh.routeProxy(host()!.id) : undefined));
  const identity = createMemo(() => ssh.identity(host()?.identityId ?? null));
  const status = createMemo(() => tab()?.status ?? "closed");
  const statusLabel = createMemo(() => (status() === "open" ? "Connected" : status() === "connecting" ? "Connecting" : "Disconnected"));
  const remoteBlocked = createMemo(() => status() !== "open");
  const vpnWait = createMemo(() => {
    const profile = useVpnState.profile(ssh.routeVpnId(host()?.id ?? ""));
    return vpnWaitLabel(profile, profile ? useVpnState.status(profile.id) : undefined);
  });
  const hostKey = createMemo(() => tab()?.info?.hostKey ?? null);
  const login = createMemo(() => {
    const current = identity();
    if (!current) return "No login";
    switch (current.auth.kind) {
      case "key": return `${current.user}, key ${ssh.key(current.auth.keyId)?.label ?? "deleted"}`;
      case "agent": return `${current.user}, SSH agent`;
      case "password": return `${current.user}, password`;
    }
  });

  const [drag, setDrag] = createSignal<DragState | null>(null);
  const ghostLabel = createMemo(() => {
    const current = drag();
    if (!current) return "";
    const what = current.entries.length === 1 ? current.entries[0].name : plural(current.entries.length, "item");
    const over = current.over;
    if (!over || over.side === current.from) return what;
    const verb = current.from === "local" ? "Upload" : "Download";
    const folder = over.folder ? ` into ${over.folder.split(/[\\/]/).filter(Boolean).pop() ?? over.folder}` : "";
    return `${verb} ${what}${folder}`;
  });
  const ghostReady = createMemo(() => {
    const current = drag();
    return current?.over !== null && current?.over !== undefined && current.over.side !== current.from;
  });

  let stopDrag: (() => void) | null = null;
  onCleanup(() => stopDrag?.());

  // Files dragged in from Explorer or Finder. Only the server pane takes them.
  function osEntry(path: string): FileEntry {
    const name = path.split(/[\\/]/).filter(Boolean).pop() ?? path;
    return { name, path, kind: "file", size: null, modified: null, mode: null, hidden: false, linkDir: false };
  }

  function osDropAt(position: { x: number, y: number }, entries: FileEntry[]): DragState | null {
    const x = position.x / window.devicePixelRatio;
    const y = position.y / window.devicePixelRatio;
    const target = dropTarget(x, y);
    return { from: "local", entries, x, y, over: target?.side === "remote" ? target : null };
  }

  let osEntries: FileEntry[] = [];
  let unlistenDrop: (() => void) | null = null;
  let disposed = false;
  onMount(() => {
    void getCurrentWebview().onDragDropEvent(event => {
      if (useWorkspaceState.store.activeGlobalTabId !== props.tabId || status() !== "open") return;
      const payload = event.payload;
      switch (payload.type) {
        case "enter":
          osEntries = payload.paths.map(osEntry);
          setDrag(osDropAt(payload.position, osEntries));
          break;
        case "over":
          if (osEntries.length > 0) setDrag(osDropAt(payload.position, osEntries));
          break;
        case "drop": {
          const dropped = osDropAt(payload.position, payload.paths.map(osEntry));
          osEntries = [];
          setDrag(null);
          if (dropped?.over) sftp.transfer(props.tabId, "local", dropped.entries, dropped.over.folder ?? undefined);
          break;
        }
        case "leave":
          osEntries = [];
          setDrag(null);
          break;
      }
    }).then(unlisten => {
      if (disposed) unlisten();
      else unlistenDrop = unlisten;
    });
  });
  onCleanup(() => {
    disposed = true;
    unlistenDrop?.();
  });

  function dropTarget(x: number, y: number): DropTarget | null {
    const element = document.elementFromPoint(x, y) as HTMLElement | null;
    const zone = element?.closest<HTMLElement>("[data-drop-side]");
    if (!element || !zone || !root.contains(zone)) return null;
    const side = zone.dataset.dropSide as Side;
    const folderRow = element.closest<HTMLElement>("[data-drop-folder]");
    return { side, folder: folderRow?.dataset.dropFolder ?? null };
  }

  function grab(side: Side, event: PointerEvent, entry: FileEntry) {
    stopDrag?.();
    const startX = event.clientX;
    const startY = event.clientY;
    let started = false;

    function move(moveEvent: PointerEvent) {
      if (!started) {
        if (Math.hypot(moveEvent.clientX - startX, moveEvent.clientY - startY) < DRAG_THRESHOLD) return;
        started = true;
        const chosen = sftp.selectedEntries(props.tabId, side);
        const entries = chosen.some(item => item.path === entry.path) ? chosen : [entry];
        setDrag({ from: side, entries, x: moveEvent.clientX, y: moveEvent.clientY, over: null });
      }
      setDrag(current => current && { ...current, x: moveEvent.clientX, y: moveEvent.clientY, over: dropTarget(moveEvent.clientX, moveEvent.clientY) });
    }

    function finish() {
      stop();
      const current = drag();
      setDrag(null);
      if (!started || !current?.over || current.over.side === current.from) return;
      sftp.transfer(props.tabId, current.from, current.entries, current.over.folder ?? undefined);
    }

    function cancel() {
      stop();
      setDrag(null);
    }

    function stop() {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", finish);
      window.removeEventListener("pointercancel", cancel);
      stopDrag = null;
    }

    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", finish);
    window.addEventListener("pointercancel", cancel);
    stopDrag = stop;
  }

  function RemoteBlocked() {
    return (
      <Branch>
        <Match when={status() === "connecting"}>
          <div class={styles.Connecting}>
            <Spinner size={18} />
            <div class={styles.ConnectingText}>
              <span>Connecting to {host()?.label ?? "the server"}</span>
              <Show when={vpnWait()}>{label => <em>{label()}</em>}</Show>
            </div>
          </div>
        </Match>
        <Match when={true}>
          <EmptyState
            tone="danger"
            icon={CircleAlert}
            title="Not connected"
            description={tab()?.reason ?? undefined}
            actions={
              <Button variant="subtle" disabled={!host()} onClick={() => void sftp.connect(props.tabId)}>
                <RefreshCw size={13} />
                Reconnect
              </Button>
            }
          />
        </Match>
      </Branch>
    );
  }

  return (
    <Show when={tab()} fallback={<div class={styles.Center}><EmptyState title="This file browser was closed" /></div>}>
      {current => (
        <div ref={root} class={styles.Sftp}>
          <div class={styles.TopBar}>
            <Show when={host()} fallback={<span class={styles.Missing}>This host was deleted</span>}>
              <RoutePreview hosts={route()} proxy={proxy()} />
            </Show>
            <div class={styles.Spacer} />
            <Show when={status() === "closed"}>
              <Button size="sm" variant="subtle" disabled={!host()} onClick={() => void sftp.connect(props.tabId)}>
                <RefreshCw size={13} />
                Reconnect
              </Button>
            </Show>
            <Switch checked={current().showHidden} onChange={checked => sftp.setShowHidden(props.tabId, checked)} label="Hidden files" />
            <span class={styles.Separator} />
            <Button icon size="sm" tooltip="Open a terminal" disabled={!host()} onClick={() => useTerminalState.open(current().hostId)}>
              <SquareTerminal size={15} />
            </Button>
            <Button icon size="sm" tooltip="Edit host" disabled={!host()} onClick={() => useHostEditorState.open(host() ?? null)}>
              <Pencil size={14} />
            </Button>
          </div>

          <div class={styles.Main}>
            <div class={styles.Panes}>
              <FilePane
                tabId={props.tabId}
                side="local"
                title="This computer"
                subtitle={current().local.listing?.path ?? ""}
                icon={Laptop}
                drag={drag()}
                onGrab={(event, entry) => grab("local", event, entry)}
              />
              <FilePane
                tabId={props.tabId}
                side="remote"
                title={host()?.label ?? "Server"}
                subtitle={current().remote.listing?.path ?? ""}
                icon={Server}
                drag={drag()}
                onGrab={(event, entry) => grab("remote", event, entry)}
                blocked={remoteBlocked()}
                blockedView={<RemoteBlocked />}
              />
            </div>
            <TransferQueue tabId={props.tabId} />
          </div>

          <footer class={styles.Status}>
            <span>
              <i class={styles.Dot} classList={{ [styles.DotOff]: status() !== "open", [styles.DotWait]: status() === "connecting" }} />
              <em>{statusLabel()}</em>
            </span>
            <Show when={hostKey()}>
              {key => <span><ShieldCheck size={12} /><em>Host key {key().algorithm} verified</em></span>}
            </Show>
            <span><User size={12} /><em>{login()}</em></span>
            <Show when={current().info?.shared}>
              <span><Link2 size={12} /><em>Shares a terminal's login, stays open if the terminal closes</em></span>
            </Show>
            <span class={styles.Spacer} />
            <span><Files size={12} /><em>Up to 3 transfers at once</em></span>
          </footer>

          <Show when={drag()}>
            {current => (
              <div class={styles.Ghost} classList={{ [styles.GhostReady]: ghostReady() }} style={{ left: `${current().x + 14}px`, top: `${current().y + 12}px` }}>
                {ghostLabel()}
              </div>
            )}
          </Show>

          <PreviewModal tabId={props.tabId} />
          <PermissionsModal tabId={props.tabId} />
        </div>
      )}
    </Show>
  );
}

export default SftpPage;
