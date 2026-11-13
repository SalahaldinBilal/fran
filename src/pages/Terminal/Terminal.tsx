import styles from "./Terminal.module.scss";
import { For, Show, createMemo, createResource } from "solid-js";
import {
  ArrowLeftRight, Clipboard, CodeXml, Columns2, FolderOpen, KeyRound, Pencil, Play, Plus, RefreshCw, Rows2, Shield, ShieldCheck, TriangleAlert, User, X,
} from "@core/icons";
import useVpnState from "@core/states/vpnState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import useTerminalState from "@core/states/terminalState";
import useSftpState from "@core/states/sftpState";
import useSshState from "@core/states/sshState";
import useSnippetsState from "@core/states/snippetsState";
import useHostEditorState from "@core/states/hostEditorState";
import useForwardRulesState from "@core/states/forwardRulesState";
import useContextMenuState, { MenuItem } from "@core/states/contextMenuState";
import useWorkspaceState from "@core/states/workspaceState";
import { panelsIn } from "@core/helpers/tiling";
import { describeForward } from "@core/helpers/forwardRules";
import { vpnModeLabel } from "@core/helpers/vpn";
import TileLayout from "@core/components/Tiling/TileLayout";
import RoutePreview from "@core/components/RoutePreview/RoutePreview";
import Button from "@core/components/Button/Button";
import EmptyState from "@core/components/EmptyState/EmptyState";
import TerminalPane from "./TerminalPane";

function TerminalPage(props: { tabId: string }) {
  const terminals = useTerminalState;
  const ssh = useSshState;
  const snippets = useSnippetsState;
  const rules = useForwardRulesState;
  const workspace = useWorkspaceState;
  const { openMenuAt } = useContextMenuState;

  const tab = createMemo(() => terminals.tab(props.tabId));
  const host = createMemo(() => ssh.host(tab()?.hostId ?? ""));
  const visible = createMemo(() => workspace.store.activeGlobalTabId === props.tabId);
  const route = createMemo(() => (host() ? ssh.route(host()!.id) : []));
  const proxy = createMemo(() => (host() ? ssh.routeProxy(host()!.id) : undefined));
  const identity = createMemo(() => ssh.identity(host()?.identityId ?? null));
  const paneCount = createMemo(() => panelsIn(tab()?.layout ?? null).length);
  const solo = createMemo(() => paneCount() === 1);
  const statuses = createMemo(() => Object.values(tab()?.panes ?? {}).map(pane => pane.status));
  const anyClosed = createMemo(() => statuses().includes("closed"));
  const connected = createMemo(() => statuses().includes("open"));
  const connecting = createMemo(() => !connected() && statuses().includes("connecting"));
  const statusLabel = createMemo(() => (connected() ? "Connected" : connecting() ? "Connecting" : "Disconnected"));
  const hostKey = createMemo(() => tab()?.info?.hostKey ?? null);
  const agentForwarding = createMemo(() => tab()?.info?.agentForwarding ?? host()?.agentForwarding ?? false);
  const vpnProfile = createMemo(() => {
    const id = host()?.id;
    return id ? useVpnState.profile(useSshState.routeVpnId(id)) : undefined;
  });
  const keepalive = createMemo(() => {
    const secs = host()?.keepaliveSecs ?? 0;
    return secs > 0 ? `Keepalive ${secs}s` : "Keepalive off";
  });
  const login = createMemo(() => {
    const current = identity();
    if (!current) return "No login";
    switch (current.auth.kind) {
      case "key": return `${current.user}, key ${ssh.key(current.auth.keyId)?.label ?? "deleted"}`;
      case "agent": return `${current.user}, SSH agent`;
      case "password": return `${current.user}, password`;
    }
  });
  // Rechecked each time the drawer opens, since the password can be saved in the meantime.
  const passwordOwner = createMemo(() => (tab()?.drawer ? identity()?.id ?? null : null));
  const [storedSlots] = createResource(passwordOwner, id => safeInvoke("get_owner_secrets", { owner: { kind: "identity", id } }).catch(() => [] as string[]));
  const hasPassword = createMemo(() => storedSlots()?.includes("password") ?? false);
  const passwordHint = createMemo(() => {
    const current = identity();
    if (!current) return "This host has no login.";
    if (!hasPassword()) return `${current.label} has no saved password. Save one on the Secrets page, under Identities.`;
    return `Types ${current.user}'s saved password at the prompt, for sudo. Enter isn't pressed, so you can check it's a password prompt first.`;
  });
  const hostForwards = createMemo(() => ssh.file.forwards.filter(rule => rule.hostId === tab()?.hostId));
  const runningForwards = createMemo(() => hostForwards().filter(rule => rules.status(rule.id)).length);

  function paneTitle(paneId: string): string {
    const label = host()?.label ?? "Terminal";
    const order = tab()?.order ?? [];
    return paneCount() > 1 ? `${label} · ${order.indexOf(paneId) + 1}` : label;
  }

  function openForwardsMenu(event: MouseEvent) {
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    const items: MenuItem[] = hostForwards().map(rule => ({
      label: `${rules.status(rule.id) ? "Stop" : "Start"} ${rule.label}`,
      hint: describeForward(rule),
      icon: ArrowLeftRight,
      onSelect: () => void rules.toggle(rule),
    }));
    openMenuAt({ x: rect.right - 260, y: rect.bottom + 4 }, [
      ...items,
      ...(items.length > 0 ? [{ separator: true } as const] : []),
      { label: "New port forward", icon: Plus, onSelect: () => rules.openEditor(null, tab()?.hostId) },
    ]);
  }

  return (
    <Show when={tab()} fallback={<div class={styles.Center}><EmptyState title="This terminal was closed" /></div>}>
      {current => (
        <div class={styles.Terminal}>
          <div class={styles.TopBar}>
            <Show when={host()} fallback={<span class={styles.Missing}>This host was deleted</span>}>
              <RoutePreview hosts={route()} proxy={proxy()} vpn={vpnProfile()} />
            </Show>
            <div class={styles.Spacer} />
            <Show when={anyClosed()}>
              <Button size="sm" variant="subtle" onClick={() => void terminals.reconnectClosed(props.tabId)}>
                <RefreshCw size={13} />
                Reconnect
              </Button>
            </Show>
            <Button icon size="sm" tooltip="Split right" onClick={() => terminals.split(props.tabId, "row")}>
              <Columns2 size={15} />
            </Button>
            <Button icon size="sm" tooltip="Split down" onClick={() => terminals.split(props.tabId, "col")}>
              <Rows2 size={15} />
            </Button>
            <span class={styles.Separator} />
            <Button
              icon
              size="sm"
              tooltip="Files on this host"
              disabled={!host()}
              onClick={() => useSftpState.open(current().hostId, current().connectionId)}
            >
              <FolderOpen size={15} />
            </Button>
            <Button
              icon
              size="sm"
              tooltip="Snippets"
              active={current().drawer}
              onClick={() => terminals.setDrawer(props.tabId, !current().drawer)}
            >
              <CodeXml size={15} />
            </Button>
            <Button icon size="sm" class={styles.ForwardsButton} tooltip="Port forwards on this host" onClick={openForwardsMenu}>
              <ArrowLeftRight size={15} />
              <Show when={runningForwards() > 0}>
                <span class={styles.Running} />
              </Show>
            </Button>
            <Button icon size="sm" tooltip="Edit host" disabled={!host()} onClick={() => useHostEditorState.open(host() ?? null)}>
              <Pencil size={14} />
            </Button>
          </div>

          <div class={styles.Main} classList={{ [styles.SoloMain]: solo() }}>
            <div class={styles.Panes}>
              <TileLayout
                tree={current().layout}
                label={paneTitle}
                onChange={tree => terminals.setLayout(props.tabId, tree)}
                renderPanel={(paneId, controls) => (
                  <TerminalPane
                    tabId={props.tabId}
                    paneId={paneId}
                    title={paneTitle(paneId)}
                    controls={controls}
                    closable={paneCount() > 1}
                    solo={solo()}
                    visible={visible()}
                  />
                )}
              />
            </div>

            <Show when={current().drawer}>
              <aside class={styles.Drawer}>
                <header class={styles.DrawerHead}>
                  <CodeXml size={14} />
                  <span>Snippets</span>
                  <div class={styles.Spacer} />
                  <Button icon size="sm" tooltip="New snippet" onClick={() => snippets.openEditor(null)}>
                    <Plus size={14} />
                  </Button>
                  <Button icon size="sm" tooltip="Close" onClick={() => terminals.setDrawer(props.tabId, false)}>
                    <X size={14} />
                  </Button>
                </header>
                <div class={styles.DrawerBody}>
                  <div class={`${styles.Snippet} ${styles.Builtin}`}>
                    <div class={styles.SnippetTop}>
                      <KeyRound size={13} class={styles.BuiltinIcon} />
                      <span class={styles.SnippetName}>Login password</span>
                    </div>
                    <span class={styles.BuiltinText}>{passwordHint()}</span>
                    <div class={styles.SnippetActions}>
                      <Button size="sm" variant="subtle" disabled={!hasPassword()} onClick={() => void terminals.typePassword(props.tabId)}>
                        Type it
                      </Button>
                    </div>
                  </div>
                  <Show
                    when={snippets.snippets.length > 0}
                    fallback={
                      <div class={styles.Center}>
                        <EmptyState
                          icon={CodeXml}
                          title="No snippets"
                          description="Save commands you run often."
                          actions={<Button variant="subtle" onClick={() => snippets.openEditor(null)}>New snippet</Button>}
                        />
                      </div>
                    }
                  >
                    <For each={snippets.snippets}>
                      {snippet => {
                        const pending = createMemo(() => current().pendingSnippet === snippet.id);
                        return (
                          <div class={styles.Snippet}>
                            <div class={styles.SnippetTop}>
                              <span class={styles.SnippetName}>{snippet.label}</span>
                              <Show when={snippet.confirm}>
                                <span class={styles.Warn}>Asks first</span>
                              </Show>
                              <Button icon size="sm" tooltip="Edit snippet" onClick={() => snippets.openEditor(snippet)}>
                                <Pencil size={12} />
                              </Button>
                            </div>
                            <code class={styles.SnippetCode}>{snippet.command}</code>
                            <Show
                              when={pending()}
                              fallback={
                                <div class={styles.SnippetActions}>
                                  <Button size="sm" variant="subtle" onClick={() => terminals.applySnippet(props.tabId, snippet, false)}>
                                    Type it
                                  </Button>
                                  <Button size="sm" variant="subtle" onClick={() => terminals.applySnippet(props.tabId, snippet, true)}>
                                    <Play size={11} />
                                    Run
                                  </Button>
                                </div>
                              }
                            >
                              <div class={styles.SnippetActions}>
                                <span class={styles.Confirm}>Run on {host()?.label}?</span>
                                <Button size="sm" variant="ghost" onClick={() => terminals.cancelSnippet(props.tabId)}>Cancel</Button>
                                <Button size="sm" variant="danger" onClick={() => terminals.applySnippet(props.tabId, snippet, true, true)}>
                                  Run
                                </Button>
                              </div>
                            </Show>
                          </div>
                        );
                      }}
                    </For>
                    <p class={styles.Hint}>Run sends the command with Enter. Type it puts it at the prompt without pressing Enter.</p>
                  </Show>
                </div>
              </aside>
            </Show>
          </div>

          <footer class={styles.Status}>
            <span>
              <i class={styles.Dot} classList={{ [styles.DotOff]: !connected(), [styles.DotWait]: connecting() }} />
              <em>{statusLabel()}</em>
            </span>
            <Show when={hostKey()}>
              {key => <span><ShieldCheck size={12} /><em>Host key {key().algorithm} verified</em></span>}
            </Show>
            <span><User size={12} /><em>{login()}</em></span>
            <Show when={agentForwarding()}>
              <span class={styles.StatusWarn}><TriangleAlert size={12} /><em>Agent forwarding on</em></span>
            </Show>
            <Show when={vpnProfile()}>
              {profile => <span><Shield size={12} /><em>VPN {profile().label}, {vpnModeLabel(useVpnState.status(profile().id))}</em></span>}
            </Show>
            <Show when={host()?.clipboardWrite}>
              <span><Clipboard size={12} /><em>Server can write to the clipboard</em></span>
            </Show>
            <span class={styles.Spacer} />
            <span><em>{keepalive()}</em></span>
            <span><em>UTF-8</em></span>
          </footer>
        </div>
      )}
    </Show>
  );
}

export default TerminalPage;
