import shared from "./Panels.module.scss";
import { For, Show, createMemo } from "solid-js";
import { ArrowLeftRight, ArrowRight, Cable, Database, FolderOpen, Shield, SquareTerminal, Zap } from "lucide-solid";
import useVpnState from "@core/states/vpnState";
import useVpnEditorState from "@core/states/vpnEditorState";
import { vpnBackendLabel, vpnRunning, vpnStateLabel } from "@core/helpers/vpn";
import { disconnectVpn, setVpnOnComputer } from "@core/helpers/vpnActions";
import useSftpState, { isFinished } from "@core/states/sftpState";
import useWorkspaceState from "@core/states/workspaceState";
import usePortForwardState from "@core/states/portForwardState";
import useConnectionsState from "@core/states/connectionsState";
import useTerminalState from "@core/states/terminalState";
import useForwardRulesState from "@core/states/forwardRulesState";
import useSshState from "@core/states/sshState";
import { withDatabaseModule } from "@core/databases";
import { plural } from "@core/helpers";
import { ConnectionProfile } from "@core/types";
import EmptyState from "@core/components/EmptyState/EmptyState";
import { ItemIcon } from "@core/components/ItemParts/ItemParts";
import PanelFrame from "./PanelFrame";
import { PanelProps } from "./types";

function textMatches(text: string, search: string): boolean {
  const needle = search.trim().toLowerCase();
  return needle === "" || text.toLowerCase().includes(needle);
}

function matches(profile: ConnectionProfile, search: string): boolean {
  return textMatches(profile.name, search);
}

function OpenNowPanel(props: PanelProps) {
  const workspace = useWorkspaceState;
  const forwards = usePortForwardState;
  const connections = useConnectionsState;
  const rules = useForwardRulesState;

  const sessions = createMemo(() => workspace.store.globalTabs.flatMap(tab => {
    if (tab.kind !== "session") return [];
    const session = workspace.store.sessions[tab.sessionId];
    if (!session || !matches(session.profile, props.search)) return [];
    const kind = withDatabaseModule(session.profile, module => module.label);
    const where = session.info.catalog ?? session.selectedDatabase;
    return [{ tabId: tab.id, profile: session.profile, sub: where ? `${kind}, ${where}` : kind }];
  }));

  const running = createMemo(() => forwards.all().flatMap(info => {
    const profile = connections.find(info.connectionId);
    if (!profile || !matches(profile, props.search)) return [];
    return [{ profile, sub: `Forwarding ${info.allNetworks ? "0.0.0.0" : "127.0.0.1"}:${info.localPort}` }];
  }));

  const terminalTabs = createMemo(() => useTerminalState.tabs().flatMap(tab => {
    const host = useSshState.host(tab.hostId);
    if (!host || !textMatches(host.label, props.search)) return [];
    const panes = Object.values(tab.panes);
    const open = panes.filter(pane => pane.status === "open").length;
    const state = open > 0 ? plural(panes.length, "pane") : panes.some(pane => pane.status === "connecting") ? "connecting" : "disconnected";
    return [{ tabId: tab.id, host, connectionId: tab.connectionId, sub: `Terminal, ${state}` }];
  }));

  const sftpTabs = createMemo(() => useSftpState.tabs().flatMap(tab => {
    const host = useSshState.host(tab.hostId);
    if (!host || !textMatches(host.label, props.search)) return [];
    const active = tab.transfers.filter(item => !isFinished(item)).length;
    const state = tab.status === "open" ? (active > 0 ? plural(active, "transfer") : "connected") : tab.status === "connecting" ? "connecting" : "disconnected";
    return [{ tabId: tab.id, host, sub: `Files, ${state}` }];
  }));

  const runningRules = createMemo(() => useSshState.file.forwards.flatMap(rule => {
    const info = rules.status(rule.id);
    if (!info || !textMatches(rule.label, props.search)) return [];
    return [{ rule, sub: rule.kind === "remote" ? `Server listening on ${info.listen}` : `Listening on ${info.listen}` }];
  }));

  const vpns = createMemo(() => useVpnState.file.profiles.flatMap(profile => {
    const status = useVpnState.status(profile.id);
    if (!vpnRunning(status) || !textMatches(profile.label, props.search)) return [];
    const backend = vpnBackendLabel(status);
    const state = (vpnStateLabel(status) ?? "").toLowerCase();
    return [{ profile, system: status?.system ?? false, sub: `VPN, ${state}${backend ? ` ${backend}` : ""}` }];
  }));

  const count = createMemo(() => sessions().length + running().length + terminalTabs().length + sftpTabs().length + runningRules().length + vpns().length);

  return (
    <PanelFrame title="Open now" icon={Zap} count={count() > 0 ? count() : null} controls={props.controls}>
      <Show
        when={count() > 0}
        fallback={
          <div class={shared.Center}>
            <EmptyState icon={Zap} title="Nothing open" description="Terminals, file browsers, database sessions, running port forwards and VPNs show up here." />
          </div>
        }
      >
        <div class={shared.Rows}>
          <For each={terminalTabs()}>
            {item => (
              <button
                type="button"
                class={shared.Row}
                style={{ "--row-color": item.host.color ?? "var(--accent)" }}
                onClick={() => workspace.activateGlobalTab(item.tabId)}
              >
                <ItemIcon><SquareTerminal size={15} /></ItemIcon>
                <span class={shared.RowText}>
                  <span class={shared.RowName}>{item.host.label}</span>
                  <span class={shared.RowSub}>{item.sub}</span>
                </span>
                <span
                  class={shared.RowEnd}
                  onClick={event => {
                    event.stopPropagation();
                    useSftpState.open(item.host.id, item.connectionId);
                  }}
                >
                  <FolderOpen size={13} /> Files
                </span>
              </button>
            )}
          </For>
          <For each={sftpTabs()}>
            {item => (
              <button
                type="button"
                class={shared.Row}
                style={{ "--row-color": item.host.color ?? "var(--accent)" }}
                onClick={() => workspace.activateGlobalTab(item.tabId)}
              >
                <ItemIcon><FolderOpen size={15} /></ItemIcon>
                <span class={shared.RowText}>
                  <span class={shared.RowName}>{item.host.label}</span>
                  <span class={shared.RowSub}>{item.sub}</span>
                </span>
                <span class={shared.RowEnd}>Switch <ArrowRight size={13} /></span>
              </button>
            )}
          </For>
          <For each={sessions()}>
            {item => (
              <button
                type="button"
                class={shared.Row}
                style={{ "--row-color": item.profile.color ?? "var(--accent)" }}
                onClick={() => workspace.activateGlobalTab(item.tabId)}
              >
                <ItemIcon><Database size={15} /></ItemIcon>
                <span class={shared.RowText}>
                  <span class={shared.RowName}>{item.profile.name}</span>
                  <span class={shared.RowSub}>{item.sub}</span>
                </span>
                <span class={shared.RowEnd}>Switch <ArrowRight size={13} /></span>
              </button>
            )}
          </For>
          <For each={running()}>
            {item => (
              <button
                type="button"
                class={shared.Row}
                style={{ "--row-color": "var(--success)" }}
                onClick={() => forwards.openDialog(item.profile)}
              >
                <ItemIcon><Cable size={15} /></ItemIcon>
                <span class={shared.RowText}>
                  <span class={shared.RowName}>{item.profile.name}</span>
                  <span class={shared.RowSub}>{item.sub}</span>
                </span>
                <span class={shared.RowEnd}>Manage <ArrowRight size={13} /></span>
              </button>
            )}
          </For>
          <For each={runningRules()}>
            {item => (
              <button
                type="button"
                class={shared.Row}
                style={{ "--row-color": "var(--success)" }}
                onClick={() => rules.openEditor(item.rule)}
              >
                <ItemIcon><ArrowLeftRight size={15} /></ItemIcon>
                <span class={shared.RowText}>
                  <span class={shared.RowName}>{item.rule.label}</span>
                  <span class={shared.RowSub}>{item.sub}</span>
                </span>
                <span
                  class={shared.RowEnd}
                  onClick={event => {
                    event.stopPropagation();
                    void rules.stop(item.rule.id);
                  }}
                >
                  Stop
                </span>
              </button>
            )}
          </For>
          <For each={vpns()}>
            {item => (
              <button
                type="button"
                class={shared.Row}
                style={{ "--row-color": item.profile.color ?? "var(--success)" }}
                onClick={() => useVpnEditorState.open(item.profile)}
              >
                <ItemIcon><Shield size={15} /></ItemIcon>
                <span class={shared.RowText}>
                  <span class={shared.RowName}>{item.profile.label}</span>
                  <span class={shared.RowSub}>{item.sub}</span>
                </span>
                <span
                  class={shared.RowEnd}
                  onClick={event => {
                    event.stopPropagation();
                    void (item.system ? setVpnOnComputer(item.profile, false) : disconnectVpn(item.profile));
                  }}
                >
                  {item.system ? "Turn off" : "Disconnect"}
                </span>
              </button>
            )}
          </For>
        </div>
      </Show>
    </PanelFrame>
  );
}

export default OpenNowPanel;
