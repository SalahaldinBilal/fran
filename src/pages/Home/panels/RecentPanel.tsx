import shared from "./Panels.module.scss";
import { For, Show, createMemo } from "solid-js";
import { Database, History, SquareTerminal } from "lucide-solid";
import useSettingsState from "@core/states/settingsState";
import useConnectionsState from "@core/states/connectionsState";
import useWorkspaceState from "@core/states/workspaceState";
import useSshState from "@core/states/sshState";
import useTerminalState from "@core/states/terminalState";
import { withDatabaseModule } from "@core/databases";
import { featureOn } from "@core/helpers/features";
import { ConnectionProfile, SshHost } from "@core/types";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Spinner from "@core/components/Spinner/Spinner";
import { ItemIcon } from "@core/components/ItemParts/ItemParts";
import PanelFrame from "./PanelFrame";
import { PanelProps } from "./types";

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
];

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

function timeAgo(timestamp: number): string {
  const seconds = Math.round((Date.now() - timestamp) / 1000);
  for (const [unit, size] of UNITS) {
    if (seconds >= size) return relative.format(-Math.floor(seconds / size), unit);
  }
  return "just now";
}

type RecentItem =
  | { kind: "database", profile: ConnectionProfile, target: string, openedAt: number }
  | { kind: "ssh", host: SshHost, target: string, openedAt: number };

function HostItem(props: { item: Extract<RecentItem, { kind: "ssh" }> }) {
  return (
    <button
      type="button"
      class={shared.Row}
      style={{ "--row-color": props.item.host.color ?? "var(--accent)" }}
      onClick={() => useTerminalState.open(props.item.host.id)}
    >
      <ItemIcon><SquareTerminal size={15} /></ItemIcon>
      <span class={shared.RowText}>
        <span class={shared.RowName}>{props.item.host.label}</span>
        <span class={shared.RowSub}>{props.item.target}</span>
      </span>
      <span class={shared.RowEnd}>{timeAgo(props.item.openedAt)}</span>
    </button>
  );
}

function DatabaseItem(props: { item: Extract<RecentItem, { kind: "database" }> }) {
  const workspace = useWorkspaceState;
  const connecting = createMemo(() => workspace.store.connecting[props.item.profile.id] ?? false);

  return (
    <button
      type="button"
      class={shared.Row}
      style={{ "--row-color": props.item.profile.color ?? "var(--accent)" }}
      onClick={() => {
        if (!connecting()) workspace.openConnection(props.item.profile);
      }}
    >
      <ItemIcon><Database size={15} /></ItemIcon>
      <span class={shared.RowText}>
        <span class={shared.RowName}>{props.item.profile.name}</span>
        <span class={shared.RowSub}>{props.item.target}</span>
      </span>
      <span class={shared.RowEnd}>
        <Show when={connecting()} fallback={timeAgo(props.item.openedAt)}>
          <Spinner size={12} />
          Connecting
        </Show>
      </span>
    </button>
  );
}

function RecentPanel(props: PanelProps) {
  const { settings } = useSettingsState;
  const connections = useConnectionsState;

  const items = createMemo(() => {
    const needle = props.search.trim().toLowerCase();
    return settings.recentConnections.flatMap((recent): RecentItem[] => {
      if (recent.kind === "ssh") {
        const host = useSshState.host(recent.id);
        if (!featureOn("ssh") || !host || (needle && !host.label.toLowerCase().includes(needle))) return [];
        return [{ kind: "ssh", host, target: useSshState.address(host), openedAt: recent.openedAt }];
      }
      const profile = connections.find(recent.id);
      if (!featureOn("database") || !profile || (needle && !profile.name.toLowerCase().includes(needle))) return [];
      const target = withDatabaseModule(profile, (module, options) => module.describeTarget(options));
      return [{ kind: "database", profile, target, openedAt: recent.openedAt }];
    });
  });

  return (
    <PanelFrame title="Recent" icon={History} controls={props.controls}>
      <Show
        when={items().length > 0}
        fallback={
          <div class={shared.Center}>
            <EmptyState icon={History} title="Nothing yet" description="Connections and hosts you open show up here." />
          </div>
        }
      >
        <div class={shared.Rows}>
          <For each={items()}>
            {item => (item.kind === "ssh" ? <HostItem item={item} /> : <DatabaseItem item={item} />)}
          </For>
        </div>
      </Show>
    </PanelFrame>
  );
}

export default RecentPanel;
