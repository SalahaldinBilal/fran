import styles from "./SearchResults.module.scss";
import { For, Show, createMemo } from "solid-js";
import { Dynamic } from "solid-js/web";
import { ArrowLeftRight, CodeXml, Database, LucideIcon, Server, Shield } from "lucide-solid";
import useVpnState from "@core/states/vpnState";
import useVpnEditorState from "@core/states/vpnEditorState";
import { vpnServer } from "@core/helpers/vpn";
import useConnectionsState from "@core/states/connectionsState";
import useSshState from "@core/states/sshState";
import useSnippetsState from "@core/states/snippetsState";
import useForwardRulesState from "@core/states/forwardRulesState";
import useHostEditorState from "@core/states/hostEditorState";
import useTerminalState from "@core/states/terminalState";
import useWorkspaceState from "@core/states/workspaceState";
import { featureOn } from "@core/helpers/features";
import { withDatabaseModule } from "@core/databases";
import { describeForward } from "@core/helpers/forwardRules";

export type SearchResult = {
  key: string,
  kind: string,
  label: string,
  sub: string,
  icon: LucideIcon,
  color: string | null,
  action: string,
  run: () => void,
};

const LIMIT = 8;

function matches(needle: string, ...texts: (string | null | undefined)[]): boolean {
  return texts.some(text => (text ?? "").toLowerCase().includes(needle));
}

// Everything Home can open, from both halves of the app, in one list.
export function searchEverything(search: string): SearchResult[] {
  const needle = search.trim().toLowerCase();
  if (!needle) return [];
  const results: SearchResult[] = [];
  const ssh = useSshState;
  const terminalsOn = featureOn("ssh");

  if (featureOn("database")) {
    for (const profile of useConnectionsState.connections) {
      if (!matches(needle, profile.name, profile.group)) continue;
      results.push({
        key: `connection:${profile.id}`,
        kind: "Database",
        label: profile.name,
        sub: withDatabaseModule(profile, module => module.label),
        icon: Database,
        color: profile.color ?? null,
        action: "Connect",
        run: () => void useWorkspaceState.openConnection(profile),
      });
    }
  }

  for (const host of ssh.file.hosts) {
    if (!matches(needle, host.label, host.host, host.group)) continue;
    results.push({
      key: `host:${host.id}`,
      kind: "SSH host",
      label: host.label,
      sub: ssh.address(host),
      icon: Server,
      color: host.color,
      action: terminalsOn ? "Open terminal" : "Edit",
      run: () => (terminalsOn ? useTerminalState.open(host.id) : useHostEditorState.open(host)),
    });
  }

  for (const rule of ssh.file.forwards) {
    if (!matches(needle, rule.label)) continue;
    results.push({
      key: `forward:${rule.id}`,
      kind: "Port forward",
      label: rule.label,
      sub: describeForward(rule),
      icon: ArrowLeftRight,
      color: null,
      action: "Edit",
      run: () => useForwardRulesState.openEditor(rule),
    });
  }

  if (featureOn("vpn")) {
    for (const profile of useVpnState.file.profiles) {
      if (!matches(needle, profile.label, profile.group, ...profile.remotes.map(remote => remote.host))) continue;
      results.push({
        key: `vpn:${profile.id}`,
        kind: "VPN",
        label: profile.label,
        sub: vpnServer(profile),
        icon: Shield,
        color: profile.color,
        action: "Edit",
        run: () => useVpnEditorState.open(profile),
      });
    }
  }

  if (terminalsOn) {
    for (const snippet of useSnippetsState.snippets) {
      if (!matches(needle, snippet.label, snippet.command)) continue;
      results.push({
        key: `snippet:${snippet.id}`,
        kind: "Snippet",
        label: snippet.label,
        sub: snippet.command.split("\n")[0],
        icon: CodeXml,
        color: null,
        action: "Edit",
        run: () => useSnippetsState.openEditor(snippet),
      });
    }
  }

  return results.slice(0, LIMIT);
}

function SearchResults(props: { results: SearchResult[], active: number, onPick: (result: SearchResult) => void, onHover: (index: number) => void }) {
  const empty = createMemo(() => props.results.length === 0);

  return (
    <div class={styles.Results} role="listbox">
      <Show when={!empty()} fallback={<div class={styles.Empty}>Nothing matches</div>}>
        <For each={props.results}>
          {(result, index) => (
            <div
              class={styles.Result}
              classList={{ [styles.Active]: index() === props.active }}
              role="option"
              aria-selected={index() === props.active}
              style={{ "--result-color": result.color ?? "var(--text-muted)" }}
              onMouseDown={event => event.preventDefault()}
              onMouseEnter={() => props.onHover(index())}
              onClick={() => props.onPick(result)}
            >
              <span class={styles.Icon}><Dynamic component={result.icon} size={14} /></span>
              <span class={styles.Text}>
                <span class={styles.Label}>{result.label}</span>
                <span class={styles.Sub}>{result.kind} · {result.sub}</span>
              </span>
              <span class={styles.Action}>{result.action}</span>
            </div>
          )}
        </For>
      </Show>
      <div class={styles.Hint}>Enter opens the highlighted item. The panels below are filtered too.</div>
    </div>
  );
}

export default SearchResults;
