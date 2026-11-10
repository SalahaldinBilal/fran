import shared from "./Panels.module.scss";
import { For, Show, createMemo } from "solid-js";
import { CodeXml, Play, Plus, SquareTerminal } from "lucide-solid";
import useSnippetsState from "@core/states/snippetsState";
import useTerminalState from "@core/states/terminalState";
import useSshState from "@core/states/sshState";
import useWorkspaceState from "@core/states/workspaceState";
import useContextMenuState, { MenuItem } from "@core/states/contextMenuState";
import { Snippet } from "@core/types";
import Button from "@core/components/Button/Button";
import EmptyState from "@core/components/EmptyState/EmptyState";
import { ItemBadge, ItemIcon } from "@core/components/ItemParts/ItemParts";
import PanelFrame from "./PanelFrame";
import { PanelProps } from "./types";

function SnippetRow(props: { snippet: Snippet }) {
  const snippets = useSnippetsState;
  const terminals = useTerminalState;
  const ssh = useSshState;
  const { openMenuAt } = useContextMenuState;

  function openRunMenu(event: MouseEvent) {
    event.stopPropagation();
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    const open = terminals.tabs().filter(tab => Object.values(tab.panes).some(pane => pane.status === "open"));
    const items: MenuItem[] = open.length > 0
      ? open.map(tab => ({
        label: ssh.host(tab.hostId)?.label ?? "Terminal",
        icon: SquareTerminal,
        onSelect: () => {
          useWorkspaceState.activateGlobalTab(tab.id);
          terminals.setDrawer(tab.id, true);
          terminals.applySnippet(tab.id, props.snippet, true);
        },
      }))
      : [{ label: "No terminal is connected", disabled: true }];
    openMenuAt({ x: rect.left, y: rect.bottom + 4 }, items);
  }

  return (
    <div
      class={shared.Row}
      role="button"
      tabIndex={0}
      onClick={() => snippets.openEditor(props.snippet)}
      onKeyDown={event => {
        if (event.key === "Enter") snippets.openEditor(props.snippet);
      }}
    >
      <ItemIcon color="var(--text-muted)"><CodeXml size={15} /></ItemIcon>
      <span class={shared.RowText}>
        <span class={shared.RowName}>{props.snippet.label}</span>
        <span class={shared.RowSub}>{props.snippet.command}</span>
      </span>
      <Show when={props.snippet.confirm}>
        <ItemBadge tone="warning">Asks first</ItemBadge>
      </Show>
      <Button size="sm" variant="subtle" onClick={openRunMenu}>
        <Play size={11} />
        Run on
      </Button>
    </div>
  );
}

function SnippetsPanel(props: PanelProps) {
  const snippets = useSnippetsState;

  const filtered = createMemo(() => {
    const needle = props.search.trim().toLowerCase();
    if (!needle) return snippets.snippets;
    return snippets.snippets.filter(snippet => [snippet.label, snippet.command].some(text => text.toLowerCase().includes(needle)));
  });
  const count = createMemo(() => (snippets.snippets.length > 0 ? snippets.snippets.length : null));

  return (
    <PanelFrame
      title="Snippets"
      icon={CodeXml}
      count={count()}
      controls={props.controls}
      actions={
        <Button icon size="sm" tooltip="New snippet" onClick={() => snippets.openEditor(null)}>
          <Plus size={14} />
        </Button>
      }
    >
      <Show
        when={snippets.snippets.length > 0}
        fallback={
          <div class={shared.Center}>
            <EmptyState
              icon={CodeXml}
              title="No snippets"
              description="Save commands you run often, then run them from any terminal."
              actions={<Button variant="subtle" onClick={() => snippets.openEditor(null)}>New snippet</Button>}
            />
          </div>
        }
      >
        <Show
          when={filtered().length > 0}
          fallback={<div class={shared.Center}><EmptyState title="Nothing matches" description={`No snippet matches "${props.search.trim()}".`} /></div>}
        >
          <div class={shared.Rows}>
            <For each={filtered()}>{snippet => <SnippetRow snippet={snippet} />}</For>
          </div>
        </Show>
      </Show>
    </PanelFrame>
  );
}

export default SnippetsPanel;
