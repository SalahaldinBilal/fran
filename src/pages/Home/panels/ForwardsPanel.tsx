import shared from "./Panels.module.scss";
import styles from "./ForwardsPanel.module.scss";
import { For, Show, createMemo } from "solid-js";
import { ArrowLeftRight, Plus } from "lucide-solid";
import useSshState from "@core/states/sshState";
import useForwardRulesState from "@core/states/forwardRulesState";
import useContextMenuState from "@core/states/contextMenuState";
import { describeForward } from "@core/helpers/forwardRules";
import { ForwardRule } from "@core/types";
import Button from "@core/components/Button/Button";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Switch from "@core/components/Switch/Switch";
import { ItemIcon } from "@core/components/ItemParts/ItemParts";
import PanelFrame from "./PanelFrame";
import { PanelProps } from "./types";

const KIND_LETTER = { local: "L", remote: "R", dynamic: "D" } as const;

function ForwardRow(props: { rule: ForwardRule }) {
  const ssh = useSshState;
  const rules = useForwardRulesState;
  const { openContextMenu } = useContextMenuState;

  const running = createMemo(() => rules.status(props.rule.id));
  const busy = createMemo(() => rules.busy[props.rule.id] ?? false);
  const via = createMemo(() => ssh.host(props.rule.hostId)?.label ?? "a deleted host");
  const sub = createMemo(() => `${describeForward(props.rule)} · via ${via()}`);
  const kindColor = createMemo(() => (running() ? "var(--success)" : "var(--text-muted)"));

  return (
    <div
      class={shared.Row}
      role="button"
      tabIndex={0}
      onClick={() => rules.openEditor(props.rule)}
      onKeyDown={event => {
        if (event.key === "Enter") rules.openEditor(props.rule);
      }}
      onContextMenu={event => openContextMenu(event, [
        { label: running() ? "Stop" : "Start", icon: ArrowLeftRight, disabled: busy(), onSelect: () => void rules.toggle(props.rule) },
        { label: "Edit", onSelect: () => rules.openEditor(props.rule) },
      ])}
    >
      <ItemIcon color={kindColor()}><span class={styles.Kind}>{KIND_LETTER[props.rule.kind]}</span></ItemIcon>
      <span class={shared.RowText}>
        <span class={shared.RowName}>{props.rule.label}</span>
        <span class={shared.RowSub}>{sub()}</span>
      </span>
      <span class={styles.Toggle} onClick={event => event.stopPropagation()}>
        <Switch checked={running() !== undefined} disabled={busy()} onChange={() => void rules.toggle(props.rule)} />
      </span>
    </div>
  );
}

function ForwardsPanel(props: PanelProps) {
  const ssh = useSshState;
  const rules = useForwardRulesState;

  const filtered = createMemo(() => {
    const needle = props.search.trim().toLowerCase();
    if (!needle) return ssh.file.forwards;
    return ssh.file.forwards.filter(rule => {
      const host = ssh.host(rule.hostId)?.label ?? "";
      return [rule.label, describeForward(rule), host].some(text => text.toLowerCase().includes(needle));
    });
  });
  const count = createMemo(() => (ssh.file.forwards.length > 0 ? ssh.file.forwards.length : null));

  return (
    <PanelFrame
      title="Port forwards"
      icon={ArrowLeftRight}
      count={count()}
      controls={props.controls}
      actions={
        <Button icon size="sm" tooltip="New port forward" onClick={() => rules.openEditor(null)}>
          <Plus size={14} />
        </Button>
      }
    >
      <Show
        when={ssh.file.forwards.length > 0}
        fallback={
          <div class={shared.Center}>
            <EmptyState
              icon={ArrowLeftRight}
              title="No port forwards"
              description="Reach a port behind an SSH host from this computer, or the other way around."
              actions={<Button variant="subtle" onClick={() => rules.openEditor(null)}>New forward</Button>}
            />
          </div>
        }
      >
        <Show
          when={filtered().length > 0}
          fallback={<div class={shared.Center}><EmptyState title="Nothing matches" description={`No forward matches "${props.search.trim()}".`} /></div>}
        >
          <div class={shared.Rows}>
            <For each={filtered()}>{rule => <ForwardRow rule={rule} />}</For>
          </div>
        </Show>
      </Show>
    </PanelFrame>
  );
}

export default ForwardsPanel;
