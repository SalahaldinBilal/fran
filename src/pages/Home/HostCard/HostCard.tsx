import styles from "../ConnectionCard/ConnectionCard.module.scss";
import { Show, createMemo } from "solid-js";
import { ArrowLeftRight, ArrowRight, Ellipsis, FolderOpen, GripVertical, Pencil, Server, SquareTerminal } from "lucide-solid";
import useSshState from "@core/states/sshState";
import useHostEditorState from "@core/states/hostEditorState";
import useTerminalState from "@core/states/terminalState";
import useSftpState from "@core/states/sftpState";
import useForwardRulesState from "@core/states/forwardRulesState";
import useContextMenuState, { MenuItem } from "@core/states/contextMenuState";
import useSettingsState from "@core/states/settingsState";
import { featureOn } from "@core/helpers/features";
import { SshHost } from "@core/types";
import Button from "@core/components/Button/Button";
import { tooltip } from "@core/components/Tooltip/Tooltip";
import { ItemBadge, ItemIcon } from "@core/components/ItemParts/ItemParts";

// Opens a terminal, or the editor when the SSH client is off and the host is only there for tunnels.
export function activateHost(host: SshHost) {
  if (featureOn("ssh")) useTerminalState.open(host.id);
  else useHostEditorState.open(host);
}

export function hostMenuItems(host: SshHost): MenuItem[] {
  return [
    ...(featureOn("ssh")
      ? [
        { label: "Open terminal", icon: SquareTerminal, onSelect: () => useTerminalState.open(host.id) },
        { label: "Browse files", icon: FolderOpen, onSelect: () => useSftpState.open(host.id) },
      ]
      : []),
    { label: "Edit", icon: Pencil, onSelect: () => useHostEditorState.open(host) },
    { label: "New port forward", icon: ArrowLeftRight, onSelect: () => useForwardRulesState.openEditor(null, host.id) },
  ];
}

function loginLabel(host: SshHost): string {
  const identity = useSshState.identity(host.identityId);
  switch (identity?.auth.kind) {
    case "key": return "Key";
    case "agent": return "SSH agent";
    case "password": return "Password";
    default: return "No login";
  }
}

export type HostCardProps = {
  host: SshHost,
  onGrab?: (event: PointerEvent) => void,
};

function HostCard(props: HostCardProps) {
  const ssh = useSshState;
  const { openContextMenu, openMenuAt } = useContextMenuState;

  const terminalsOn = createMemo(() => featureOn("ssh"));
  const filled = createMemo(() => useSettingsState.settings.colorFill && props.host.color !== null);
  const jumps = createMemo(() => props.host.jumps.flatMap(id => ssh.host(id)?.label ?? []));
  const proxy = createMemo(() => ssh.proxy(props.host.proxyId));
  const target = createMemo(() => {
    const via = jumps().length > 0 ? ` via ${jumps().join(", ")}` : "";
    return `${ssh.address(props.host)}${via}`;
  });
  const kind = createMemo(() => props.host.group ? `SSH host, ${props.host.group}` : "SSH host");
  const login = createMemo(() => loginLabel(props.host));
  const status = createMemo(() => (terminalsOn() ? "Open terminal" : "Edit"));

  return (
    <div
      class={styles.Card}
      classList={{ [styles.Filled]: filled() }}
      style={{ "--card-color": props.host.color ?? "var(--accent)" }}
      role="button"
      tabIndex={0}
      aria-label={`${status()} ${props.host.label}`}
      onClick={() => activateHost(props.host)}
      onKeyDown={event => {
        if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) {
          event.preventDefault();
          activateHost(props.host);
        }
      }}
      onContextMenu={event => openContextMenu(event, hostMenuItems(props.host))}
    >
      <div class={styles.Top}>
        <ItemIcon size="lg" color={props.host.color}>
          <Server size={18} />
        </ItemIcon>
        <div class={styles.Titles}>
          <div class={styles.Name} ref={element => tooltip(element, () => props.host.label)}>{props.host.label}</div>
          <div class={styles.Kind}>{kind()}</div>
        </div>
        <div class={styles.Tools} onClick={event => event.stopPropagation()}>
          <Show when={props.onGrab}>
            {grab => (
              <span ref={element => tooltip(element, () => "Drag to reorder")} class={styles.Grip} onPointerDown={event => grab()(event)}>
                <GripVertical size={14} />
              </span>
            )}
          </Show>
          <Show when={terminalsOn()}>
            <Button icon size="sm" tooltip="Browse files" onClick={() => useSftpState.open(props.host.id)}>
              <FolderOpen size={14} />
            </Button>
          </Show>
          <Button icon size="sm" tooltip="Edit" onClick={() => useHostEditorState.open(props.host)}>
            <Pencil size={14} />
          </Button>
          <Button
            icon
            size="sm"
            tooltip="More"
            onClick={event => {
              const rect = event.currentTarget.getBoundingClientRect();
              openMenuAt({ x: rect.left, y: rect.bottom + 2 }, hostMenuItems(props.host));
            }}
          >
            <Ellipsis size={16} />
          </Button>
        </div>
      </div>

      <div class={styles.Target} ref={element => tooltip(element, target)}>
        <SquareTerminal size={14} />
        <span>{target()}</span>
      </div>

      <div class={styles.Bottom}>
        <span class={styles.Badges}>
          <ItemBadge>{login()}</ItemBadge>
          <Show when={proxy()}>
            {item => <ItemBadge>{item().label}</ItemBadge>}
          </Show>
          <Show when={props.host.agentForwarding}>
            <ItemBadge tone="warning">Agent forwarding</ItemBadge>
          </Show>
        </span>
        <span class={styles.Status}>
          {status()}
          <ArrowRight size={14} class={styles.Arrow} />
        </span>
      </div>
    </div>
  );
}

export default HostCard;
