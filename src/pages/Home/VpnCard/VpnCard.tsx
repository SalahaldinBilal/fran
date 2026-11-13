import styles from "../ConnectionCard/ConnectionCard.module.scss";
import vpnStyles from "../panels/VpnPanel.module.scss";
import { Show, createMemo } from "solid-js";
import { CircleAlert, Ellipsis, GripVertical, Monitor, Pencil, Server, Shield, Unplug } from "@core/icons";
import useVpnState from "@core/states/vpnState";
import useVpnEditorState from "@core/states/vpnEditorState";
import useContextMenuState, { MenuItem } from "@core/states/contextMenuState";
import useSettingsState from "@core/states/settingsState";
import { vpnBackendLabel, vpnRunning, vpnServer, vpnStateLabel } from "@core/helpers/vpn";
import { disconnectVpn, setVpnOnComputer } from "@core/helpers/vpnActions";
import { syncMenu } from "@core/helpers/syncTargets";
import { itemKey } from "@core/states/syncState";
import { VpnAuth, VpnProfile } from "@core/types";
import Button from "@core/components/Button/Button";
import Toggle from "@core/components/Switch/Switch";
import { tooltip } from "@core/components/Tooltip/Tooltip";
import { ItemBadge, ItemIcon } from "@core/components/ItemParts/ItemParts";

const AUTH_LABELS: Record<VpnAuth, string> = { cert: "Certificate", userPass: "Password", certAndUserPass: "Certificate and password" };

export function vpnMenuItems(profile: VpnProfile): MenuItem[] {
  const vpn = useVpnState;
  const onComputer = vpn.onComputer(profile.id);
  const ownRunning = vpnRunning(vpn.status(profile.id)) && !onComputer;
  return [
    { label: "Edit", icon: Pencil, onSelect: () => useVpnEditorState.open(profile) },
    onComputer
      ? { label: "Turn off for this computer", icon: Monitor, onSelect: () => void setVpnOnComputer(profile, false) }
      : { label: "Turn on for this computer", icon: Monitor, disabled: vpn.turningOn(profile.id), onSelect: () => void setVpnOnComputer(profile, true) },
    ...(ownRunning ? [{ label: "Disconnect", icon: Unplug, onSelect: () => void disconnectVpn(profile) }] : []),
    ...syncMenu(itemKey("vpn", profile.id), profile.label, "vpnProfiles"),
  ];
}

// Everything a VPN card and its compact row show, so the two stay the same.
export function useVpnView(profile: () => VpnProfile) {
  const vpn = useVpnState;
  const status = createMemo(() => vpn.status(profile().id));
  const running = createMemo(() => vpnRunning(status()));
  const turningOn = createMemo(() => vpn.turningOn(profile().id));
  const onComputer = createMemo(() => vpn.onComputer(profile().id));
  const ownRunning = createMemo(() => running() && !onComputer());
  const stateLabel = createMemo(() => vpnStateLabel(status()));
  const live = createMemo(() => status()?.phase === "up");
  const failed = createMemo(() => (!running() && !turningOn() ? status()?.lastError ?? null : null));
  const server = createMemo(() => vpnServer(profile()));
  const filled = createMemo(() => useSettingsState.settings.colorFill && profile().color !== null);
  const systemOnly = createMemo(() => profile().needsSystem.length > 0 && !onComputer());
  const switchTooltip = createMemo(() => {
    if (!onComputer()) return "Turn on for this computer";
    const backend = vpnBackendLabel(status());
    return backend ? `On for this computer ${backend}. Turn off.` : "On for this computer. Turn off.";
  });
  return { status, running, turningOn, onComputer, ownRunning, stateLabel, live, failed, server, filled, systemOnly, switchTooltip };
}

export function VpnStateBadges(props: { view: ReturnType<typeof useVpnView>, profile: VpnProfile }) {
  return (
    <>
      <Show when={props.view.stateLabel()}>
        {label => (
          <span class={vpnStyles.State} classList={{ [vpnStyles.Live]: props.view.live() }}>
            <span class={vpnStyles.Dot} />
            <span class={vpnStyles.Label}>{label()}</span>
          </span>
        )}
      </Show>
      <Show when={props.view.failed()}>
        {message => (
          <span class={vpnStyles.Failed} ref={element => tooltip(element, () => message())}>
            <CircleAlert size={12} />
            <span class={vpnStyles.Label}>Failed</span>
          </span>
        )}
      </Show>
      <Show when={props.view.systemOnly()}>
        <span ref={element => tooltip(element, () => props.profile.needsSystem.join(". "))}>
          <ItemBadge tone="warning">Needs the installed OpenVPN</ItemBadge>
        </span>
      </Show>
    </>
  );
}

export function VpnComputerSwitch(props: { view: ReturnType<typeof useVpnView>, profile: VpnProfile, label?: string }) {
  return (
    <span
      class={vpnStyles.Computer}
      ref={element => tooltip(element, () => props.view.switchTooltip())}
      onClick={event => event.stopPropagation()}
      onKeyDown={event => event.stopPropagation()}
    >
      <Toggle
        checked={props.view.onComputer()}
        disabled={props.view.turningOn()}
        label={props.label}
        onChange={value => void setVpnOnComputer(props.profile, value)}
      />
    </span>
  );
}

function VpnCard(props: { profile: VpnProfile, onGrab?: (event: PointerEvent) => void }) {
  const { openContextMenu, openMenuAt } = useContextMenuState;
  const view = useVpnView(() => props.profile);

  const kind = createMemo(() => (props.profile.group ? `VPN, ${props.profile.group}` : "VPN"));
  const login = createMemo(() => (props.profile.kind === "wireGuard" ? "WireGuard" : AUTH_LABELS[props.profile.auth]));

  return (
    <div
      class={styles.Card}
      classList={{ [styles.Filled]: view.filled() }}
      style={{ "--card-color": props.profile.color ?? "var(--accent)" }}
      role="button"
      tabIndex={0}
      aria-label={`Edit ${props.profile.label}`}
      onClick={() => useVpnEditorState.open(props.profile)}
      onKeyDown={event => {
        if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) {
          event.preventDefault();
          useVpnEditorState.open(props.profile);
        }
      }}
      onContextMenu={event => openContextMenu(event, vpnMenuItems(props.profile))}
    >
      <div class={styles.Top}>
        <ItemIcon size="lg" color={props.profile.color}>
          <Shield size={18} />
        </ItemIcon>
        <div class={styles.Titles}>
          <div class={styles.Name} ref={element => tooltip(element, () => props.profile.label)}>{props.profile.label}</div>
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
          <Show when={view.ownRunning()}>
            <Button icon size="sm" tooltip="Disconnect" onClick={() => void disconnectVpn(props.profile)}>
              <Unplug size={14} />
            </Button>
          </Show>
          <Button icon size="sm" tooltip="Edit" onClick={() => useVpnEditorState.open(props.profile)}>
            <Pencil size={14} />
          </Button>
          <Button
            icon
            size="sm"
            tooltip="More"
            onClick={event => {
              const rect = event.currentTarget.getBoundingClientRect();
              openMenuAt({ x: rect.left, y: rect.bottom + 2 }, vpnMenuItems(props.profile));
            }}
          >
            <Ellipsis size={16} />
          </Button>
        </div>
      </div>

      <div class={styles.Target} ref={element => tooltip(element, view.server)}>
        <Server size={14} />
        <span>{view.server()}</span>
      </div>

      <div class={styles.Bottom}>
        <span class={styles.Badges}>
          <VpnStateBadges view={view} profile={props.profile} />
          <Show when={!view.stateLabel() && !view.failed() && !view.systemOnly()}>
            <ItemBadge>{login()}</ItemBadge>
          </Show>
        </span>
        <VpnComputerSwitch view={view} profile={props.profile} label="This computer" />
      </div>
    </div>
  );
}

export default VpnCard;
