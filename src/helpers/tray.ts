import { createEffect, createRoot } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import useVpnState from "@core/states/vpnState";
import useSettingsState from "@core/states/settingsState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import useLockState from "@core/states/lockState";
import useTerminalState from "@core/states/terminalState";
import useWorkspaceState from "@core/states/workspaceState";
import useForwardRulesState from "@core/states/forwardRulesState";
import usePortForwardState from "@core/states/portForwardState";
import useConnectionsState from "@core/states/connectionsState";
import useSshState from "@core/states/sshState";
import { featureOn } from "./features";
import { plural } from "@core/helpers";
import { vpnBackendLabel, vpnRunning, vpnStateLabel } from "./vpn";
import { setVpnOnComputer } from "./vpnActions";
import { safeInvoke } from "./safeInvoke";
import { TrayItem } from "@core/types";

function joinParts(parts: string[]): string {
  if (parts.length <= 1) return parts[0] ?? "";
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

// What stops when Fran quits, like "2 VPNs, 1 port forward and 3 terminals".
function runningParts(): string[] {
  const vpns = useVpnState.file.profiles.filter(profile => vpnRunning(useVpnState.status(profile.id))).length;
  const forwards = usePortForwardState.all().length + Object.keys(useForwardRulesState.running).length;
  const terminals = useTerminalState.tabs().length;
  const sessions = useWorkspaceState.store.globalTabs.filter(tab => tab.kind === "session").length;
  return [
    ...(vpns > 0 ? [plural(vpns, "VPN")] : []),
    ...(forwards > 0 ? [plural(forwards, "port forward")] : []),
    ...(terminals > 0 ? [plural(terminals, "terminal")] : []),
    ...(sessions > 0 ? [plural(sessions, "database session")] : []),
  ];
}

// Asks first when something is running. Behind the lock screen there's nothing to confirm with, so it just quits.
export async function quitApp() {
  const parts = runningParts();
  if (parts.length > 0 && !useLockState.locked()) {
    const confirmed = await usePromptState.confirm({
      title: "Quit Fran?",
      message: `${joinParts(parts)} stop.`,
      confirmLabel: "Quit",
      danger: true,
    });
    if (!confirmed) return;
  }
  await safeInvoke("quit_app");
}

function menuItems(): TrayItem[] {
  const items: TrayItem[] = [];
  if (featureOn("vpn")) {
    useVpnState.file.profiles.forEach((profile, index) => {
      const status = useVpnState.status(profile.id);
      const onComputer = useVpnState.onComputer(profile.id);
      const turning = useVpnState.turningOn(profile.id);
      const backend = vpnBackendLabel(status);
      items.push({
        id: `vpn:${profile.id}`,
        label: turning ? `${profile.label}: turning on` : `${profile.label} on this computer${onComputer && backend ? ` ${backend}` : ""}`,
        checked: onComputer,
        enabled: !turning,
        separatorBefore: index === 0,
      });
      if (vpnRunning(status) && !onComputer) items.push({ id: `own:${profile.id}`, label: `    ${vpnStateLabel(status)}`, enabled: false });
    });
  }
  const rules = useSshState.file.forwards.filter(rule => useForwardRulesState.status(rule.id));
  rules.forEach((rule, index) => items.push({ id: `forward:${rule.id}`, label: `Stop ${rule.label}`, separatorBefore: index === 0 }));
  usePortForwardState.all().forEach((info, index) => {
    const name = useConnectionsState.find(info.connectionId)?.name ?? "a connection";
    items.push({ id: `forward:db:${info.connectionId}`, label: `Stop forward for ${name}`, separatorBefore: index === 0 && rules.length === 0 });
  });
  if (useLockState.enabled() && !useLockState.locked()) items.push({ id: "lock", label: "Lock Fran", separatorBefore: true });
  return items;
}

function tooltip(): string {
  const parts = runningParts();
  return parts.length > 0 ? `Fran, ${joinParts(parts)} running` : "Fran";
}

// Tray actions that need the window come here. The menu is rebuilt whenever what's running changes.
export function startTray() {
  void listen("quit-requested", () => void quitApp().catch(useToastState.pushError));
  void listen<string>("tray-vpn", event => {
    const profile = useVpnState.profile(event.payload);
    if (profile) void setVpnOnComputer(profile, !useVpnState.onComputer(profile.id));
  });
  void listen<string>("tray-forward-stop", event => {
    const id = event.payload;
    if (id.startsWith("db:")) void usePortForwardState.stop(id.slice(3));
    else void useForwardRulesState.stop(id);
  });
  void listen("tray-lock", () => void useLockState.lock());
  void listen("tray-notice-shown", () => void useSettingsState.update({ trayNoticeShown: true }));

  createRoot(() => {
    createEffect(() => {
      const items = menuItems();
      const text = tooltip();
      const vpnOn = useVpnState.onComputerCount() > 0;
      void safeInvoke("set_tray_menu", { items, tooltip: text, vpnOn }).catch(() => undefined);
    });
  });
}
