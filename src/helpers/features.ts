import useSettingsState, { AppSettings, Features } from "@core/states/settingsState";
import useWorkspaceState, { GlobalTab } from "@core/states/workspaceState";
import useAgentState from "@core/states/agentState";
import useVpnState from "@core/states/vpnState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import { plural } from "@core/helpers";
import { addPanel, panelsIn } from "@core/helpers/tiling";

export type Feature = keyof Features | "any";

const FEATURE_NAMES: Record<keyof Features, string> = {
  database: "database client",
  ssh: "SSH client",
  vpn: "VPN client",
};

export function featureOn(feature: Feature): boolean {
  return feature === "any" || useSettingsState.settings.features[feature];
}

export function tabFeature(tab: GlobalTab): Feature {
  switch (tab.kind) {
    case "session":
    case "agents":
      return "database";
    case "terminal":
    case "sftp":
      return "ssh";
    default:
      return "any";
  }
}

// False when nothing changed, because both would be off or the user kept the tabs open.
export async function setFeatures(next: Features, extra: Partial<AppSettings> = {}): Promise<boolean> {
  if (!next.database && !next.ssh && !next.vpn) {
    useToastState.pushToast("Keep at least one of them on");
    return false;
  }

  const workspace = useWorkspaceState;
  const current = useSettingsState.settings.features;
  const turningOff = (Object.keys(FEATURE_NAMES) as (keyof Features)[]).filter(feature => current[feature] && !next[feature]);
  const closing = workspace.store.globalTabs.filter(tab => {
    const feature = tabFeature(tab);
    return feature !== "any" && !next[feature];
  });

  const stoppingVpns = current.vpn && !next.vpn ? useVpnState.onComputerCount() : 0;
  if (closing.length > 0 || stoppingVpns > 0) {
    const names = turningOff.map(feature => FEATURE_NAMES[feature]).join(" and ");
    const parts = [
      ...(closing.length > 0 ? [`${plural(closing.length, "open tab")} will close.`] : []),
      ...(stoppingVpns > 0 ? [`${plural(stoppingVpns, "VPN")} on for this computer will turn off.`] : []),
    ];
    const confirmed = await usePromptState.confirm({
      title: `Turn off the ${names}?`,
      message: `${parts.join(" ")} Nothing you've saved is removed.`,
      confirmLabel: "Turn off",
      danger: true,
    });
    if (!confirmed) return false;
  }

  for (const tab of closing) await workspace.closeGlobalTab(tab.id, true);
  if (!next.database && useAgentState.config.enabled) await useAgentState.update({ enabled: false });
  // Own tunnels keep working for connections and hosts that use them, like SSH hosts stay for DB tunnels.
  if (stoppingVpns > 0) await useVpnState.stopSystems();
  // A layout arranged by hand doesn't have the VPN panel yet, so turning the VPN client on adds it.
  const layout = useSettingsState.settings.homeLayout;
  const homeLayout = next.vpn && !current.vpn && layout && !panelsIn(layout).includes("vpn")
    ? { homeLayout: addPanel(JSON.parse(JSON.stringify(layout)), "vpn") }
    : {};
  await useSettingsState.update({ ...extra, ...homeLayout, features: { ...next } });
  return true;
}
