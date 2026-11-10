import { createEffect, createRoot, on } from "solid-js";
import useVpnState from "@core/states/vpnState";
import useSettingsState from "@core/states/settingsState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import useWorkspaceState from "@core/states/workspaceState";
import useTerminalState from "@core/states/terminalState";
import useSftpState from "@core/states/sftpState";
import useForwardRulesState from "@core/states/forwardRulesState";
import useSshState from "@core/states/sshState";
import { withDatabaseModule } from "@core/databases";
import { safeInvoke } from "./safeInvoke";
import { withConnectPrompts } from "./connectFlow";
import { plural } from "@core/helpers";
import { ConnectionProfile, ForwardRule, SystemBackend, VpnProfile } from "@core/types";

export function connectionVpnId(profile: ConnectionProfile): string | null {
  const leg = withDatabaseModule(profile, (module, options) => module.vpnLeg(options));
  if (!leg) return null;
  if (leg.kind === "savedHost") return leg.hostId ? useSshState.routeVpnId(leg.hostId) : null;
  return profile.vpnId ?? null;
}

function hostUsesVpn(hostId: string, profileId: string): boolean {
  return useSshState.routeVpnId(hostId) === profileId;
}

function runningRules(profileId: string): ForwardRule[] {
  return useSshState.file.forwards.filter(rule => useForwardRulesState.status(rule.id) && hostUsesVpn(rule.hostId, profileId));
}

// What's open through the VPN right now, by name, for the confirms.
export function vpnUserNames(profileId: string): string[] {
  const workspace = useWorkspaceState;
  const names: string[] = [];
  for (const tab of workspace.store.globalTabs) {
    if (tab.kind !== "session") continue;
    const session = workspace.store.sessions[tab.sessionId];
    if (session && connectionVpnId(session.profile) === profileId) names.push(session.profile.name);
  }
  const terminals = useTerminalState.tabs().filter(tab => hostUsesVpn(tab.hostId, profileId));
  if (terminals.length > 0) {
    const hosts = [...new Set(terminals.map(tab => useSshState.host(tab.hostId)?.label ?? "a host"))];
    names.push(`${terminals.length === 1 ? "a terminal" : `${terminals.length} terminals`} on ${hosts.join(", ")}`);
  }
  const files = useSftpState.tabs().filter(tab => hostUsesVpn(tab.hostId, profileId));
  if (files.length > 0) names.push(files.length === 1 ? "a file tab" : `${files.length} file tabs`);
  for (const rule of runningRules(profileId)) names.push(`the ${rule.label} forward`);
  return names;
}

function joinNames(names: string[]): string {
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

// The users by name when Fran knows them, else how many. Agent sessions are counted but not listed.
function usersText(profileId: string, users: number): string {
  const names = vpnUserNames(profileId);
  return `In use by ${names.length > 0 ? joinNames(names) : plural(users, "connection")}.`;
}

// What was up through the VPN when a switch started. Only these get reconnected.
type Users = { panes: Map<string, Set<string>>, files: Set<string>, rules: ForwardRule[] };

function openUsers(profileId: string): Users {
  const panes = new Map<string, Set<string>>();
  for (const tab of useTerminalState.tabs()) {
    if (!hostUsesVpn(tab.hostId, profileId)) continue;
    const open = Object.entries(tab.panes).filter(([, pane]) => pane.status === "open").map(([paneId]) => paneId);
    if (open.length > 0) panes.set(tab.id, new Set(open));
  }
  const files = new Set(useSftpState.tabs().filter(tab => hostUsesVpn(tab.hostId, profileId) && tab.status === "open").map(tab => tab.id));
  return { panes, files, rules: runningRules(profileId) };
}

const watching = new Map<string, () => void>();

// Each one is reconnected as soon as it drops, and let go of once it has, or once it's closed by hand.
function reconnectUsers(profileId: string, users: Users) {
  watching.get(profileId)?.();
  const rules = new Map(users.rules.map(rule => [rule.id, rule]));
  createRoot(dispose => {
    watching.set(profileId, dispose);
    createEffect(() => {
      for (const [tabId, paneIds] of users.panes) {
        const tab = useTerminalState.tabs().find(candidate => candidate.id === tabId);
        for (const paneId of [...paneIds]) {
          const status = tab?.panes[paneId]?.status;
          if (status === undefined) paneIds.delete(paneId);
          if (status === "closed") {
            paneIds.delete(paneId);
            void useTerminalState.connect(tabId, paneId);
          }
        }
        if (paneIds.size === 0) users.panes.delete(tabId);
      }
      for (const tabId of [...users.files]) {
        const tab = useSftpState.tabs().find(candidate => candidate.id === tabId);
        if (!tab) users.files.delete(tabId);
        if (tab?.status === "closed") {
          users.files.delete(tabId);
          void useSftpState.connect(tabId);
        }
      }
      for (const [ruleId, rule] of [...rules]) {
        if (!useSshState.forward(ruleId)) rules.delete(ruleId);
        if (!useForwardRulesState.status(ruleId) && !useForwardRulesState.busy[ruleId]) {
          rules.delete(ruleId);
          void useForwardRulesState.start(rule);
        }
      }
      if (users.panes.size === 0 && users.files.size === 0 && rules.size === 0) {
        watching.delete(profileId);
        queueMicrotask(dispose);
      }
    });
  });
}

export async function disconnectVpn(profile: VpnProfile) {
  const status = useVpnState.status(profile.id);
  if (status && status.users > 0) {
    const confirmed = await usePromptState.confirm({
      title: `Disconnect ${profile.label}?`,
      message: `${usersText(profile.id, status.users)} They lose their connection and reconnect when you use them again.`,
      confirmLabel: "Disconnect",
      danger: true,
    });
    if (!confirmed) return;
  }
  try {
    await useVpnState.disconnect(profile.id);
  } catch (error) {
    useToastState.pushError(error);
  }
}

// WireGuard always goes through Fran's service, OpenVPN when that's the choice in Settings and its profile doesn't
// need the installed OpenVPN. A service that isn't set up yet is offered here instead of failing.
async function serviceReady(profile: VpnProfile, backend: SystemBackend): Promise<boolean> {
  const needsInstalled = profile.needsSystem.length > 0 || profile.systemOptions.some(option => option[0] === "cryptoapicert" || option[0] === "pkcs11-id");
  const usesService = profile.kind === "wireGuard" || (backend === "fran" && !needsInstalled);
  if (!usesService) return true;
  const status = await safeInvoke("vpn_service_status");
  if (status.state !== "notSetUp" || status.nixos) return true;
  const confirmed = await usePromptState.confirm({
    title: "Set up Fran's VPN service?",
    message: `${profile.label} turns on for this computer through Fran's VPN service. Setting it up asks for admin rights once, then turning VPNs on asks for nothing. It's set up for everyone on this computer, which you can change in Settings > VPN.`,
    confirmLabel: "Set up",
  });
  if (!confirmed) return false;
  await safeInvoke("set_up_vpn_service", { access: "everyone" });
  return true;
}

// On runs Fran's service, or the installed OpenVPN when picked or needed, which asks for the admin password on macOS
// and Linux. Either way it logs in again.
export async function setVpnOnComputer(profile: VpnProfile, on: boolean) {
  const users = useVpnState.status(profile.id)?.users ?? 0;
  if (users > 0) {
    const confirmed = await usePromptState.confirm(on
      ? {
        title: `Turn on ${profile.label} for this computer?`,
        message: `${usersText(profile.id, users)} Once it's on for the computer, they move over and reconnect by themselves. Database connections reconnect on their next query.`,
        confirmLabel: "Turn on",
      }
      : {
        title: `Turn off ${profile.label} for this computer?`,
        message: `${usersText(profile.id, users)} They move back to Fran's own tunnel and reconnect by themselves. A VPN that asks for a one-time code asks for a new one.`,
        confirmLabel: "Turn off",
        danger: true,
      });
    if (!confirmed) return;
  }
  const open = openUsers(profile.id);
  try {
    if (!on) {
      await useVpnState.turnOffSystem(profile.id);
      // A one-time code can't log in twice, so the own tunnel needs a new one before anything can move back.
      if (users > 0 && profile.challenge.kind === "static" && profile.needsSystem.length === 0) {
        await withConnectPrompts(
          { connectionId: null, connectionName: profile.label },
          secrets => safeInvoke("open_vpn_tunnel", { profileId: profile.id, secrets }),
        );
      }
    } else {
      const program = useSettingsState.settings.vpn.program.trim() || null;
      const backend = useSettingsState.settings.vpn.systemWith;
      if (!(await serviceReady(profile, backend))) return;
      const done = await withConnectPrompts(
        { connectionId: null, connectionName: profile.label },
        secrets => useVpnState.turnOnSystem(profile.id, secrets, program, backend),
      );
      if (done === null) return;
    }
    reconnectUsers(profile.id, open);
  } catch (error) {
    useToastState.pushError(error);
  }
}

async function answerPrompt(profile: VpnProfile, key: string) {
  const prompt = useVpnState.status(profile.id)?.prompt;
  if (!prompt) return;
  const stored = prompt.slots.filter(slot => slot.store && !slot.oneTime);
  const answer = await usePromptState.askForSecrets(profile.label, prompt.slots, stored.length > 0, { title: prompt.title, submitLabel: "Send" });
  // The prompt may have been answered or dropped in the meantime.
  if (promptKey(profile.id) !== key) return;
  try {
    if (!answer) {
      await useVpnState.turnOffSystem(profile.id);
      return;
    }
    if (answer.save) {
      for (const slot of stored) {
        const value = answer.values[slot.id];
        if (value && slot.store) await safeInvoke("set_owner_secret", { owner: slot.store.owner, slot: slot.store.slot, value });
      }
    }
    await useVpnState.answerPrompt(profile.id, answer.values);
  } catch (error) {
    useToastState.pushError(error);
  }
}

function promptKey(profileId: string): string | null {
  const prompt = useVpnState.status(profileId)?.prompt;
  return prompt ? `${profileId}:${prompt.title}:${prompt.slots.map(slot => slot.id).join(",")}` : null;
}

// A VPN on for the computer can ask for something mid-session, like a new one-time code. One prompt at a time.
export function watchVpnPrompts() {
  createRoot(() => {
    const asked = new Set<string>();
    createEffect(on(() => useVpnState.file.profiles.map(profile => promptKey(profile.id)), keys => {
      for (const key of [...asked]) {
        if (!keys.includes(key)) asked.delete(key);
      }
      useVpnState.file.profiles.forEach((profile, index) => {
        const key = keys[index];
        if (key && !asked.has(key)) {
          asked.add(key);
          void answerPrompt(profile, key);
        }
      });
    }));
  });
}
