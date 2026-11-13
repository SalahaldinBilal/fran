import { Cloud as CloudIcon } from "@core/icons";
import { withCloudModule } from "@core/clouds";
import useSyncState from "@core/states/syncState";
import { MenuItem } from "@core/states/contextMenuState";
import { Cloud, SyncCategory, SyncTarget } from "@core/types";

// Where the choice is made. A category's empty choice is "Don't sync", anything narrower falls back to what's above it.
export type SyncScope = "category" | "group" | "item";

export type SyncChoice = { id: string, label: string, hint?: string, target: SyncTarget | null };

export const SYNC_CATEGORIES: readonly { id: SyncCategory, label: string, hint?: string }[] = [
  { id: "connections", label: "Connections" },
  { id: "sshHosts", label: "SSH hosts" },
  { id: "identities", label: "Identities and keys", hint: "Logins and the public half of keys. Private keys have their own row." },
  { id: "proxies", label: "Proxies" },
  { id: "vpnProfiles", label: "VPN profiles", hint: "Servers, certificates and options. Never the client key." },
  { id: "forwards", label: "Port forward rules" },
  { id: "knownHosts", label: "Known hosts" },
  { id: "savedQueries", label: "Saved queries" },
  { id: "snippets", label: "Snippets" },
  { id: "settings", label: "Settings", hint: "Not the ones that belong to one computer, like the Home layout. The choices on this page go with them, except this one." },
  { id: "secrets", label: "Secrets", hint: "Their names and notes. The values follow the next row." },
  { id: "passwords", label: "Passwords and secret values", hint: "Readable on every computer signed into that cloud." },
  { id: "privateKeys", label: "Private keys", hint: "SSH keys kept in the vault, VPN client keys, TLS and preshared keys." },
];

const KIND_LABELS: Record<string, string> = {
  connection: "Connection",
  sshHost: "SSH host",
  identity: "Identity",
  key: "Key",
  proxy: "Proxy",
  forward: "Port forward",
  vpn: "VPN",
  savedQuery: "Saved query",
  snippet: "Snippet",
  knownHost: "Known host",
  setting: "Setting",
  secret: "Secret",
  vault: "Password or key",
  order: "Order",
};

// "Connection", "SSH host" and so on, from an item key like `connection:<id>`.
export function kindLabel(key: string): string {
  return KIND_LABELS[key.split(":", 1)[0]] ?? "Item";
}

export function isSecretCategory(category: SyncCategory): boolean {
  return category === "passwords" || category === "privateKeys";
}

export function targetId(target: SyncTarget | null): string {
  if (target === null) return "";
  return target.kind === "cloud" ? `cloud:${target.cloud}` : target.kind;
}

function accepting(category: SyncCategory): Cloud[] {
  return useSyncState.view.clouds.filter(cloud => withCloudModule(cloud, module => module.accepts(category)));
}

// `inherited` names what an empty choice ends up as, like "Personal" or "Not synced".
export function syncChoices(category: SyncCategory, scope: SyncScope, inherited?: string): SyncChoice[] {
  const choices: SyncChoice[] = scope === "category"
    ? [{ id: "", label: "Don't sync", target: null }]
    : [
      { id: "", label: scope === "group" ? "Same as the others" : "Same as its group", hint: inherited, target: null },
      { id: "local", label: "Keep on this computer", target: { kind: "local" } },
    ];
  if (isSecretCategory(category)) {
    choices.push({ id: "withItem", label: "Same cloud as the item it belongs to", target: { kind: "withItem" } });
  }
  for (const cloud of accepting(category)) {
    const target: SyncTarget = { kind: "cloud", cloud: cloud.id };
    choices.push({ id: targetId(target), label: cloud.name, hint: cloud.status.signedOut ? "Signed out" : undefined, target });
  }
  return choices;
}

// What an item with no choice of its own syncs to right now.
export function homeLabel(key: string): string {
  return useSyncState.home(key)?.name ?? "Not synced";
}

// The "Sync to" entry of an item's context menu. Empty when there's no cloud to pick.
export function syncMenu(key: string, label: string, category: SyncCategory): MenuItem[] {
  const sync = useSyncState;
  if (accepting(category).length === 0) return [];
  const current = targetId(sync.itemRoute(key));
  return [{
    label: "Sync to",
    icon: CloudIcon,
    hint: homeLabel(key),
    children: syncChoices(category, "item").map(choice => ({
      label: choice.id === current ? `${choice.label} (now)` : choice.label,
      hint: choice.hint,
      onSelect: () => void sync.setItemRoute(key, label, choice.target),
    })),
  }];
}

export function groupSyncMenu(group: string, category: SyncCategory): MenuItem[] {
  const sync = useSyncState;
  if (accepting(category).length === 0) return [];
  const current = targetId(sync.groupRoute(group));
  return [{
    label: "Sync this group to",
    icon: CloudIcon,
    children: syncChoices(category, "group").map(choice => ({
      label: choice.id === current ? `${choice.label} (now)` : choice.label,
      onSelect: () => void sync.setGroupRoute(group, choice.target),
    })),
  }];
}
