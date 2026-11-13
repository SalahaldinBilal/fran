import { createMemo, createRoot, createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { listen } from "@tauri-apps/api/event";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { Cloud, CloudKind, SyncCategory, SyncPhase, SyncTarget, SyncView } from "@core/types";
import useConnectionsState from "./connectionsState";
import useSshState from "./sshState";
import useVpnState from "./vpnState";
import useSnippetsState from "./snippetsState";
import useSecretsState from "./secretsState";
import useSavedQueriesState from "./savedQueriesState";
import useSettingsState from "./settingsState";
import usePromptState from "./promptState";
import useToastState from "./toastState";

// The item kinds Rust uses in item keys, like `connection:<id>`.
export type SyncItemKind = "connection" | "sshHost" | "identity" | "key" | "proxy" | "forward" | "vpn" | "savedQuery" | "snippet" | "secret";

export type OverallSync = "off" | SyncPhase;

// `cloudId` set means signing back into that cloud. `kind` set skips the kind picker.
export type AddCloudRequest = { kind: CloudKind | null, cloudId: string | null };

const FOCUS_SYNC_EVERY_MS = 30_000;

const EMPTY: SyncView = {
  clouds: [],
  routes: { categories: {}, groups: {}, items: {} },
  homes: {},
  replaced: [],
  moved: {},
  missing: [],
  waitingRoutes: {},
  duplicates: [],
};

const RELOADS: Record<string, () => unknown> = {
  connection: () => useConnectionsState.load(),
  sshHost: () => useSshState.load(),
  identity: () => useSshState.load(),
  key: () => useSshState.load(),
  proxy: () => useSshState.load(),
  forward: () => useSshState.load(),
  knownHost: () => useSshState.loadKnownHosts(),
  vpn: () => useVpnState.load(),
  savedQuery: () => useSavedQueriesState.load(),
  snippet: () => useSnippetsState.load(),
  secret: () => useSecretsState.load(),
  vault: () => useSecretsState.load(),
  setting: () => useSettingsState.load(),
  order: () => Promise.all([useConnectionsState.load(), useSshState.load(), useVpnState.load()]),
};

export function itemKey(kind: SyncItemKind, id: string): string {
  return `${kind}:${id}`;
}

export function passwordKey(owner: { kind: string, id: string }, slot: string): string {
  return `vault:${owner.kind}:${owner.id}:${slot}`;
}

export function groupKey(kind: SyncItemKind, group: string): string {
  return `${kind}:${group}`;
}

function sameTarget(left: SyncTarget | null, right: SyncTarget | null): boolean {
  if (left === null || right === null) return left === right;
  return left.kind === right.kind && (left.kind !== "cloud" || (right.kind === "cloud" && left.cloud === right.cloud));
}

function useSyncStateInner() {
  const { pushError } = useToastState;
  const [view, setView] = createStore<SyncView>(EMPTY);
  const [loaded, setLoaded] = createSignal(false);
  const [addRequest, setAddRequest] = createSignal<AddCloudRequest | null>(null);
  // Shown once after sign-up or after a new key is made, then dropped.
  const [recoveryKey, setRecoveryKey] = createSignal<{ cloudName: string, key: string } | null>(null);

  const overall = createMemo<OverallSync>(() => {
    const phases = view.clouds.map(cloud => cloud.status.phase);
    if (phases.length === 0) return "off";
    if (phases.includes("error")) return "error";
    if (phases.includes("syncing")) return "syncing";
    return phases.includes("waiting") ? "waiting" : "upToDate";
  });

  // Clicking back into the window shouldn't start a pass each time. The workers also pull every 5 minutes.
  let lastFocusSync = 0;
  let loading: Promise<void> | null = null;
  let loadAgain = false;

  // One request at a time, with one more after it when anything changed meanwhile. Parallel ones could land out of order and leave an old status showing.
  function load(): Promise<void> {
    if (loading) {
      loadAgain = true;
      return loading;
    }
    loading = (async () => {
      do {
        loadAgain = false;
        try {
          setView(reconcile(await safeInvoke("sync_get")));
        } catch (error) {
          pushError(error);
        }
      } while (loadAgain);
      setLoaded(true);
      loading = null;
    })();
    return loading;
  }

  function start() {
    void load();
    void listen("sync-changed", () => void load());
    void listen<string[]>("sync-applied", event => {
      const reloads = new Set(event.payload.map(kind => RELOADS[kind]).filter(reload => reload !== undefined));
      reloads.forEach(reload => void reload());
    });
    window.addEventListener("focus", () => {
      if (view.clouds.length === 0 || Date.now() - lastFocusSync < FOCUS_SYNC_EVERY_MS) return;
      lastFocusSync = Date.now();
      void safeInvoke("sync_now", { cloudId: null }).catch(() => undefined);
    });
  }

  function cloud(id: string | null | undefined): Cloud | undefined {
    return id ? view.clouds.find(candidate => candidate.id === id) : undefined;
  }

  function cloudByIdentity(identity: string): Cloud | undefined {
    return view.clouds.find(candidate => candidate.identity === identity);
  }

  // The cloud an item syncs to right now, whatever decided it.
  function home(key: string): Cloud | undefined {
    return cloud(view.homes[key]);
  }

  // What the user picked on this exact item, null when it follows its group or category.
  function itemRoute(key: string): SyncTarget | null {
    return view.routes.items[key] ?? null;
  }

  function groupRoute(key: string): SyncTarget | null {
    return view.routes.groups[key] ?? null;
  }

  function categoryRoute(category: SyncCategory): SyncTarget | null {
    return view.routes.categories[category] ?? null;
  }

  async function run(action: () => Promise<unknown>) {
    try {
      await action();
      await load();
    } catch (error) {
      pushError(error);
    }
  }

  function setCategoryRoute(category: SyncCategory, target: SyncTarget | null) {
    return run(() => safeInvoke("sync_set_category_route", { category, target }));
  }

  function setGroupRoute(group: string, target: SyncTarget | null) {
    return run(() => safeInvoke("sync_set_group_route", { group, target }));
  }

  // Moving an item to a cloud offers to take along what it points at, when that lives somewhere else.
  async function setItemRoute(key: string, label: string, target: SyncTarget | null) {
    if (sameTarget(itemRoute(key), target)) return;
    const keys = [key];
    try {
      if (target?.kind === "cloud") {
        const others = await safeInvoke("sync_move_candidates", { key, cloudId: target.cloud });
        if (others.length > 0) {
          const names = others.map(other => other.label || other.key).join(", ");
          const along = await usePromptState.confirm({
            title: `Move what ${label} uses too?`,
            message: `${label} uses ${names}, which ${others.length === 1 ? "isn't" : "aren't"} in ${cloud(target.cloud)?.name ?? "that cloud"}. `
              + "A computer that only has that cloud would get it without them.",
            confirmLabel: "Move them too",
          });
          if (along) keys.push(...others.map(other => other.key));
        }
      }
      await safeInvoke("sync_set_item_routes", { keys, target });
      await load();
    } catch (error) {
      pushError(error);
    }
  }

  function useForEverything(cloudId: string) {
    return run(() => safeInvoke("sync_use_for_everything", { cloudId }));
  }

  function syncNow(cloudId: string | null) {
    return safeInvoke("sync_now", { cloudId }).catch(pushError);
  }

  function rename(cloudId: string, name: string) {
    return run(() => safeInvoke("sync_rename_cloud", { cloudId, name }));
  }

  function restore(id: string) {
    return run(() => safeInvoke("sync_restore_replaced", { id }));
  }

  function discard(id: string | null) {
    return run(() => safeInvoke("sync_discard_replaced", { id }));
  }

  // Null settles every one listed. Merge keeps the cloud's copy, else both stay.
  function settleDuplicates(ids: string[] | null, merge: boolean) {
    return run(() => safeInvoke("sync_settle_duplicates", { ids, merge }));
  }

  return {
    view,
    loaded,
    overall,
    load,
    start,
    cloud,
    cloudByIdentity,
    home,
    itemRoute,
    groupRoute,
    categoryRoute,
    setCategoryRoute,
    setGroupRoute,
    setItemRoute,
    useForEverything,
    syncNow,
    rename,
    restore,
    discard,
    settleDuplicates,
    addRequest,
    openAdd: (kind: CloudKind | null = null, cloudId: string | null = null) => setAddRequest({ kind, cloudId }),
    closeAdd: () => setAddRequest(null),
    recoveryKey,
    showRecoveryKey: (cloudName: string, key: string) => setRecoveryKey({ cloudName, key }),
    closeRecoveryKey: () => setRecoveryKey(null),
  };
}

const useSyncState = createRoot(useSyncStateInner);
export default useSyncState;
