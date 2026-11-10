import { createMemo, createRoot, createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { Channel } from "@tauri-apps/api/core";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { SystemBackend, VpnFile, VpnProfile, VpnStatus } from "@core/types";

const EMPTY: VpnFile = { version: 1, profiles: [], groupOrder: [] };

function useVpnStateInner() {
  const [file, setFile] = createStore<VpnFile>(structuredClone(EMPTY));
  const [statuses, setStatuses] = createStore<Record<string, VpnStatus>>({});
  const [loaded, setLoaded] = createSignal(false);
  const [loadError, setLoadError] = createSignal<unknown>(null);
  let watching = false;

  async function load() {
    try {
      setFile(reconcile(await safeInvoke("list_vpn")));
      setLoadError(null);
    } catch (error) {
      setLoadError(error);
    } finally {
      setLoaded(true);
    }
    if (!watching) {
      watching = true;
      const channel = new Channel<VpnStatus[]>();
      channel.onmessage = list => setStatuses(reconcile(Object.fromEntries(list.map(status => [status.profileId, status]))));
      void safeInvoke("watch_vpn", { channel }).catch(() => {
        watching = false;
      });
    }
  }

  function profile(id: string | null): VpnProfile | undefined {
    return id ? file.profiles.find(candidate => candidate.id === id) : undefined;
  }

  function status(id: string): VpnStatus | undefined {
    return statuses[id];
  }

  function upsert(saved: VpnProfile) {
    setFile("profiles", items => (items.some(item => item.id === saved.id)
      ? items.map(item => (item.id === saved.id ? saved : item))
      : [...items, saved]));
  }

  async function save(next: VpnProfile): Promise<VpnProfile> {
    const saved = await safeInvoke("save_vpn_profile", { profile: next });
    upsert(saved);
    return saved;
  }

  async function importFile(path: string, secrets: Record<string, string> = {}): Promise<VpnProfile> {
    const saved = await safeInvoke("import_vpn_file", { path, secrets });
    upsert(saved);
    return saved;
  }

  async function setKey(id: string, pem: string): Promise<VpnProfile> {
    const saved = await safeInvoke("set_vpn_key", { id, pem });
    upsert(saved);
    return saved;
  }

  async function clearKey(id: string): Promise<VpnProfile> {
    const saved = await safeInvoke("clear_vpn_key", { id });
    upsert(saved);
    return saved;
  }

  async function setWireGuardKey(id: string, key: string): Promise<VpnProfile> {
    const saved = await safeInvoke("set_vpn_wireguard_key", { id, key });
    upsert(saved);
    return saved;
  }

  async function generateWireGuardKey(id: string): Promise<VpnProfile> {
    const saved = await safeInvoke("generate_vpn_wireguard_key", { id });
    upsert(saved);
    return saved;
  }

  async function remove(id: string) {
    await safeInvoke("delete_vpn_profile", { id });
    setFile("profiles", items => items.filter(item => item.id !== id));
  }

  async function disconnect(id: string) {
    await safeInvoke("disconnect_vpn", { profileId: id });
  }

  async function turnOnSystem(id: string, secrets: Record<string, string>, program: string | null, with_: SystemBackend) {
    await safeInvoke("turn_on_vpn_system", { profileId: id, secrets, program, with: with_ });
  }

  // From the admin prompt until it's connected.
  function turningOn(id: string): boolean {
    const current = statuses[id];
    return current !== undefined && current.system && current.phase === "connecting";
  }

  async function answerPrompt(id: string, values: Record<string, string>) {
    await safeInvoke("answer_vpn_prompt", { profileId: id, values });
  }

  async function turnOffSystem(id: string) {
    await safeInvoke("turn_off_vpn_system", { profileId: id });
  }

  async function stopSystems() {
    await safeInvoke("stop_system_vpns");
  }

  function onComputer(id: string): boolean {
    const current = statuses[id];
    return current !== undefined && current.system && current.phase !== "down";
  }

  const onComputerCount = createMemo(() => Object.values(statuses).filter(current => current.system && current.phase !== "down").length);

  // Shown right away, then saved. A failed save reloads what's on disk.
  async function reorder(ids: string[], groups: string[], moved?: { id: string, group: string | null }) {
    function rank(id: string) {
      const index = ids.indexOf(id);
      return index >= 0 ? index : ids.length;
    }
    setFile("profiles", items => [...items]
      .map(item => (moved && item.id === moved.id ? { ...item, group: moved.group } : item))
      .sort((a, b) => rank(a.id) - rank(b.id)));
    setFile("groupOrder", groups);
    try {
      if (moved) await safeInvoke("move_vpn_profile", moved);
      await safeInvoke("save_vpn_order", { ids, groups });
    } catch (error) {
      await load();
      throw error;
    }
  }

  async function renameGroup(from: string, to: string) {
    await safeInvoke("rename_vpn_group", { from, to });
    await load();
  }

  return {
    file,
    statuses,
    loaded,
    loadError,
    load,
    profile,
    status,
    save,
    importFile,
    setKey,
    clearKey,
    setWireGuardKey,
    generateWireGuardKey,
    remove,
    disconnect,
    turningOn,
    answerPrompt,
    turnOnSystem,
    turnOffSystem,
    stopSystems,
    onComputer,
    onComputerCount,
    reorder,
    renameGroup,
  };
}

const useVpnState = createRoot(useVpnStateInner);
export default useVpnState;
