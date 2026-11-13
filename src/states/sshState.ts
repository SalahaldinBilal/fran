import { createRoot, createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { shownField } from "@core/helpers/secretRefs";
import { ForwardRule, HostKeyInfo, Identity, KeyMeta, Proxy, SshFile, SshHost } from "@core/types";

const EMPTY: SshFile = { version: 1, hosts: [], identities: [], keys: [], proxies: [], forwards: [], groupOrder: [] };

function useSshStateInner() {
  const [file, setFile] = createStore<SshFile>(structuredClone(EMPTY));
  const [knownHosts, setKnownHosts] = createStore<HostKeyInfo[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [loadError, setLoadError] = createSignal<unknown>(null);

  async function load() {
    try {
      setFile(reconcile(await safeInvoke("list_ssh")));
      setLoadError(null);
    } catch (error) {
      setLoadError(error);
    } finally {
      setLoaded(true);
    }
  }

  async function loadKnownHosts() {
    setKnownHosts(reconcile(await safeInvoke("list_known_hosts")));
  }

  function host(id: string): SshHost | undefined {
    return file.hosts.find(candidate => candidate.id === id);
  }

  function identity(id: string | null): Identity | undefined {
    return id ? file.identities.find(candidate => candidate.id === id) : undefined;
  }

  function key(id: string): KeyMeta | undefined {
    return file.keys.find(candidate => candidate.id === id);
  }

  function proxy(id: string | null): Proxy | undefined {
    return id ? file.proxies.find(candidate => candidate.id === id) : undefined;
  }

  // Mirrors the backend: the first jump host is reached through its own route.
  function route(hostId: string, seen: string[] = []): SshHost[] {
    const target = host(hostId);
    if (!target || seen.includes(hostId) || seen.length > 8) return [];
    const [first, ...rest] = target.jumps;
    const before = first ? route(first, [...seen, hostId]) : [];
    const later = rest.map(host).filter((jump): jump is SshHost => jump !== undefined);
    return [...before, ...later, target];
  }

  function routeProxy(hostId: string, seen: string[] = []): Proxy | undefined {
    const target = host(hostId);
    if (!target || seen.includes(hostId)) return undefined;
    return proxy(target.proxyId) ?? (target.jumps[0] ? routeProxy(target.jumps[0], [...seen, hostId]) : undefined);
  }

  // Mirrors the backend: the host's own VPN, else its first jump's.
  function routeVpnId(hostId: string, seen: string[] = []): string | null {
    const target = host(hostId);
    if (!target || seen.includes(hostId)) return null;
    return target.vpnId ?? (target.jumps[0] ? routeVpnId(target.jumps[0], [...seen, hostId]) : null);
  }

  function address(target: SshHost): string {
    const login = identity(target.identityId);
    const user = login ? shownField(login.secretRefs, "user", login.user) : "?";
    const port = shownField(target.secretRefs, "port", target.port);
    return `${user}@${shownField(target.secretRefs, "host", target.host)}${port !== "22" ? `:${port}` : ""}`;
  }

  function upsert<T extends { id: string }>(items: T[], saved: T): T[] {
    return items.some(item => item.id === saved.id) ? items.map(item => (item.id === saved.id ? saved : item)) : [...items, saved];
  }

  async function saveHost(next: SshHost): Promise<SshHost> {
    const saved = await safeInvoke("save_ssh_host", { host: next });
    setFile("hosts", items => upsert(items, saved));
    return saved;
  }

  async function deleteHost(id: string) {
    await safeInvoke("delete_ssh_host", { id });
    setFile("hosts", hosts => hosts.filter(item => item.id !== id));
  }

  // Shown right away, then saved. A failed save reloads what's on disk.
  async function reorderHosts(ids: string[], groups: string[], moved?: { id: string, group: string | null }) {
    function rank(id: string) {
      const index = ids.indexOf(id);
      return index >= 0 ? index : ids.length;
    }
    setFile("hosts", hosts => [...hosts]
      .map(item => (moved && item.id === moved.id ? { ...item, group: moved.group } : item))
      .sort((a, b) => rank(a.id) - rank(b.id)));
    setFile("groupOrder", groups);
    try {
      if (moved) await safeInvoke("move_ssh_host", moved);
      await safeInvoke("save_ssh_host_order", { ids, groups });
    } catch (error) {
      await load();
      throw error;
    }
  }

  async function renameGroup(from: string, to: string) {
    await safeInvoke("rename_ssh_group", { from, to });
    await load();
  }

  async function saveIdentity(next: Identity): Promise<Identity> {
    const saved = await safeInvoke("save_identity", { identity: next });
    setFile("identities", items => upsert(items, saved));
    return saved;
  }

  async function deleteIdentity(id: string) {
    await safeInvoke("delete_identity", { id });
    setFile("identities", items => items.filter(item => item.id !== id));
  }

  async function saveProxy(next: Proxy): Promise<Proxy> {
    const saved = await safeInvoke("save_proxy", { proxy: next });
    setFile("proxies", items => upsert(items, saved));
    return saved;
  }

  async function deleteProxy(id: string) {
    await safeInvoke("delete_proxy", { id });
    setFile("proxies", items => items.filter(item => item.id !== id));
  }

  function addKey(saved: KeyMeta) {
    setFile("keys", items => upsert(items, saved));
  }

  async function renameKey(id: string, label: string) {
    addKey(await safeInvoke("rename_key", { id, label }));
  }

  async function deleteKey(id: string) {
    await safeInvoke("delete_key", { id });
    setFile("keys", items => items.filter(item => item.id !== id));
  }

  function forward(id: string): ForwardRule | undefined {
    return file.forwards.find(candidate => candidate.id === id);
  }

  async function saveForward(next: ForwardRule): Promise<ForwardRule> {
    const saved = await safeInvoke("save_forward_rule", { rule: next });
    setFile("forwards", items => upsert(items, saved));
    return saved;
  }

  async function deleteForward(id: string) {
    await safeInvoke("delete_forward_rule", { id });
    setFile("forwards", items => items.filter(item => item.id !== id));
  }

  async function forgetKnownHost(target: HostKeyInfo) {
    await safeInvoke("forget_known_host", { host: target.host, port: target.port });
    setKnownHosts(items => items.filter(item => !(item.host === target.host && item.port === target.port)));
  }

  return {
    file,
    knownHosts,
    loaded,
    loadError,
    load,
    loadKnownHosts,
    host,
    identity,
    key,
    proxy,
    route,
    routeProxy,
    routeVpnId,
    address,
    saveHost,
    deleteHost,
    reorderHosts,
    renameGroup,
    saveIdentity,
    deleteIdentity,
    saveProxy,
    deleteProxy,
    addKey,
    renameKey,
    deleteKey,
    forward,
    saveForward,
    deleteForward,
    forgetKnownHost,
  };
}

const useSshState = createRoot(useSshStateInner);
export default useSshState;
