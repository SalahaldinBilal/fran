import { createRoot, createSignal, createStore, reconcile, snapshot } from "solid-js";
import { immediateWrite } from "@core/helpers/immediateWrite";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { ConnectionProfile } from "@core/types";

function useConnectionsStateInner() {
  const [connections, writeConnections] = createStore<ConnectionProfile[]>([]);
  const setConnections = immediateWrite(writeConnections);
  const [groupOrder, setGroupOrder] = createSignal<string[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [loadError, setLoadError] = createSignal<unknown>(null);

  async function load() {
    try {
      const file = await safeInvoke("list_connections");
      setConnections(reconcile(file.connections));
      setGroupOrder(file.groupOrder);
      setLoadError(null);
    } catch (error) {
      setLoadError(error);
    } finally {
      setLoaded(true);
    }
  }

  function find(id: string): ConnectionProfile | undefined {
    return connections.find(profile => profile.id === id);
  }

  async function save(profile: ConnectionProfile): Promise<ConnectionProfile> {
    const saved = await safeInvoke("save_connection", { profile });
    const index = connections.findIndex(existing => existing.id === saved.id);
    if (index >= 0) {
      setConnections(reconcile(snapshot(connections).map((item, position) => (position === index ? saved : item))));
    } else {
      setConnections(list => {
        list.push(saved);
      });
    }
    return saved;
  }

  async function duplicate(id: string) {
    await safeInvoke("duplicate_connection", { id });
    await load();
  }

  async function reorder(ids: string[], groups: string[]) {
    function rank(id: string) {
      const index = ids.indexOf(id);
      return index >= 0 ? index : ids.length;
    }
    setConnections(reconcile([...snapshot(connections)].sort((a, b) => rank(a.id) - rank(b.id))));
    setGroupOrder(groups);
    await safeInvoke("save_connection_order", { ids, groups });
  }

  async function renameGroup(from: string, to: string) {
    await safeInvoke("rename_group", { from, to });
    await load();
  }

  async function remove(id: string) {
    await safeInvoke("delete_connection", { id });
    setConnections(list => list.filter(profile => profile.id !== id));
  }

  return { connections, groupOrder, loaded, loadError, load, find, save, duplicate, reorder, renameGroup, remove };
}

const useConnectionsState = createRoot(useConnectionsStateInner);
export default useConnectionsState;
