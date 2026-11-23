import { createRoot, createSignal, createStore, reconcile, snapshot } from "solid-js";
import { immediateWrite } from "@core/helpers/immediateWrite";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { SavedQuery } from "@core/types";

function useSavedQueriesStateInner() {
  const [queries, writeQueries] = createStore<SavedQuery[]>([]);
  const setQueries = immediateWrite(writeQueries);
  const [loaded, setLoaded] = createSignal(false);
  const [loadError, setLoadError] = createSignal<unknown>(null);

  async function load() {
    try {
      setQueries(reconcile(await safeInvoke("list_saved_queries")));
      setLoadError(null);
    } catch (error) {
      setLoadError(error);
    } finally {
      setLoaded(true);
    }
  }

  function find(id: string): SavedQuery | undefined {
    return queries.find(query => query.id === id);
  }

  async function save(query: SavedQuery): Promise<SavedQuery> {
    const saved = await safeInvoke("save_query", { query });
    const index = queries.findIndex(existing => existing.id === saved.id);
    if (index >= 0) {
      setQueries(reconcile(snapshot(queries).map((item, position) => (position === index ? saved : item))));
    } else {
      setQueries(list => {
        list.push(saved);
      });
    }
    return saved;
  }

  async function rename(id: string, name: string) {
    const existing = find(id);
    if (existing) await save({ ...existing, name });
  }

  async function remove(id: string) {
    await safeInvoke("delete_saved_query", { id });
    setQueries(list => list.filter(query => query.id !== id));
  }

  return { queries, loaded, loadError, load, find, save, rename, remove };
}

const useSavedQueriesState = createRoot(useSavedQueriesStateInner);
export default useSavedQueriesState;
