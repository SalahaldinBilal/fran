import { createRoot, createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { Snippet } from "@core/types";

type SnippetEditorRequest = { snippet: Snippet | null };

function useSnippetsStateInner() {
  const [snippets, setSnippets] = createStore<Snippet[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [loadError, setLoadError] = createSignal<unknown>(null);
  const [editorRequest, setEditorRequest] = createSignal<SnippetEditorRequest | null>(null);

  async function load() {
    try {
      setSnippets(reconcile(await safeInvoke("list_snippets")));
      setLoadError(null);
    } catch (error) {
      setLoadError(error);
    } finally {
      setLoaded(true);
    }
  }

  function find(id: string | null): Snippet | undefined {
    return id ? snippets.find(snippet => snippet.id === id) : undefined;
  }

  async function save(next: Snippet): Promise<Snippet> {
    const saved = await safeInvoke("save_snippet", { snippet: next });
    setSnippets(items => (items.some(item => item.id === saved.id) ? items.map(item => (item.id === saved.id ? saved : item)) : [...items, saved]));
    return saved;
  }

  async function remove(id: string) {
    await safeInvoke("delete_snippet", { id });
    setSnippets(items => items.filter(item => item.id !== id));
  }

  return {
    snippets,
    loaded,
    loadError,
    load,
    find,
    save,
    remove,
    editorRequest,
    openEditor: (snippet: Snippet | null) => setEditorRequest({ snippet }),
    closeEditor: () => setEditorRequest(null),
  };
}

const useSnippetsState = createRoot(useSnippetsStateInner);
export default useSnippetsState;
