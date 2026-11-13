import { createRoot, createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { NamedSecret, SecretInfo } from "@core/types";

// `onSaved` lets a field that opened the editor for a new secret start using it.
type SecretEditorRequest = { secret: SecretInfo | null, onSaved?: (secret: NamedSecret) => void };

// Named secrets, without their values. Those only leave the vault through the Show and Copy checks.
function useSecretsStateInner() {
  const [secrets, setSecrets] = createStore<SecretInfo[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [loadError, setLoadError] = createSignal<unknown>(null);
  const [editorRequest, setEditorRequest] = createSignal<SecretEditorRequest | null>(null);

  async function load() {
    try {
      setSecrets(reconcile(await safeInvoke("list_secrets")));
      setLoadError(null);
    } catch (error) {
      setLoadError(error);
    } finally {
      setLoaded(true);
    }
  }

  function find(id: string | null | undefined): SecretInfo | undefined {
    return id ? secrets.find(secret => secret.id === id) : undefined;
  }

  async function save(next: NamedSecret, value: string | null): Promise<NamedSecret> {
    const saved = await safeInvoke("save_secret", { secret: next, value });
    await load();
    return saved;
  }

  async function remove(id: string) {
    await safeInvoke("delete_secret", { id });
    setSecrets(items => items.filter(item => item.id !== id));
  }

  return {
    secrets,
    loaded,
    loadError,
    load,
    find,
    save,
    remove,
    editorRequest,
    openEditor: (secret: SecretInfo | null, onSaved?: (secret: NamedSecret) => void) => setEditorRequest({ secret, onSaved }),
    closeEditor: () => setEditorRequest(null),
  };
}

const useSecretsState = createRoot(useSecretsStateInner);
export default useSecretsState;
