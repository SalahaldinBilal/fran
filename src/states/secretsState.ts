import { createRoot, createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { NamedSecret, SecretInfo, SecretOwner } from "@core/types";

// A saved password a new secret takes its value from. Rust copies it, the value never comes here.
export type CopyFrom = { owner: SecretOwner, slot: string };

// `onSaved` lets a field that opened the editor for a new secret start using it.
type SecretEditorRequest = { secret: SecretInfo | null, onSaved?: (secret: NamedSecret) => void, copyFrom?: CopyFrom };

// Named secrets, without their values. Those only leave the vault through the Show and Copy checks.
function useSecretsStateInner() {
  const [secrets, setSecrets] = createStore<SecretInfo[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [loadError, setLoadError] = createSignal<unknown>(null);
  const [editorRequest, setEditorRequest] = createSignal<SecretEditorRequest | null>(null);
  // The identity of the cloud whose names are being linked.
  const [linkRequest, setLinkRequest] = createSignal<string | null>(null);

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

  async function save(next: NamedSecret, value: string | null, copyFrom?: CopyFrom): Promise<NamedSecret> {
    const saved = await safeInvoke("save_secret", { secret: next, value: copyFrom ? null : value, copyFrom });
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
    openEditor: (secret: SecretInfo | null, onSaved?: (secret: NamedSecret) => void, copyFrom?: CopyFrom) => setEditorRequest({ secret, onSaved, copyFrom }),
    closeEditor: () => setEditorRequest(null),
    linkRequest,
    openLink: (identity: string) => setLinkRequest(identity),
    closeLink: () => setLinkRequest(null),
  };
}

const useSecretsState = createRoot(useSecretsStateInner);
export default useSecretsState;
