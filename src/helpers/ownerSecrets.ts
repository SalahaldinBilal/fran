import { createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { PendingSecret, SecretEditor } from "@core/databases/types";
import { SecretOwner, SecretRefs } from "@core/types";
import { safeInvoke } from "./safeInvoke";
import { createSecretRefs } from "./secretRefs";

// A SecretEditor for an identity, key or proxy. Changes are written by `apply` once the owner is saved and has an id.
// `refs` holds which named secrets its fields and password use, saved with the owner itself.
export function createOwnerSecrets() {
  const [stored, setStored] = createSignal<string[]>([]);
  const [owner, setOwner] = createSignal<SecretOwner | null>(null);
  const [pending, setPending] = createStore<Record<string, PendingSecret>>({});
  const refs = createSecretRefs();

  async function reset(next: SecretOwner | null, secretRefs?: SecretRefs) {
    setPending(reconcile({}));
    setStored([]);
    setOwner(next);
    refs.reset(secretRefs);
    if (next) setStored(await safeInvoke("get_owner_secrets", { owner: next }).catch(() => []));
  }

  async function apply(target: SecretOwner) {
    for (const [slot, value] of Object.entries(pending)) {
      if (value === null) await safeInvoke("clear_owner_secret", { owner: target, slot });
      else if (typeof value === "string") await safeInvoke("set_owner_secret", { owner: target, slot, value });
    }
  }

  const editor: SecretEditor = {
    isStored: slot => stored().includes(slot),
    pending: slot => pending[slot],
    setPending: (slot, value) => setPending(slot, value),
    owner,
    refs: refs.editor,
  };

  return { editor, reset, apply, refs };
}
