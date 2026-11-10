import { createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { PendingSecret, SecretEditor } from "@core/databases/types";
import { SecretOwner } from "@core/types";
import { safeInvoke } from "./safeInvoke";

// A SecretEditor for an identity, key or proxy. Changes are written by `apply` once the owner is saved and has an id.
export function createOwnerSecrets() {
  const [stored, setStored] = createSignal<string[]>([]);
  const [owner, setOwner] = createSignal<SecretOwner | null>(null);
  const [pending, setPending] = createStore<Record<string, PendingSecret>>({});

  async function reset(next: SecretOwner | null) {
    setPending(reconcile({}));
    setStored([]);
    setOwner(next);
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
  };

  return { editor, reset, apply };
}
