import { createStore, produce, reconcile, unwrap } from "solid-js/store";
import { KeyRound, Plus } from "@core/icons";
import { SecretRefs } from "@core/types";
import useContextMenuState, { MenuItem } from "@core/states/contextMenuState";
import useSecretsState from "@core/states/secretsState";

export const SLOT_PREFIX = "slot:";

// Which named secret fills each field and password slot of the item being edited. Null clears one.
export type SecretRefsEditor = {
  get: (key: string) => string | undefined,
  set: (key: string, secretId: string | null) => void,
};

// For editors that keep their fields in signals instead of a draft store.
export function createSecretRefs() {
  const [refs, setRefs] = createStore<SecretRefs>({});

  const editor: SecretRefsEditor = {
    get: key => refs[key],
    set: (key, secretId) => setRefs(produce(draft => {
      if (secretId) draft[key] = secretId;
      else delete draft[key];
    })),
  };

  function reset(next: SecretRefs | undefined) {
    setRefs(reconcile({ ...(next ?? {}) }));
  }

  // Only the keys in `keep` are saved, so a field that was hidden since doesn't keep its secret.
  function snapshot(keep?: (key: string) => boolean): SecretRefs {
    const all = { ...unwrap(refs) };
    for (const key of Object.keys(all)) {
      if (keep && !keep(key)) delete all[key];
    }
    return all;
  }

  return { editor, reset, snapshot };
}

// The same refs seen from a nested part of the item, like a connection's `ssh` options.
export function scopedRefs(refs: SecretRefsEditor | undefined, prefix: string): SecretRefsEditor | undefined {
  if (!refs) return undefined;
  return {
    get: key => refs.get(key.startsWith(SLOT_PREFIX) ? key : prefix + key),
    set: (key, secretId) => refs.set(key.startsWith(SLOT_PREFIX) ? key : prefix + key, secretId),
  };
}

// What a list shows for a field: its value, or the name of the secret that fills it.
export function shownField(refs: SecretRefs | undefined, path: string, value: string | number): string {
  const secretId = refs?.[path];
  if (!secretId) return String(value);
  return useSecretsState.find(secretId)?.name ?? "deleted secret";
}

// A copy of an item for labels: text fields a secret fills read as the secret's name instead of empty.
export function withSecretNames<T extends { secretRefs?: SecretRefs }>(item: T): T {
  const refs = item.secretRefs;
  if (!refs || Object.keys(refs).length === 0) return item;
  const copy = JSON.parse(JSON.stringify(item));
  for (const [path, secretId] of Object.entries(refs)) {
    if (path.startsWith(SLOT_PREFIX)) continue;
    const parts = path.split(".");
    const last = parts.pop() ?? "";
    const parent = parts.reduce((value, part) => value?.[part], copy);
    if (parent && typeof parent[last] === "string") parent[last] = useSecretsState.find(secretId)?.name ?? "deleted secret";
  }
  return copy;
}

// A menu of the named secrets under the button that was clicked, with a way to make a new one.
export function pickSecret(event: MouseEvent, onPick: (secretId: string) => void) {
  const secrets = useSecretsState;
  const items: MenuItem[] = secrets.secrets.map(secret => ({
    label: secret.name,
    icon: KeyRound,
    onSelect: () => onPick(secret.id),
  }));
  if (items.length > 0) items.push({ separator: true });
  items.push({ label: "New secret…", icon: Plus, onSelect: () => secrets.openEditor(null, saved => onPick(saved.id)) });
  useContextMenuState.openContextMenu(event, items);
}
