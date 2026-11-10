import { createEffect, createRoot, createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { withUserCheck } from "@core/helpers/revealSecret";
import { SavedSecret } from "@core/types";
import useLockState from "./lockState";

// What's in the vault, and while the passwords are unlocked, their values. Rust owns how long that lasts.
function useSavedSecretsStateInner() {
  const [secrets, setSecrets] = createStore<SavedSecret[]>([]);
  const [values, setValues] = createStore<Record<string, string>>({});
  const [unlockedUntil, setUnlockedUntil] = createSignal<number | null>(null);
  const [loadError, setLoadError] = createSignal<unknown>(null);
  let expiry: ReturnType<typeof setTimeout> | undefined;

  async function load() {
    try {
      setSecrets(reconcile(await safeInvoke("list_saved_secrets")));
      setLoadError(null);
    } catch (error) {
      setLoadError(error);
    }
  }

  function forget() {
    clearTimeout(expiry);
    setUnlockedUntil(null);
    setValues(reconcile({}));
  }

  function hideValues() {
    setValues(reconcile({}));
  }

  function startTimer(milliseconds: number) {
    clearTimeout(expiry);
    setUnlockedUntil(Date.now() + milliseconds);
    expiry = setTimeout(forget, milliseconds);
  }

  async function fetchValues() {
    const revealed = await safeInvoke("reveal_all_secrets");
    setValues(reconcile(Object.fromEntries(revealed.map(item => [item.id, item.value]))));
  }

  // True when the passwords are unlocked afterwards.
  async function unlock(): Promise<boolean> {
    const milliseconds = await withUserCheck(options => safeInvoke("unlock_secrets", { options }));
    if (milliseconds === null) return false;
    startTimer(milliseconds);
    await fetchValues();
    return true;
  }

  async function lock() {
    forget();
    await safeInvoke("lock_secrets").catch(() => undefined);
  }

  // Coming back to the page while still unlocked shows the values again without asking.
  async function resume() {
    const milliseconds = await safeInvoke("get_secrets_unlock").catch(() => 0);
    if (milliseconds <= 0) {
      forget();
      return;
    }
    startTimer(milliseconds);
    await fetchValues().catch(forget);
  }

  createEffect(() => {
    if (useLockState.locked()) forget();
  });

  return { secrets, values, unlockedUntil, loadError, load, unlock, lock, resume, hideValues };
}

const useSavedSecretsState = createRoot(useSavedSecretsStateInner);
export default useSavedSecretsState;
