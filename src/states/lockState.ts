import { createMemo, createRoot } from "solid-js";
import { safeInvoke } from "@core/helpers/safeInvoke";
import useVaultState from "./vaultState";
import useSettingsState from "./settingsState";
import useToastState from "./toastState";

const CHECK_EVERY_MS = 10_000;
const ACTIVITY_EVENTS = ["pointerdown", "pointermove", "keydown", "wheel"] as const;

function useLockStateInner() {
  const vault = useVaultState;
  const enabled = createMemo(() => vault.status()?.lockEnabled ?? false);
  const locked = createMemo(() => vault.status()?.locked ?? false);
  let lastActivity = Date.now();
  let timer: ReturnType<typeof setInterval> | null = null;

  function touch() {
    lastActivity = Date.now();
  }

  function check() {
    const minutes = useSettingsState.settings.lockAfterMinutes;
    if (!enabled() || locked() || minutes <= 0) return;
    if (Date.now() - lastActivity >= minutes * 60_000) void lock();
  }

  // Watches for activity so the lock can come on after the chosen idle time.
  function start() {
    if (timer !== null) return;
    for (const name of ACTIVITY_EVENTS) window.addEventListener(name, touch, { passive: true, capture: true });
    timer = setInterval(check, CHECK_EVERY_MS);
  }

  async function lock() {
    try {
      vault.setStatus(await safeInvoke("lock_app"));
    } catch (error) {
      useToastState.pushError(error);
    }
  }

  // Throws on a wrong password so the lock screen can show it.
  async function unlock(password: string) {
    vault.setStatus(await safeInvoke("unlock_app", { password }));
    touch();
  }

  async function enable(password: string) {
    vault.setStatus(await safeInvoke("enable_app_lock", { password }));
    touch();
  }

  async function disable(password: string) {
    vault.setStatus(await safeInvoke("disable_app_lock", { password }));
  }

  async function changePassword(current: string, next: string) {
    await safeInvoke("change_app_lock_password", { current, next });
  }

  return { enabled, locked, start, lock, unlock, enable, disable, changePassword };
}

const useLockState = createRoot(useLockStateInner);
export default useLockState;
