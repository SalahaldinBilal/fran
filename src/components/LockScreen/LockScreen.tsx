import styles from "./LockScreen.module.scss";
import { Show, createMemo, createSignal, onCleanup, onMount } from "solid-js";
import { Portal } from "solid-js/web";
import { Lock } from "lucide-solid";
import useLockState from "@core/states/lockState";
import useVaultState from "@core/states/vaultState";
import useModalState from "@core/states/modalState";
import { errorMessage } from "@core/helpers/errors";
import Button from "../Button/Button";
import Input from "../Input/Input";

function LockScreen() {
  const lock = useLockState;
  const [password, setPassword] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [resetting, setResetting] = createSignal(false);
  const submitLabel = createMemo(() => (busy() ? "Unlocking" : "Unlock"));
  let input: HTMLInputElement | undefined;

  onMount(() => {
    onCleanup(useModalState.track());
    input?.focus();
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!password() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      await lock.unlock(password());
      setPassword("");
    } catch (failure) {
      setError(errorMessage(failure));
      input?.select();
    } finally {
      setBusy(false);
    }
  }

  // Confirmed here rather than in a dialog, since dialogs open under the lock screen.
  async function reset() {
    setBusy(true);
    await useVaultState.reset();
    setBusy(false);
    setResetting(false);
  }

  return (
    <Portal>
      <div class={styles.LockScreen}>
        <form class={styles.Card} onSubmit={submit}>
          <span class={styles.Icon}><Lock size={22} /></span>
          <h1>Fran is locked</h1>
          <Show
            when={!resetting()}
            fallback={
              <>
                <p class={styles.Warning}>
                  Without the password the vault can't be opened. Resetting deletes every saved password, passphrase and key in it, the
                  agent history, terminal logs and the app lock. Connections and hosts stay, and you'll be asked for their passwords again.
                </p>
                <div class={styles.Choices}>
                  <Button variant="ghost" onClick={() => setResetting(false)}>Cancel</Button>
                  <Button variant="danger" disabled={busy()} onClick={() => void reset()}>Reset vault</Button>
                </div>
              </>
            }
          >
            <p>Terminals, sessions and port forwards are still running.</p>
            <Input
              type="password"
              value={password()}
              onValue={setPassword}
              placeholder="Password"
              class={styles.Input}
              inputRef={element => { input = element; }}
            />
            <Show when={error()}>
              {message => <span class={styles.Error}>{message()}</span>}
            </Show>
            <Button type="submit" variant="primary" disabled={busy() || !password()} class={styles.Submit}>
              {submitLabel()}
            </Button>
            <button type="button" class={styles.Forgot} onClick={() => setResetting(true)}>Forgot the password?</button>
          </Show>
        </form>
      </div>
    </Portal>
  );
}

export default LockScreen;
