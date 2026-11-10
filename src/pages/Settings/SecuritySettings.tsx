import styles from "./Settings.module.scss";
import { Match, Show, Switch as Branch, createMemo, createSignal } from "solid-js";
import { Lock } from "lucide-solid";
import useSettingsState, { LOCK_AFTER_MINUTES } from "@core/states/settingsState";
import useLockState from "@core/states/lockState";
import useVaultState from "@core/states/vaultState";
import useToastState from "@core/states/toastState";
import { errorMessage } from "@core/helpers/errors";
import Button from "@core/components/Button/Button";
import Input from "@core/components/Input/Input";
import Select, { SelectItem } from "@core/components/Select/Select";
import Switch from "@core/components/Switch/Switch";
import { SettingGroup, SettingRow, SettingsPage } from "./SettingsLayout";

const MIN_LENGTH = 8;

const LOCK_ITEMS: SelectItem<number>[] = LOCK_AFTER_MINUTES.map(minutes => ({
  value: minutes,
  label: minutes === 0 ? "Only when Fran starts" : `After ${minutes} minutes idle`,
}));

type Form = "none" | "enable" | "change" | "disable";

function SecuritySettings() {
  const { settings, update } = useSettingsState;
  const lock = useLockState;
  const vault = useVaultState;
  const [form, setForm] = createSignal<Form>("none");
  const [current, setCurrent] = createSignal("");
  const [next, setNext] = createSignal("");
  const [repeat, setRepeat] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const vaultUsable = createMemo(() => vault.status()?.available ?? false);
  const nextProblem = createMemo(() => {
    if (next().length > 0 && [...next()].length < MIN_LENGTH) return `Use at least ${MIN_LENGTH} characters`;
    if (repeat().length > 0 && repeat() !== next()) return "The two passwords don't match";
    return null;
  });
  const nextReady = createMemo(() => [...next()].length >= MIN_LENGTH && next() === repeat());
  const formMessage = createMemo(() => error() ?? (form() !== "disable" ? nextProblem() : null));
  const submitVariant = createMemo(() => (form() === "disable" ? "danger" : "primary"));
  const submitLabel = createMemo(() => {
    if (busy()) return "Working";
    switch (form()) {
      case "enable": return "Turn on";
      case "change": return "Change password";
      default: return "Turn off";
    }
  });

  function open(which: Form) {
    setForm(which);
    setCurrent("");
    setNext("");
    setRepeat("");
    setError(null);
  }

  async function run(action: () => Promise<void>, done: string) {
    setBusy(true);
    setError(null);
    try {
      await action();
      open("none");
      useToastState.pushToast(done, "info");
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    switch (form()) {
      case "enable":
        if (nextReady()) void run(() => lock.enable(next()), "App lock is on");
        break;
      case "change":
        if (nextReady() && current()) void run(() => lock.changePassword(current(), next()), "Lock password changed");
        break;
      case "disable":
        if (current()) void run(() => lock.disable(current()), "App lock is off");
        break;
    }
  }

  function PasswordField(props: { label: string, value: string, onValue: (value: string) => void, autofocus?: boolean }) {
    return (
      <label class={styles.FormField}>
        <span>{props.label}</span>
        <Input type="password" value={props.value} onValue={props.onValue} autofocus={props.autofocus} />
      </label>
    );
  }

  return (
    <SettingsPage title="Security" description="Lock Fran with a password of its own, on top of the OS keychain.">
      <SettingGroup title="App lock">
        <SettingRow
          name="Lock with a password"
          hint="Saved passwords and keys can only be read after you type it. While locked, terminals, sessions and forwards keep running."
        >
          <Switch
            checked={lock.enabled()}
            disabled={!vaultUsable() || busy()}
            onChange={on => open(on ? "enable" : "disable")}
          />
        </SettingRow>
        <Show when={lock.enabled()}>
          <SettingRow name="Lock" hint="Activity anywhere in the window resets the timer.">
            <Select value={settings.lockAfterMinutes} items={LOCK_ITEMS} onChange={lockAfterMinutes => void update({ lockAfterMinutes })} />
          </SettingRow>
          <SettingRow name="Password">
            <div class={styles.RowButtons}>
              <Button variant="subtle" onClick={() => open("change")}>Change</Button>
              <Button variant="subtle" onClick={() => void lock.lock()}>
                <Lock size={13} />
                Lock now
              </Button>
            </div>
          </SettingRow>
        </Show>
      </SettingGroup>

      <Show when={form() !== "none"}>
        <form class={styles.InlineForm} onSubmit={submit}>
          <Branch>
            <Match when={form() === "enable"}>
              <p class={styles.FormLead}>
                Pick a password. If you forget it, the only way back in is to reset the vault, which deletes every saved password and key.
              </p>
              <PasswordField label="Password" value={next()} onValue={setNext} autofocus />
              <PasswordField label="Again" value={repeat()} onValue={setRepeat} />
            </Match>
            <Match when={form() === "change"}>
              <PasswordField label="Current password" value={current()} onValue={setCurrent} autofocus />
              <PasswordField label="New password" value={next()} onValue={setNext} />
              <PasswordField label="Again" value={repeat()} onValue={setRepeat} />
            </Match>
            <Match when={form() === "disable"}>
              <p class={styles.FormLead}>The vault key goes back into the OS keychain, so Fran opens without a password.</p>
              <PasswordField label="Current password" value={current()} onValue={setCurrent} autofocus />
            </Match>
          </Branch>
          <Show when={formMessage()}>
            {message => <p class={styles.FormError}>{message()}</p>}
          </Show>
          <div class={styles.FormActions}>
            <Button variant="ghost" onClick={() => open("none")}>Cancel</Button>
            <Button type="submit" variant={submitVariant()} disabled={busy()}>{submitLabel()}</Button>
          </div>
          <p class={styles.FormHint}>Checking the password takes about a second, on purpose. It makes guessing slow.</p>
        </form>
      </Show>

      <Show when={!vaultUsable() && !lock.enabled()}>
        <p class={styles.FormError}>The vault isn't available, so the app lock can't be turned on. {vault.status()?.message}</p>
      </Show>
    </SettingsPage>
  );
}

export default SecuritySettings;
