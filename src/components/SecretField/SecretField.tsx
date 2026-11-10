import styles from "./SecretField.module.scss";
import { Show, createEffect, createMemo, createSignal, onCleanup } from "solid-js";
import useLockState from "@core/states/lockState";
import { Eye, EyeOff, KeyRound, Undo2 } from "lucide-solid";
import Input from "../Input/Input";
import Button from "../Button/Button";
import { SecretEditor } from "@core/databases/types";
import { SHOW_FOR_MS, revealSecret } from "@core/helpers/revealSecret";
import useToastState from "@core/states/toastState";

export type SecretFieldProps = {
  slot: string,
  secrets: SecretEditor,
};

function SecretField(props: SecretFieldProps) {
  const [shown, setShown] = createSignal<string | null>(null);
  const [revealing, setRevealing] = createSignal(false);
  let hideTimer: ReturnType<typeof setTimeout> | undefined;

  const stored = createMemo(() => props.secrets.isStored(props.slot));
  const pending = createMemo(() => props.secrets.pending(props.slot));
  const owner = createMemo(() => props.secrets.owner?.() ?? null);
  const canShow = createMemo(() => stored() && pending() === undefined && owner() !== null);
  const inputType = createMemo(() => (shown() !== null ? "text" : "password"));
  const value = createMemo(() => shown() ?? pending() ?? "");
  const placeholder = createMemo(() => (stored() ? "Saved in vault" : "Asked when connecting"));
  const padding = createMemo(() => (stored() ? "3px" : undefined));
  const iconClass = createMemo(() => (stored() ? styles.StoredIcon : undefined));

  function hide() {
    clearTimeout(hideTimer);
    setShown(null);
  }

  onCleanup(hide);
  createEffect(() => {
    if (useLockState.locked()) hide();
  });

  async function show() {
    const current = owner();
    if (!current) return;
    setRevealing(true);
    try {
      const value = await revealSecret(current, props.slot);
      if (value === null) return;
      setShown(value);
      clearTimeout(hideTimer);
      hideTimer = setTimeout(hide, SHOW_FOR_MS);
    } catch (error) {
      useToastState.pushError(error);
    } finally {
      setRevealing(false);
    }
  }

  return (
    <Show
      when={pending() !== null}
      fallback={
        <div class={styles.Removed}>
          <span>Removed from the vault on save</span>
          <Button size="sm" onClick={() => props.secrets.setPending(props.slot, undefined)}>
            <Undo2 size={14} />
            Undo
          </Button>
        </div>
      }
    >
      <Input
        type={inputType()}
        value={value()}
        onValue={next => {
          hide();
          props.secrets.setPending(props.slot, next === "" ? undefined : next);
        }}
        placeholder={placeholder()}
        before={<KeyRound size={14} class={iconClass()} />}
        style={{ "padding-right": padding() }}
        after={
          <Show when={stored() && pending() === undefined}>
            <span class={styles.Tools}>
              <Show when={canShow()}>
                <Show
                  when={shown() === null}
                  fallback={
                    <Button icon size="sm" tooltip="Hide" onClick={hide}>
                      <EyeOff size={14} />
                    </Button>
                  }
                >
                  <Button icon size="sm" tooltip="Show" disabled={revealing()} onClick={show}>
                    <Eye size={14} />
                  </Button>
                </Show>
              </Show>
              <Button size="sm" variant="danger" onClick={() => props.secrets.setPending(props.slot, null)}>
                Remove
              </Button>
            </span>
          </Show>
        }
      />
    </Show>
  );
}

export default SecretField;
