import styles from "./SecretField.module.scss";
import { Show, createEffect, createMemo, createSignal, onCleanup } from "solid-js";
import useLockState from "@core/states/lockState";
import { Ellipsis, Eye, EyeOff, KeyRound, Link2, Trash2, Undo2 } from "@core/icons";
import { syncMenu } from "@core/helpers/syncTargets";
import { passwordKey } from "@core/states/syncState";
import useContextMenuState, { MenuItem } from "@core/states/contextMenuState";
import Input from "../Input/Input";
import Button from "../Button/Button";
import { SecretChip } from "../SecretInput/SecretInput";
import { SLOT_PREFIX, pickSecret, secretMenuItems } from "@core/helpers/secretRefs";
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

  const refKey = createMemo(() => SLOT_PREFIX + props.slot);
  const secretId = createMemo(() => props.secrets.refs?.get(refKey()));
  const canUseSecret = createMemo(() => props.secrets.refs !== undefined);
  const showsTools = createMemo(() => stored() && pending() === undefined);
  const showsSecretButton = createMemo(() => canUseSecret() && !showsTools());

  // A connection that isn't saved yet has no owner, and nothing to sync.
  const syncKey = createMemo(() => {
    const current = owner();
    return current ? passwordKey(current, props.slot) : null;
  });
  // The slot's own saved value stays in the vault, unused, until the secret is taken off again.
  function pick(id: string) {
    hide();
    props.secrets.setPending(props.slot, undefined);
    props.secrets.refs?.set(refKey(), id);
  }

  function useSecret(event: MouseEvent) {
    pickSecret(event, pick);
  }

  // Everything but Show, so the field keeps one button besides it.
  function openMore(event: MouseEvent & { currentTarget: HTMLButtonElement }) {
    const rect = event.currentTarget.getBoundingClientRect();
    const current = owner();
    const items: MenuItem[] = [];
    if (canUseSecret()) {
      const copyFrom = current ? { owner: current, slot: props.slot } : undefined;
      items.push({ label: "Use a secret instead", icon: Link2, children: secretMenuItems(pick, copyFrom) });
    }
    const key = syncKey();
    if (key) items.push(...syncMenu(key, "This password", "passwords"));
    if (items.length > 0) items.push({ separator: true });
    items.push({ label: "Remove from the vault", icon: Trash2, danger: true, onSelect: () => props.secrets.setPending(props.slot, null) });
    useContextMenuState.openMenuAt({ x: rect.right - 220, y: rect.bottom + 4 }, items);
  }

  return (
    <Show
      when={!secretId()}
      fallback={<SecretChip secretId={secretId() ?? ""} onClear={() => props.secrets.refs?.set(refKey(), null)} />}
    >
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
          after={
            <>
              <Show when={showsSecretButton()}>
                <Button icon size="sm" tooltip="Use a secret" onClick={useSecret}>
                  <Link2 size={13} />
                </Button>
              </Show>
              <Show when={showsTools()}>
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
                  <Button icon size="sm" tooltip="More" onClick={openMore}>
                    <Ellipsis size={15} />
                  </Button>
                </span>
              </Show>
            </>
          }
        />
      </Show>
    </Show>
  );
}

export default SecretField;
