import styles from "./Sftp.module.scss";
import { For, Match, Show, Switch, createEffect, createMemo, createSignal } from "solid-js";
import { CircleAlert } from "lucide-solid";
import useSftpState from "@core/states/sftpState";
import Modal from "@core/components/Modal/Modal";
import Button from "@core/components/Button/Button";
import Input from "@core/components/Input/Input";
import CodeView from "@core/components/CodeView/CodeView";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Spinner from "@core/components/Spinner/Spinner";
import { octal } from "./format";

export function PreviewModal(props: { tabId: string }) {
  const sftp = useSftpState;
  const preview = createMemo(() => sftp.tab(props.tabId)?.preview ?? null);

  return (
    <Modal
      show={preview() !== null}
      onHide={() => sftp.closePreview(props.tabId)}
      title={preview()?.name}
      subtitle={<span class={styles.ModalPath}>{preview()?.path}</span>}
      width={860}
    >
      <div class={styles.PreviewBody}>
        <Switch>
          <Match when={preview()?.error}>
            {error => (
              <div class={styles.Center}>
                <EmptyState tone="danger" icon={CircleAlert} title="This file can't be shown" description={error()} />
              </div>
            )}
          </Match>
          <Match when={preview()?.text !== null && preview()?.text !== undefined}>
            <CodeView value={preview()?.text ?? ""} language="text" readOnly />
          </Match>
          <Match when={true}>
            <div class={styles.Center}><Spinner size={18} /></div>
          </Match>
        </Switch>
      </div>
      <p class={styles.ModalHint}>Read only. Files up to 1 MiB can be previewed.</p>
    </Modal>
  );
}

const WHO = [
  { label: "Owner", shift: 6 },
  { label: "Group", shift: 3 },
  { label: "Others", shift: 0 },
];

const BITS = [
  { label: "Read", letter: "r", bit: 0o4 },
  { label: "Write", letter: "w", bit: 0o2 },
  { label: "Run", letter: "x", bit: 0o1 },
];

export function PermissionsModal(props: { tabId: string }) {
  const sftp = useSftpState;
  const target = createMemo(() => sftp.tab(props.tabId)?.permissions ?? null);
  const [mode, setMode] = createSignal(0);
  const [typed, setTyped] = createSignal("");
  const [saving, setSaving] = createSignal(false);

  createEffect(() => {
    const current = target();
    if (!current) return;
    setMode(current.mode);
    setTyped(octal(current.mode));
  });

  const special = createMemo(() => (mode() & 0o7000) !== 0);
  const typedValid = createMemo(() => /^[0-7]{3,4}$/.test(typed()));

  function toggle(shift: number, bit: number) {
    const next = mode() ^ (bit << shift);
    setMode(next);
    setTyped(octal(next));
  }

  function onTyped(value: string) {
    setTyped(value);
    if (/^[0-7]{3,4}$/.test(value)) setMode(parseInt(value, 8));
  }

  async function apply() {
    if (!typedValid()) return;
    setSaving(true);
    await sftp.savePermissions(props.tabId, mode());
    setSaving(false);
  }

  return (
    <Modal
      show={target() !== null}
      onHide={() => sftp.closePermissions(props.tabId)}
      title={`Permissions of ${target()?.name ?? ""}`}
      subtitle={<span class={styles.ModalPath}>{target()?.path}</span>}
      width={420}
      footer={
        <>
          <Button variant="ghost" onClick={() => sftp.closePermissions(props.tabId)}>Cancel</Button>
          <Button variant="primary" disabled={!typedValid() || saving()} onClick={() => void apply()}>Apply</Button>
        </>
      }
    >
      <div class={styles.PermGrid}>
        <span />
        <For each={BITS}>{bit => <span class={styles.PermHead}>{bit.label}</span>}</For>
        <For each={WHO}>
          {who => (
            <>
              <span class={styles.PermWho}>{who.label}</span>
              <For each={BITS}>
                {bit => {
                  const on = createMemo(() => (mode() & (bit.bit << who.shift)) !== 0);
                  return (
                    <Button size="sm" variant="subtle" active={on()} class={styles.PermBit} onClick={() => toggle(who.shift, bit.bit)}>
                      {bit.letter}
                    </Button>
                  );
                }}
              </For>
            </>
          )}
        </For>
      </div>
      <div class={styles.PermOctal}>
        <span>As a number</span>
        <Input value={typed()} onValue={onTyped} mono class={styles.PermInput} />
      </div>
      <Show when={special()}>
        <p class={styles.ModalHint}>This includes setuid, setgid or sticky bits. They're kept as typed.</p>
      </Show>
    </Modal>
  );
}
