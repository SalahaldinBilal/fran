import styles from "./SecretEditor.module.scss";
import { For, Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { cloudModule } from "@core/clouds";
import useSecretsState from "@core/states/secretsState";
import useSyncState from "@core/states/syncState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage } from "@core/helpers/errors";
import { plural } from "@core/helpers";
import Modal from "../Modal/Modal";
import Button from "../Button/Button";
import Switch from "../Switch/Switch";
import Note from "../Note/Note";

type Choice = { name: string, taken: string | null };

function LinkSecretsModal() {
  const secrets = useSecretsState;
  const { pushError, pushToast } = useToastState;
  const [names, setNames] = createSignal<string[] | null>(null);
  const [loadError, setLoadError] = createSignal<unknown>(null);
  const [picked, setPicked] = createSignal<ReadonlySet<string>>(new Set());
  const [saving, setSaving] = createSignal(false);

  const cloud = createMemo(() => {
    const identity = secrets.linkRequest();
    return identity ? useSyncState.cloudByIdentity(identity) ?? null : null;
  });
  const store = createMemo(() => {
    const current = cloud();
    return current ? cloudModule(current.kind).secretStore ?? null : null;
  });
  const title = createMemo(() => `Link secrets from ${cloud()?.name ?? "a cloud"}`);
  const choices = createMemo<Choice[]>(() => (names() ?? []).map(name => ({ name, taken: takenBy(name) })));
  const free = createMemo(() => choices().filter(choice => choice.taken === null));
  const saveLabel = createMemo(() => (saving() ? "Linking" : picked().size > 0 ? `Link ${plural(picked().size, "secret")}` : "Link"));

  // A name already linked to this cloud, or already used by a secret in Fran, can't be linked again.
  function takenBy(name: string): string | null {
    const identity = secrets.linkRequest();
    if (secrets.secrets.some(secret => secret.link?.cloud === identity && secret.link.name === name)) return "Linked";
    if (secrets.secrets.some(secret => secret.name.toLowerCase() === name.toLowerCase())) return "Name in use";
    return null;
  }

  createEffect(on(secrets.linkRequest, identity => {
    setNames(null);
    setLoadError(null);
    setPicked(new Set<string>());
    const current = cloud();
    const found = store();
    if (!identity || !current || !found) return;
    found.names(current).then(list => {
      if (secrets.linkRequest() === identity) setNames(list);
    }, error => {
      if (secrets.linkRequest() === identity) setLoadError(error);
    });
  }));

  function toggle(name: string, checked: boolean) {
    const next = new Set(picked());
    if (checked) next.add(name);
    else next.delete(name);
    setPicked(next);
  }

  function pickAll() {
    setPicked(new Set(free().map(choice => choice.name)));
  }

  async function link() {
    const [current, found, identity] = [cloud(), store(), secrets.linkRequest()];
    if (!current || !found || !identity) return;
    const first = !secrets.secrets.some(secret => secret.link?.cloud === identity);
    if (first) {
      const confirmed = await usePromptState.confirm({ title: `Keep secrets in ${current.name}?`, message: found.notice, confirmLabel: "Link them" });
      if (!confirmed) return;
    }
    setSaving(true);
    const failed: string[] = [];
    for (const name of picked()) {
      try {
        await safeInvoke("save_secret", { secret: { id: "", name, note: "", link: { cloud: identity, name } }, value: null });
      } catch (error) {
        failed.push(`${name}: ${errorMessage(error)}`);
      }
    }
    await secrets.load();
    setSaving(false);
    const linked = picked().size - failed.length;
    if (linked > 0) pushToast(`Linked ${plural(linked, "secret")}. Their values arrive with the next sync.`, "success", 3000);
    if (failed.length > 0) pushError(new Error(`Not linked: ${failed.join(", ")}`));
    if (failed.length === 0) secrets.closeLink();
    void useSyncState.syncNow(current.id);
  }

  return (
    <Modal
      show={secrets.linkRequest() !== null}
      onHide={secrets.closeLink}
      title={title()}
      width={460}
      footer={
        <>
          <Button variant="ghost" onClick={pickAll} disabled={free().length === 0}>Pick all</Button>
          <div class={styles.Spacer} />
          <Button variant="subtle" onClick={secrets.closeLink}>Cancel</Button>
          <Button variant="primary" onClick={() => void link()} disabled={saving() || picked().size === 0}>{saveLabel()}</Button>
        </>
      }
    >
      <div class={styles.Form}>
        <Show when={loadError()}>
          <Note tone="warning">The names couldn't be read. {errorMessage(loadError())}</Note>
        </Show>
        <Show when={!loadError()}>
          <Show when={names() !== null} fallback={<div class={styles.Waiting}>Reading the names</div>}>
            <Show when={choices().length > 0} fallback={<div class={styles.Waiting}>{cloud()?.name} has no secrets yet</div>}>
              <div class={styles.Names}>
                <For each={choices()}>
                  {choice => (
                    <div class={styles.NameRow}>
                      <Switch
                        checked={picked().has(choice.name)}
                        disabled={choice.taken !== null}
                        onChange={checked => toggle(choice.name, checked)}
                        label={choice.name}
                      />
                      <Show when={choice.taken}>{taken => <span class={styles.Taken}>{taken()}</span>}</Show>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </Show>
        </Show>
        <Note>Each name becomes a secret with the same name in Fran. Only the names picked here are ever read.</Note>
      </div>
    </Modal>
  );
}

export default LinkSecretsModal;
