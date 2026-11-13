import styles from "./SecretEditor.module.scss";
import { Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { Eye, EyeOff, Trash2 } from "@core/icons";
import { cloudModule } from "@core/clouds";
import useSecretsState from "@core/states/secretsState";
import useSyncState from "@core/states/syncState";
import useSettingsState from "@core/states/settingsState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import useContextMenuState from "@core/states/contextMenuState";
import { Cloud, SecretInfo, SecretLink } from "@core/types";
import Modal from "../Modal/Modal";
import Button from "../Button/Button";
import Field from "../Field/Field";
import Input from "../Input/Input";
import Note from "../Note/Note";
import Select, { SelectItem } from "../Select/Select";

const THIS_COMPUTER = "";

export function usedByText(secret: SecretInfo): string {
  const names = [...new Set(secret.usedBy.map(used => used.label))];
  return names.length > 0 ? names.join(", ") : "Nothing";
}

// The cloud a secret's value is linked to, when this computer has it and its kind can hold secrets by name.
function linkedCloud(link: SecretLink | null | undefined): Cloud | null {
  const cloud = link ? useSyncState.cloudByIdentity(link.cloud) : undefined;
  return cloud && cloudModule(cloud.kind).secretStore ? cloud : null;
}

// Deleting in Fran only drops the link. The secret in the cloud goes only when the user turns that on in the confirm.
export async function deleteSecret(secret: SecretInfo): Promise<boolean> {
  const cloud = linkedCloud(secret.link);
  const answer = await usePromptState.confirmWithOption({
    title: `Delete ${secret.name}?`,
    message: secret.usedBy.length > 0
      ? `It's used by ${usedByText(secret)}. They stop connecting until you pick another secret or type a value in their settings.`
      : "Its value is removed from the vault.",
    confirmLabel: "Delete",
    danger: true,
    option: cloud && secret.link ? `Also delete ${secret.link.name} in ${cloud.name}` : "",
  });
  if (!answer) return false;
  await useSecretsState.remove(secret.id);
  if (answer.option && cloud && secret.link) await cloudModule(cloud.kind).secretStore?.deleteLinked(cloud, secret.link.name);
  return true;
}

function SecretEditor() {
  const secrets = useSecretsState;
  const sync = useSyncState;
  const { pushError, pushToast } = useToastState;
  const [name, setName] = createSignal("");
  const [value, setValue] = createSignal("");
  const [note, setNote] = createSignal("");
  const [storedIn, setStoredIn] = createSignal(THIS_COMPUTER);
  const [linkName, setLinkName] = createSignal("");
  const [linkTouched, setLinkTouched] = createSignal(false);
  const [visible, setVisible] = createSignal(false);
  const [saving, setSaving] = createSignal(false);

  const editing = createMemo(() => secrets.editorRequest()?.secret ?? null);
  const copyFrom = createMemo(() => secrets.editorRequest()?.copyFrom ?? null);
  const title = createMemo(() => (editing() ? `Edit ${editing()?.name}` : copyFrom() ? "Make it a secret" : "New secret"));
  const saveLabel = createMemo(() => (saving() ? "Saving" : editing() ? "Save" : "Add secret"));
  const valueType = createMemo(() => (visible() ? "text" : "password"));

  const stores = createMemo(() => sync.view.clouds.filter(cloud => cloudModule(cloud.kind).secretStore));
  const store = createMemo(() => stores().find(cloud => cloud.identity === storedIn()) ?? null);
  // A link to a cloud this computer doesn't have is kept as it is.
  const elsewhere = createMemo(() => storedIn() !== THIS_COMPUTER && store() === null);
  const storeItems = createMemo<SelectItem<string>[]>(() => {
    const items: SelectItem<string>[] = [{ value: THIS_COMPUTER, label: "This computer" }];
    items.push(...stores().map(cloud => ({ value: cloud.identity, label: cloud.name, hint: cloudModule(cloud.kind).detail(cloud) })));
    if (elsewhere()) items.push({ value: storedIn(), label: "A cloud this computer isn't signed into" });
    return items;
  });
  const showsStore = createMemo(() => stores().length > 0 || storedIn() !== THIS_COMPUTER);
  const linkLabel = createMemo(() => `Name in ${store()?.name ?? "that cloud"}`);

  const problems = createMemo(() => {
    const [cloud, current] = [store(), editing()];
    if (!cloud || !current || current.link?.cloud !== cloud.identity) return [];
    const key = `vault:secret:${current.id}:value`;
    return cloud.status.problems.filter(problem => problem.key === key).map(problem => problem.reason);
  });
  const computed = createMemo(() => problems().includes("computed"));
  const missing = createMemo(() => problems().includes("missing") && linkName().trim() === editing()?.link?.name);
  const readOnly = createMemo(() => store()?.status.problems.some(problem => problem.reason === "readOnly") ?? false);
  const valuePlaceholder = createMemo(() => {
    if (computed()) return "Built from other secrets there";
    if (editing()?.hasValue) return "Saved in vault. Type to replace it.";
    return store() ? "Empty takes the value that's already there" : "";
  });
  const valueHint = createMemo(() => {
    const cloud = store();
    if (!cloud) return undefined;
    if (computed()) return `${cloud.name} builds this value from other secrets, so it can only be changed there.`;
    if (readOnly()) return `The token for ${cloud.name} can only read. A value typed here stays on this computer.`;
    return `A value typed here is written to ${cloud.name}. If it's changed there, that one wins.`;
  });
  const canSave = createMemo(() => {
    if (saving() || name().trim() === "") return false;
    if (storedIn() !== THIS_COMPUTER) return linkName().trim() !== "";
    return editing() !== null || copyFrom() !== null || value() !== "";
  });

  function startsIn(): string {
    const chosen = useSettingsState.settings.newSecretsStoredIn;
    return stores().some(cloud => cloud.identity === chosen) ? chosen : THIS_COMPUTER;
  }

  createEffect(on(secrets.editorRequest, request => {
    if (!request) return;
    setName(request.secret?.name ?? "");
    setNote(request.secret?.note ?? "");
    setStoredIn(request.secret ? request.secret.link?.cloud ?? THIS_COMPUTER : startsIn());
    setLinkName(request.secret?.link?.name ?? "");
    setLinkTouched(Boolean(request.secret?.link));
    setValue("");
    setVisible(false);
  }));

  function suggestedName(identity: string, from: string): string | null {
    const cloud = stores().find(candidate => candidate.identity === identity);
    const suggest = cloud ? cloudModule(cloud.kind).secretStore?.suggestName : undefined;
    return suggest ? suggest(from) : null;
  }

  // The name in the cloud follows the secret's name until it's typed or picked.
  function changeName(next: string) {
    setName(next);
    const suggested = linkTouched() ? null : suggestedName(storedIn(), next);
    if (suggested !== null) setLinkName(suggested);
  }

  function changeLinkName(next: string) {
    setLinkTouched(true);
    setLinkName(next);
  }

  function pickStore(identity: string) {
    setStoredIn(identity);
    const suggested = suggestedName(identity, name());
    if (suggested !== null && (!linkTouched() || linkName().trim() === "")) setLinkName(suggested);
  }

  async function pickName(event: MouseEvent & { currentTarget: HTMLButtonElement }) {
    const cloud = store();
    const names = cloud ? cloudModule(cloud.kind).secretStore?.names : undefined;
    if (!cloud || !names) return;
    const rect = event.currentTarget.getBoundingClientRect();
    try {
      const found = await names(cloud);
      if (found.length === 0) {
        pushToast(`${cloud.name} has no secrets yet`, "info", 2500);
        return;
      }
      useContextMenuState.openMenuAt({ x: rect.left, y: rect.bottom + 2 }, found.map(option => ({ label: option, onSelect: () => changeLinkName(option) })));
    } catch (error) {
      pushError(error);
    }
  }

  // Asked once per cloud, before the first secret is kept there.
  async function confirmStore(link: SecretLink | null): Promise<boolean> {
    const cloud = store();
    const notice = cloud ? cloudModule(cloud.kind).secretStore?.notice : undefined;
    if (!link || !cloud || !notice) return true;
    if (secrets.secrets.some(secret => secret.link?.cloud === link.cloud)) return true;
    return usePromptState.confirm({ title: `Keep this secret in ${cloud.name}?`, message: notice, confirmLabel: "Keep it there" });
  }

  // A name the cloud already has keeps its value there, so a value from here would be dropped.
  async function clashesInCloud(link: SecretLink | null, typed: string | null): Promise<boolean> {
    const cloud = store();
    const names = cloud ? cloudModule(cloud.kind).secretStore?.names : undefined;
    const sameLink = editing()?.link?.cloud === link?.cloud && editing()?.link?.name === link?.name;
    if (!link || !cloud || !names || sameLink || (typed === null && !copyFrom())) return false;
    if (!(await names(cloud)).includes(link.name)) return false;
    const fix = copyFrom() ? "Give it a new name" : "Give it a new name, or leave the value empty to use the one there";
    pushError(new Error(`${link.name} is already in ${cloud.name}, and its value there is the one used. ${fix}.`));
    return true;
  }

  async function save() {
    const link = storedIn() === THIS_COMPUTER ? null : { cloud: storedIn(), name: linkName().trim() };
    const typed = computed() || value() === "" ? null : value();
    try {
      if (await clashesInCloud(link, typed)) return;
    } catch (error) {
      pushError(error);
      return;
    }
    if (!await confirmStore(link)) return;
    setSaving(true);
    try {
      const request = secrets.editorRequest();
      const saved = await secrets.save({ id: editing()?.id ?? "", name: name(), note: note(), link }, typed, copyFrom() ?? undefined);
      pushToast(editing() ? `Saved ${saved.name}` : `Added ${saved.name}`, "success", 2500);
      secrets.closeEditor();
      request?.onSaved?.(saved);
    } catch (error) {
      pushError(error);
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    const current = editing();
    if (!current) return;
    try {
      if (await deleteSecret(current)) secrets.closeEditor();
    } catch (error) {
      pushError(error);
    }
  }

  return (
    <Modal
      show={secrets.editorRequest() !== null}
      onHide={secrets.closeEditor}
      title={title()}
      width={460}
      footer={
        <>
          <Show when={editing()}>
            <Button variant="ghost" class={styles.Delete} onClick={remove}>
              <Trash2 size={14} />
              Delete
            </Button>
          </Show>
          <div class={styles.Spacer} />
          <Button variant="subtle" onClick={secrets.closeEditor}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={!canSave()}>{saveLabel()}</Button>
        </>
      }
    >
      <div class={styles.Form}>
        <Field label="Name">
          <Input mono value={name()} onValue={changeName} placeholder="PROD_DB_HOST" autofocus />
        </Field>
        <Show when={showsStore()}>
          <Field label="Stored in">
            <Select value={storedIn()} items={storeItems()} onChange={pickStore} />
          </Field>
        </Show>
        <Show when={store()}>
          <Field label={linkLabel()} hint="An existing name links to that secret. A new name creates it there.">
            <div class={styles.LinkRow}>
              <Input mono value={linkName()} onValue={changeLinkName} placeholder="PROD_DB_HOST" />
              <Button variant="subtle" onClick={event => void pickName(event)}>Pick</Button>
            </div>
          </Field>
        </Show>
        <Show when={!copyFrom()}>
          <Field label="Value" hint={valueHint()}>
            <Input
              mono
              type={valueType()}
              value={value()}
              onValue={setValue}
              placeholder={valuePlaceholder()}
              disabled={computed()}
              after={
                <Show when={value() !== ""}>
                  <Button icon size="sm" tooltip={visible() ? "Hide" : "Show"} onClick={() => setVisible(shown => !shown)}>
                    <Show when={visible()} fallback={<Eye size={14} />}><EyeOff size={14} /></Show>
                  </Button>
                </Show>
              }
            />
          </Field>
        </Show>
        <Show when={copyFrom()}>
<Note>The value is the saved password. The password field then uses this secret, and the old copy stays unused in the vault.</Note>
        </Show>
        <Field label="Note">
          <Input value={note()} onValue={setNote} placeholder="Optional" />
        </Field>
        <Show when={missing()}>
          <Note tone="warning">
            {linkName()} isn't in {store()?.name} any more. The last value is still on this computer. Pick another name, or store the secret on this computer.
          </Note>
        </Show>
        <Show when={elsewhere()}>
          <Note>This secret's value comes from a cloud this computer isn't signed into. Add that cloud on the Sync page to get it.</Note>
        </Show>
        <Note>The value is kept in the encrypted vault. Fields that use this secret only save its name.</Note>
      </div>
    </Modal>
  );
}

export default SecretEditor;
