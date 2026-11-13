import styles from "./SecretEditor.module.scss";
import { Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { Eye, EyeOff, Trash2 } from "@core/icons";
import useSecretsState from "@core/states/secretsState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import { SecretInfo } from "@core/types";
import Modal from "../Modal/Modal";
import Button from "../Button/Button";
import Field from "../Field/Field";
import Input from "../Input/Input";
import Note from "../Note/Note";

export function usedByText(secret: SecretInfo): string {
  const names = [...new Set(secret.usedBy.map(used => used.label))];
  return names.length > 0 ? names.join(", ") : "Nothing";
}

export async function confirmDeleteSecret(secret: SecretInfo): Promise<boolean> {
  const users = usedByText(secret);
  return usePromptState.confirm({
    title: `Delete ${secret.name}?`,
    message: secret.usedBy.length > 0
      ? `It's used by ${users}. They stop connecting until you pick another secret or type a value in their settings.`
      : "Its value is removed from the vault.",
    confirmLabel: "Delete",
    danger: true,
  });
}

function SecretEditor() {
  const secrets = useSecretsState;
  const { pushError, pushToast } = useToastState;
  const [name, setName] = createSignal("");
  const [value, setValue] = createSignal("");
  const [note, setNote] = createSignal("");
  const [visible, setVisible] = createSignal(false);
  const [saving, setSaving] = createSignal(false);

  const editing = createMemo(() => secrets.editorRequest()?.secret ?? null);
  const title = createMemo(() => (editing() ? `Edit ${editing()?.name}` : "New secret"));
  const saveLabel = createMemo(() => (saving() ? "Saving" : editing() ? "Save" : "Add secret"));
  const valueType = createMemo(() => (visible() ? "text" : "password"));
  const valuePlaceholder = createMemo(() => (editing()?.hasValue ? "Saved in vault. Type to replace it." : ""));
  const canSave = createMemo(() => !saving() && name().trim() !== "" && (editing() !== null || value() !== ""));

  createEffect(on(secrets.editorRequest, request => {
    if (!request) return;
    setName(request.secret?.name ?? "");
    setNote(request.secret?.note ?? "");
    setValue("");
    setVisible(false);
  }));

  async function save() {
    setSaving(true);
    try {
      const request = secrets.editorRequest();
      const saved = await secrets.save({ id: editing()?.id ?? "", name: name(), note: note() }, value() === "" ? null : value());
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
    if (!current || !await confirmDeleteSecret(current)) return;
    try {
      await secrets.remove(current.id);
      secrets.closeEditor();
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
          <Input mono value={name()} onValue={setName} placeholder="PROD_DB_HOST" autofocus />
        </Field>
        <Field label="Value">
          <Input
            mono
            type={valueType()}
            value={value()}
            onValue={setValue}
            placeholder={valuePlaceholder()}
            after={
              <Show when={value() !== ""}>
                <Button icon size="sm" tooltip={visible() ? "Hide" : "Show"} onClick={() => setVisible(shown => !shown)}>
                  <Show when={visible()} fallback={<Eye size={14} />}><EyeOff size={14} /></Show>
                </Button>
              </Show>
            }
          />
        </Field>
        <Field label="Note">
          <Input value={note()} onValue={setNote} placeholder="Optional" />
        </Field>
        <Note>The value is kept in the encrypted vault. Fields that use this secret only save its name.</Note>
      </div>
    </Modal>
  );
}

export default SecretEditor;
