import styles from "./SnippetEditor.module.scss";
import { Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { Trash2 } from "lucide-solid";
import useSnippetsState from "@core/states/snippetsState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import Modal from "../Modal/Modal";
import Button from "../Button/Button";
import Field from "../Field/Field";
import Input from "../Input/Input";
import Switch from "../Switch/Switch";
import Note from "../Note/Note";

function SnippetEditor() {
  const snippets = useSnippetsState;
  const { pushError, pushToast } = useToastState;
  const [label, setLabel] = createSignal("");
  const [command, setCommand] = createSignal("");
  const [confirm, setConfirm] = createSignal(false);
  const [saving, setSaving] = createSignal(false);

  const editing = createMemo(() => snippets.editorRequest()?.snippet ?? null);
  const title = createMemo(() => (editing() ? `Edit ${editing()?.label}` : "New snippet"));
  const saveLabel = createMemo(() => (saving() ? "Saving" : editing() ? "Save" : "Add snippet"));

  createEffect(on(snippets.editorRequest, request => {
    if (!request) return;
    setLabel(request.snippet?.label ?? "");
    setCommand(request.snippet?.command ?? "");
    setConfirm(request.snippet?.confirm ?? false);
  }));

  async function save() {
    setSaving(true);
    try {
      const saved = await snippets.save({ id: editing()?.id ?? "", label: label(), command: command(), confirm: confirm() });
      pushToast(editing() ? `Saved ${saved.label}` : `Added ${saved.label}`, "success", 2500);
      snippets.closeEditor();
    } catch (error) {
      pushError(error);
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    const current = editing();
    if (!current) return;
    const confirmed = await usePromptState.confirm({
      title: `Delete ${current.label}?`,
      message: "The snippet is removed from every terminal.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!confirmed) return;
    try {
      await snippets.remove(current.id);
      snippets.closeEditor();
    } catch (error) {
      pushError(error);
    }
  }

  return (
    <Modal
      show={snippets.editorRequest() !== null}
      onHide={snippets.closeEditor}
      title={title()}
      width={480}
      footer={
        <>
          <Show when={editing()}>
            <Button variant="ghost" class={styles.Delete} onClick={remove}>
              <Trash2 size={14} />
              Delete
            </Button>
          </Show>
          <div class={styles.Spacer} />
          <Button variant="subtle" onClick={snippets.closeEditor}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={saving() || command().trim() === ""}>{saveLabel()}</Button>
        </>
      }
    >
      <div class={styles.Form}>
        <Field label="Name">
          <Input value={label()} onValue={setLabel} placeholder="Restart API" autofocus />
        </Field>
        <Field label="Command">
          <textarea
            class={styles.Command}
            rows={4}
            value={command()}
            spellcheck={false}
            placeholder="sudo systemctl restart api"
            onInput={event => setCommand(event.currentTarget.value)}
          />
        </Field>
        <Switch checked={confirm()} onChange={setConfirm} label="Ask before running" />
        <Note>Snippets are saved as plain text in snippets.json. Don't put passwords or tokens in them.</Note>
      </div>
    </Modal>
  );
}

export default SnippetEditor;
