import styles from "./ForwardRuleEditor.module.scss";
import { Match, Show, Switch as Branch, createEffect, createMemo, createSignal, on } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { Trash2 } from "@core/icons";
import { ForwardKind, ForwardRule } from "@core/types";
import useForwardRulesState from "@core/states/forwardRulesState";
import useSshState from "@core/states/sshState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import { FORWARD_KIND_LABELS } from "@core/helpers/forwardRules";
import { toPort } from "@core/databases/shared/fields";
import Modal from "../Modal/Modal";
import Button from "../Button/Button";
import Field, { FieldRow } from "../Field/Field";
import Input from "../Input/Input";
import Select, { SelectItem } from "../Select/Select";
import SegmentedControl from "../SegmentedControl/SegmentedControl";
import Switch from "../Switch/Switch";
import Note from "../Note/Note";
import SyncField from "../SyncTarget/SyncField";
import { itemKey } from "@core/states/syncState";

const NOTES: Record<ForwardKind, string> = {
  local: "Connections to the port on this computer go through the host to the destination.",
  remote: "The server listens on its side and sends each connection back to a port this computer can reach.",
  dynamic: "A SOCKS5 proxy on this computer. Point a browser or tool at it to reach things as the server does.",
};

function blankRule(hostId: string): ForwardRule {
  return {
    id: "",
    label: "",
    kind: "local",
    hostId,
    listenPort: 0,
    allNetworks: false,
    remoteBind: "localhost",
    targetHost: "",
    targetPort: 0,
  };
}

function portText(port: number): string {
  return port > 0 ? String(port) : "";
}

function ForwardRuleEditor() {
  const rules = useForwardRulesState;
  const ssh = useSshState;
  const { pushError, pushToast } = useToastState;
  const [draft, setDraft] = createStore<ForwardRule>(blankRule(""));
  const [saving, setSaving] = createSignal(false);

  const editing = createMemo(() => rules.editorRequest()?.rule ?? null);
  const title = createMemo(() => (editing() ? `Edit ${editing()?.label}` : "New port forward"));
  const saveLabel = createMemo(() => (saving() ? "Saving" : editing() ? "Save" : "Add forward"));
  const running = createMemo(() => (editing() ? rules.status(editing()!.id) !== undefined : false));
  const syncKey = createMemo(() => (draft.id ? itemKey("forward", draft.id) : null));
  const hostItems = createMemo<SelectItem<string>[]>(() => ssh.file.hosts.map(host => ({ value: host.id, label: `${host.label} (${host.host})` })));
  const hostHint = createMemo(() => (hostItems().length === 0 ? "Add an SSH host first." : undefined));
  const remoteShared = createMemo(() => draft.kind === "remote" && !["localhost", "127.0.0.1", "::1"].includes(draft.remoteBind.trim()));
  const listens = createMemo(() => draft.kind !== "remote");
  const exposed = createMemo(() => listens() && draft.allNetworks);
  const exposedWarning = createMemo(() => (draft.kind === "dynamic"
    ? "Anyone who can reach this computer can browse as the server through the proxy. It has no login."
    : "Anyone who can reach this computer can connect through the forward. The service's own login is the only thing in the way."));

  createEffect(on(rules.editorRequest, request => {
    if (!request) return;
    const initial = request.rule
      ? JSON.parse(JSON.stringify(request.rule)) as ForwardRule
      : blankRule(request.hostId ?? ssh.file.hosts[0]?.id ?? "");
    setDraft(reconcile(initial));
  }));

  async function save() {
    setSaving(true);
    try {
      const saved = await ssh.saveForward(JSON.parse(JSON.stringify(draft)) as ForwardRule);
      pushToast(editing() ? `Saved ${saved.label}` : `Added ${saved.label}`, "success", 2500);
      rules.closeEditor();
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
      message: running() ? "It's running and stops now." : "The forward is removed.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!confirmed) return;
    try {
      await ssh.deleteForward(current.id);
      if (running()) await rules.stop(current.id);
      rules.closeEditor();
    } catch (error) {
      pushError(error);
    }
  }

  return (
    <Modal
      show={rules.editorRequest() !== null}
      onHide={rules.closeEditor}
      title={title()}
      width={500}
      footer={
        <>
          <Show when={editing()}>
            <Button variant="ghost" class={styles.Delete} onClick={remove}>
              <Trash2 size={14} />
              Delete
            </Button>
          </Show>
          <div class={styles.Spacer} />
          <Button variant="subtle" onClick={rules.closeEditor}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={saving() || running() || !draft.hostId}>{saveLabel()}</Button>
        </>
      }
    >
      <div class={styles.Form}>
        <Show when={running()}>
          <Note tone="warning">This forward is running. Stop it before changing it.</Note>
        </Show>
        <Field label="Name">
          <Input value={draft.label} onValue={value => setDraft("label", value)} placeholder="Grafana" autofocus />
        </Field>
        <Field label="Type">
          <SegmentedControl
            fill
            value={draft.kind}
            onChange={kind => setDraft("kind", kind)}
            options={(Object.keys(FORWARD_KIND_LABELS) as ForwardKind[]).map(kind => ({ value: kind, label: FORWARD_KIND_LABELS[kind] }))}
          />
        </Field>
        <Field label="Through host" hint={hostHint()}>
          <Select value={draft.hostId} items={hostItems()} onChange={id => setDraft("hostId", id)} placeholder="Pick a host" disabled={hostItems().length === 0} />
        </Field>

        <Branch>
          <Match when={draft.kind === "local"}>
            <FieldRow>
              <Field label="Port on this computer" width={170}>
                <Input type="number" min={1} max={65535} value={portText(draft.listenPort)} onValue={value => setDraft("listenPort", toPort(value))} placeholder="8080" />
              </Field>
              <Field label="Destination, as the server sees it" grow>
                <Input value={draft.targetHost} onValue={value => setDraft("targetHost", value)} placeholder="grafana.internal" />
              </Field>
              <Field label="Port" width={96}>
                <Input type="number" min={1} max={65535} value={portText(draft.targetPort)} onValue={value => setDraft("targetPort", toPort(value))} placeholder="3000" />
              </Field>
            </FieldRow>
          </Match>
          <Match when={draft.kind === "remote"}>
            <FieldRow>
              <Field label="Server listens on" grow>
                <Input value={draft.remoteBind} onValue={value => setDraft("remoteBind", value)} placeholder="localhost" />
              </Field>
              <Field label="Port" width={96}>
                <Input type="number" min={1} max={65535} value={portText(draft.listenPort)} onValue={value => setDraft("listenPort", toPort(value))} placeholder="8080" />
              </Field>
            </FieldRow>
            <FieldRow>
              <Field label="Sends to, as this computer sees it" grow>
                <Input value={draft.targetHost} onValue={value => setDraft("targetHost", value)} placeholder="127.0.0.1" />
              </Field>
              <Field label="Port" width={96}>
                <Input type="number" min={1} max={65535} value={portText(draft.targetPort)} onValue={value => setDraft("targetPort", toPort(value))} placeholder="5173" />
              </Field>
            </FieldRow>
          </Match>
          <Match when={draft.kind === "dynamic"}>
            <Field label="Port on this computer" width={170}>
              <Input type="number" min={1} max={65535} value={portText(draft.listenPort)} onValue={value => setDraft("listenPort", toPort(value))} placeholder="1080" />
            </Field>
          </Match>
        </Branch>

        <Show when={listens()}>
          <Switch checked={draft.allNetworks} onChange={value => setDraft("allNetworks", value)} label="Listen on all networks (0.0.0.0)" />
        </Show>
        <Note>{NOTES[draft.kind]}</Note>
        <Show when={exposed()}>
          <Note tone="warning">{exposedWarning()} Windows may ask to let Fran through the firewall.</Note>
        </Show>
        <Show when={remoteShared()}>
          <Note tone="warning">Other machines that reach the server can use this port, if the server's GatewayPorts setting allows it.</Note>
        </Show>
        <SyncField itemKey={syncKey()} label={draft.label} category="forwards" />
      </div>
    </Modal>
  );
}

export default ForwardRuleEditor;
