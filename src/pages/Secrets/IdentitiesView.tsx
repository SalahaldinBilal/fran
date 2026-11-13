import styles from "./Secrets.module.scss";
import { For, Match, Show, Switch, createEffect, createMemo, createSignal, on } from "solid-js";
import { KeyRound, Lock, Pencil, Plus, ShieldCheck, Trash2, User } from "@core/icons";
import useSshState from "@core/states/sshState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import { createOwnerSecrets } from "@core/helpers/ownerSecrets";
import { shownField } from "@core/helpers/secretRefs";
import { IS_WINDOWS } from "@core/helpers/platform";
import { Identity, IdentityAuth } from "@core/types";
import Modal from "@core/components/Modal/Modal";
import Button from "@core/components/Button/Button";
import Field, { FieldRow } from "@core/components/Field/Field";
import Input from "@core/components/Input/Input";
import SecretInput from "@core/components/SecretInput/SecretInput";
import Select, { SelectItem } from "@core/components/Select/Select";
import SegmentedControl from "@core/components/SegmentedControl/SegmentedControl";
import SecretField from "@core/components/SecretField/SecretField";
import EmptyState from "@core/components/EmptyState/EmptyState";

const COLUMNS = "minmax(180px, 1.4fr) minmax(140px, 1.4fr) minmax(120px, 1.2fr) 70px";

const AGENT_PLACEHOLDER = IS_WINDOWS ? "\\\\.\\pipe\\openssh-ssh-agent" : "$SSH_AUTH_SOCK";
const AGENT_HINT = IS_WINDOWS
  ? "Leave empty for the OpenSSH agent, or Pageant if that isn't running."
  : "Leave empty to use SSH_AUTH_SOCK.";

type AuthKind = IdentityAuth["kind"];

function IdentityModal(props: { identity: Identity | null, show: boolean, onClose: () => void }) {
  const ssh = useSshState;
  const { pushError } = useToastState;
  const secrets = createOwnerSecrets();
  const [label, setLabel] = createSignal("");
  const [user, setUser] = createSignal("");
  const [kind, setKind] = createSignal<AuthKind>("key");
  const [keyId, setKeyId] = createSignal<string | null>(null);
  const [socket, setSocket] = createSignal("");
  const [busy, setBusy] = createSignal(false);

  createEffect(on(() => props.show, show => {
    if (!show) return;
    const identity = props.identity;
    setLabel(identity?.label ?? "");
    setUser(identity?.user ?? "");
    setKind(identity?.auth.kind ?? (ssh.file.keys.length > 0 ? "key" : "agent"));
    setKeyId(identity?.auth.kind === "key" ? identity.auth.keyId : ssh.file.keys[0]?.id ?? null);
    setSocket(identity?.auth.kind === "agent" ? identity.auth.socket : "");
    void secrets.reset(identity ? { kind: "identity", id: identity.id } : null, identity?.secretRefs);
  }));

  const userFromSecret = createMemo(() => secrets.refs.editor.get("user") !== undefined);
  const canSave = createMemo(() => !busy() && (user().trim() !== "" || userFromSecret()));

  const title = createMemo(() => (props.identity ? `Edit ${props.identity.label}` : "New identity"));
  const saveLabel = createMemo(() => (props.identity ? "Save" : "Add identity"));
  const keyItems = createMemo<SelectItem<string | null>[]>(() => ssh.file.keys.map(key => ({ value: key.id, label: `${key.label} (${key.algorithm})` })));
  const keyHint = createMemo(() => (keyItems().length === 0 ? "No keys yet. Generate or import one on the SSH keys page." : undefined));
  const namePlaceholder = createMemo(() => user() || "deploy");

  function auth(): IdentityAuth {
    switch (kind()) {
      case "key": {
        const id = keyId();
        if (!id) throw new Error("Pick a key");
        return { kind: "key", keyId: id };
      }
      case "agent":
        return { kind: "agent", socket: socket().trim() };
      case "password":
        return { kind: "password" };
    }
  }

  async function save() {
    setBusy(true);
    try {
      const secretRefs = secrets.refs.snapshot(key => key === "user" || kind() === "password");
      const saved = await ssh.saveIdentity({ id: props.identity?.id ?? "", label: label(), user: user(), auth: auth(), secretRefs });
      if (saved.auth.kind === "password") await secrets.apply({ kind: "identity", id: saved.id });
      props.onClose();
    } catch (error) {
      pushError(error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      show={props.show}
      onHide={props.onClose}
      title={title()}
      width={460}
      footer={
        <>
          <Button variant="subtle" onClick={props.onClose}>Cancel</Button>
          <Button variant="primary" disabled={!canSave()} onClick={save}>{saveLabel()}</Button>
        </>
      }
    >
      <div class={styles.Form}>
        <FieldRow>
          <Field label="Name" grow>
            <Input value={label()} onValue={setLabel} placeholder={namePlaceholder()} autofocus />
          </Field>
          <Field label="User" grow>
            <SecretInput path="user" refs={secrets.refs.editor} value={user()} onValue={setUser} placeholder="deploy" />
          </Field>
        </FieldRow>
        <Field label="Log in with">
          <SegmentedControl
            fill
            value={kind()}
            onChange={setKind}
            options={[
              { value: "key", label: "Key" },
              { value: "agent", label: "SSH agent" },
              { value: "password", label: "Password" },
            ]}
          />
        </Field>
        <Switch>
          <Match when={kind() === "key"}>
            <Field label="Key" hint={keyHint()}>
              <Select value={keyId()} items={keyItems()} onChange={setKeyId} placeholder="Pick a key" disabled={keyItems().length === 0} />
            </Field>
          </Match>
          <Match when={kind() === "agent"}>
            <Field label="Agent socket" hint={AGENT_HINT}>
              <Input value={socket()} onValue={setSocket} placeholder={AGENT_PLACEHOLDER} mono />
            </Field>
          </Match>
          <Match when={kind() === "password"}>
            <Field label="Password" hint="Saved to the vault. Show asks your system to confirm it's you first.">
              <SecretField slot="password" secrets={secrets.editor} />
            </Field>
          </Match>
        </Switch>
      </div>
    </Modal>
  );
}

function IdentitiesView() {
  const ssh = useSshState;
  const { confirm } = usePromptState;
  const { pushError } = useToastState;
  const [editing, setEditing] = createSignal<{ identity: Identity | null } | null>(null);
  const editingIdentity = createMemo(() => editing()?.identity ?? null);

  async function remove(identity: Identity) {
    const confirmed = await confirm({
      title: `Delete ${identity.label}?`,
      message: "Its saved password is removed from the vault too.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (confirmed) await ssh.deleteIdentity(identity.id).catch(pushError);
  }

  return (
    <>
      <div class={styles.Head}>
        <h2>Identities</h2>
        <Button variant="primary" onClick={() => setEditing({ identity: null })}>
          <Plus size={14} />
          New identity
        </Button>
      </div>
      <p class={styles.Description}>
        A user name and how it logs in. Hosts point at an identity, so changing a password or key here changes it for every host that uses it.
      </p>

      <div class={styles.List} style={{ "--columns": COLUMNS }}>
        <div class={styles.ListHead}><span>Name</span><span>Logs in with</span><span>Used by</span><span /></div>
        <Show
          when={ssh.file.identities.length > 0}
          fallback={<div class={styles.Empty}><EmptyState icon={User} title="No identities yet" description="They're made when you add a host, or here." /></div>}
        >
          <For each={ssh.file.identities}>
            {identity => {
              const usedBy = createMemo(() => ssh.file.hosts.filter(host => host.identityId === identity.id).map(host => host.label));
              const usedText = createMemo(() => (usedBy().length > 0 ? usedBy().join(", ") : "Nothing"));
              const keyLabel = createMemo(() => (identity.auth.kind === "key" ? ssh.key(identity.auth.keyId)?.label ?? "a deleted key" : ""));
              const user = createMemo(() => shownField(identity.secretRefs, "user", identity.user));
              return (
                <div class={styles.ListRow}>
                  <div class={styles.Name}>
                    <span class={styles.ItemIcon}><User size={15} /></span>
                    <span class={styles.NameText}><b>{identity.label}</b><small class={styles.Mono}>{user()}</small></span>
                  </div>
                  <span class={styles.Cell}>
                    <Switch>
                      <Match when={identity.auth.kind === "key"}><KeyRound size={12} />Key {keyLabel()}</Match>
                      <Match when={identity.auth.kind === "agent"}><ShieldCheck size={12} />SSH agent</Match>
                      <Match when={identity.auth.kind === "password"}><Lock size={12} />Password</Match>
                    </Switch>
                  </span>
                  <span class={styles.Cell}>{usedText()}</span>
                  <div class={styles.Tools}>
                    <Button icon size="sm" tooltip="Edit" onClick={() => setEditing({ identity })}><Pencil size={14} /></Button>
                    <Button icon size="sm" tooltip="Delete" onClick={() => remove(identity)}><Trash2 size={14} /></Button>
                  </div>
                </div>
              );
            }}
          </For>
        </Show>
      </div>

      <IdentityModal identity={editingIdentity()} show={editing() !== null} onClose={() => setEditing(null)} />
    </>
  );
}

export default IdentitiesView;
