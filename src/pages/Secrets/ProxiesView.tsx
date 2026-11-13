import styles from "./Secrets.module.scss";
import { For, Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { Globe, Pencil, Plus, Trash2 } from "@core/icons";
import useSshState from "@core/states/sshState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import { createOwnerSecrets } from "@core/helpers/ownerSecrets";
import { shownField } from "@core/helpers/secretRefs";
import SecretInput from "@core/components/SecretInput/SecretInput";
import { toPort } from "@core/databases/shared/fields";
import { Proxy, ProxyKind } from "@core/types";
import Modal from "@core/components/Modal/Modal";
import Button from "@core/components/Button/Button";
import Field, { FieldRow } from "@core/components/Field/Field";
import Input from "@core/components/Input/Input";
import Switch from "@core/components/Switch/Switch";
import SegmentedControl from "@core/components/SegmentedControl/SegmentedControl";
import SecretField from "@core/components/SecretField/SecretField";
import EmptyState from "@core/components/EmptyState/EmptyState";

const COLUMNS = "minmax(180px, 1.4fr) 110px minmax(140px, 1.4fr) minmax(100px, 1fr) 70px";

const KIND_LABELS: Record<ProxyKind, string> = { socks5: "SOCKS5", httpConnect: "HTTP CONNECT" };

function ProxyModal(props: { proxy: Proxy | null, show: boolean, onClose: () => void }) {
  const ssh = useSshState;
  const { pushError } = useToastState;
  const secrets = createOwnerSecrets();
  const [label, setLabel] = createSignal("");
  const [kind, setKind] = createSignal<ProxyKind>("socks5");
  const [host, setHost] = createSignal("");
  const [port, setPort] = createSignal(1080);
  const [login, setLogin] = createSignal(false);
  const [user, setUser] = createSignal("");
  const [busy, setBusy] = createSignal(false);

  createEffect(on(() => props.show, show => {
    if (!show) return;
    const proxy = props.proxy;
    setLabel(proxy?.label ?? "");
    setKind(proxy?.kind ?? "socks5");
    setHost(proxy?.host ?? "");
    setPort(proxy?.port ?? 1080);
    setLogin((proxy?.user ?? "") !== "");
    setUser(proxy?.user ?? "");
    void secrets.reset(proxy ? { kind: "proxy", id: proxy.id } : null, proxy?.secretRefs);
  }));

  const hostFromSecret = createMemo(() => secrets.refs.editor.get("host") !== undefined);
  const canSave = createMemo(() => !busy() && (host().trim() !== "" || hostFromSecret()));

  const title = createMemo(() => (props.proxy ? `Edit ${props.proxy.label}` : "New proxy"));
  const saveLabel = createMemo(() => (props.proxy ? "Save" : "Add proxy"));
  const namePlaceholder = createMemo(() => host() || "office proxy");

  async function save() {
    setBusy(true);
    try {
      const saved = await ssh.saveProxy({
        id: props.proxy?.id ?? "",
        label: label(),
        kind: kind(),
        host: host(),
        port: port(),
        user: login() ? user() : "",
        secretRefs: secrets.refs.snapshot(key => key === "host" || key === "port" || login()),
      });
      if (login()) await secrets.apply({ kind: "proxy", id: saved.id });
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
        <Field label="Name">
          <Input value={label()} onValue={setLabel} placeholder={namePlaceholder()} autofocus />
        </Field>
        <Field label="Type">
          <SegmentedControl
            fill
            value={kind()}
            onChange={setKind}
            options={[
              { value: "socks5", label: "SOCKS5" },
              { value: "httpConnect", label: "HTTP CONNECT" },
            ]}
          />
        </Field>
        <FieldRow>
          <Field label="Address" grow>
            <SecretInput path="host" refs={secrets.refs.editor} value={host()} onValue={setHost} placeholder="proxy.example.com" />
          </Field>
          <Field label="Port" width={96}>
            <SecretInput path="port" refs={secrets.refs.editor} type="number" value={port()} onValue={value => setPort(toPort(value))} />
          </Field>
        </FieldRow>
        <Switch checked={login()} onChange={setLogin} label="The proxy needs a login" />
        <Show when={login()}>
          <FieldRow>
            <Field label="User" grow>
              <SecretInput path="user" refs={secrets.refs.editor} value={user()} onValue={setUser} />
            </Field>
            <Field label="Password" grow>
              <SecretField slot="password" secrets={secrets.editor} />
            </Field>
          </FieldRow>
        </Show>
        <Show when={kind() === "httpConnect" && login()}>
          <p class={styles.FormNote}>The proxy only sees the encrypted SSH stream, but its own login is sent in the clear unless the proxy runs on this computer.</p>
        </Show>
      </div>
    </Modal>
  );
}

function ProxiesView() {
  const ssh = useSshState;
  const { confirm } = usePromptState;
  const { pushError } = useToastState;
  const [editing, setEditing] = createSignal<{ proxy: Proxy | null } | null>(null);
  const editingProxy = createMemo(() => editing()?.proxy ?? null);

  async function remove(proxy: Proxy) {
    const confirmed = await confirm({
      title: `Delete ${proxy.label}?`,
      message: "Its saved password is removed from the vault too.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (confirmed) await ssh.deleteProxy(proxy.id).catch(pushError);
  }

  return (
    <>
      <div class={styles.Head}>
        <h2>Proxies</h2>
        <Button variant="primary" onClick={() => setEditing({ proxy: null })}>
          <Plus size={14} />
          New proxy
        </Button>
      </div>
      <p class={styles.Description}>
        For networks where SSH has to go out through a SOCKS5 or HTTP proxy. A host uses its proxy to reach the first hop of its route.
        To go through another SSH server, add it as a jump host instead.
      </p>

      <div class={styles.List} style={{ "--columns": COLUMNS }}>
        <div class={styles.ListHead}><span>Name</span><span>Type</span><span>Address</span><span>Used by</span><span /></div>
        <Show
          when={ssh.file.proxies.length > 0}
          fallback={<div class={styles.Empty}><EmptyState icon={Globe} title="No proxies" description="Most setups don't need one." /></div>}
        >
          <For each={ssh.file.proxies}>
            {proxy => {
              const usedBy = createMemo(() => ssh.file.hosts.filter(host => host.proxyId === proxy.id).map(host => host.label));
              const usedText = createMemo(() => (usedBy().length > 0 ? usedBy().join(", ") : "Nothing"));
              const address = createMemo(() => `${shownField(proxy.secretRefs, "host", proxy.host)}:${shownField(proxy.secretRefs, "port", proxy.port)}`);
              return (
                <div class={styles.ListRow}>
                  <div class={styles.Name}>
                    <span class={styles.ItemIcon}><Globe size={15} /></span>
                    <span class={styles.NameText}><b>{proxy.label}</b></span>
                  </div>
                  <span class={styles.Cell}>{KIND_LABELS[proxy.kind]}</span>
                  <span class={`${styles.Cell} ${styles.Mono}`}>{address()}</span>
                  <span class={styles.Cell}>{usedText()}</span>
                  <div class={styles.Tools}>
                    <Button icon size="sm" tooltip="Edit" onClick={() => setEditing({ proxy })}><Pencil size={14} /></Button>
                    <Button icon size="sm" tooltip="Delete" onClick={() => remove(proxy)}><Trash2 size={14} /></Button>
                  </div>
                </div>
              );
            }}
          </For>
        </Show>
      </div>

      <ProxyModal proxy={editingProxy()} show={editing() !== null} onClose={() => setEditing(null)} />
    </>
  );
}

export default ProxiesView;
