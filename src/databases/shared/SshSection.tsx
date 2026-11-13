import styles from "./ConnectionForm.module.scss";
import { Match, Show, Switch, createMemo, createSignal } from "solid-js";
import { unwrap } from "solid-js/store";
import { Pencil, Plus, Save, Server } from "@core/icons";
import { IdentityAuth, SecretRefs, SshAuthMethod, SshOptions } from "@core/types";
import useSecretsState from "@core/states/secretsState";
import { SecretEditor } from "../types";
import Field, { FieldRow, FieldSection } from "@core/components/Field/Field";
import SecretInput from "@core/components/SecretInput/SecretInput";
import { SecretRefsEditor } from "@core/helpers/secretRefs";
import Select, { SelectItem } from "@core/components/Select/Select";
import Button from "@core/components/Button/Button";
import SegmentedControl from "@core/components/SegmentedControl/SegmentedControl";
import SecretField from "@core/components/SecretField/SecretField";
import FilePathInput from "@core/components/FilePathInput/FilePathInput";
import RoutePreview from "@core/components/RoutePreview/RoutePreview";
import useSshState from "@core/states/sshState";
import useVpnState from "@core/states/vpnState";
import useHostEditorState from "@core/states/hostEditorState";
import useToastState from "@core/states/toastState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { toPort } from "./fields";
import { IS_WINDOWS } from "@core/helpers/platform";

const SSH_AUTH: SelectItem<SshAuthMethod>[] = [
  { value: "password", label: "Password" },
  { value: "publicKey", label: "Key file" },
  { value: "agent", label: "SSH agent" },
];

const AGENT_SOCKET_PLACEHOLDER = IS_WINDOWS ? "\\\\.\\pipe\\openssh-ssh-agent" : "$SSH_AUTH_SOCK";
const AGENT_SOCKET_HINT = IS_WINDOWS
  ? "Leave empty for the OpenSSH agent, or Pageant if that isn't running. Enter a pipe for agents like 1Password that use their own."
  : "Leave empty to use SSH_AUTH_SOCK. Enter a socket path for agents like 1Password that use their own.";

type Source = "saved" | "inline";

export type SshSectionProps = {
  ssh: SshOptions,
  description: string,
  // The database as the SSH server sees it, shown at the end of the route.
  databaseTarget: string,
  secrets: SecretEditor,
  // Named secrets for the inline fields, by their path in the SSH options.
  refs?: SecretRefsEditor,
  update: (mutate: (ssh: SshOptions) => void) => void,
};

function SshSection(props: SshSectionProps) {
  const sshState = useSshState;
  const editor = useHostEditorState;
  const { pushToast, pushError } = useToastState;
  const [saving, setSaving] = createSignal(false);

  const source = createMemo<Source>(() => (props.ssh.hostId !== null ? "saved" : "inline"));

  const hostItems = createMemo<SelectItem<string | null>[]>(() =>
    sshState.file.hosts.map(host => ({ value: host.id, label: `${host.label} (${sshState.address(host)})` })));
  const savedHost = createMemo(() => (props.ssh.hostId ? sshState.host(props.ssh.hostId) : undefined));
  const route = createMemo(() => (props.ssh.hostId ? sshState.route(props.ssh.hostId) : []));
  const routeProxy = createMemo(() => (props.ssh.hostId ? sshState.routeProxy(props.ssh.hostId) : undefined));
  const routeVpn = createMemo(() => (props.ssh.hostId ? useVpnState.profile(sshState.routeVpnId(props.ssh.hostId)) : undefined));
  const hostPlaceholder = createMemo(() => (props.ssh.hostId && savedHost() === undefined ? "Deleted host, pick another" : "Pick a host"));

  // An empty id keeps the saved-host mode until one is picked.
  function pickSource(next: Source) {
    props.update(ssh => {
      ssh.hostId = next === "saved" ? ssh.hostId ?? sshState.file.hosts[0]?.id ?? "" : null;
    });
  }

  function newHost() {
    editor.open(null, host => props.update(ssh => { ssh.hostId = host.id; }));
  }

  async function keyForFile(path: string): Promise<string> {
    const existing = sshState.file.keys.find(key => key.storage.kind === "file" && key.storage.path === path);
    if (existing) return existing.id;
    const key = await safeInvoke("import_key", { path, label: "", toVault: false, passphrase: null });
    sshState.addKey(key);
    return key.id;
  }

  function refsFor(paths: Record<string, string>): SecretRefs {
    const refs: SecretRefs = {};
    for (const [from, to] of Object.entries(paths)) {
      const secretId = props.refs?.get(from);
      if (secretId) refs[to] = secretId;
    }
    return refs;
  }

  // What a field shows: what was typed, or the name of the secret that fills it.
  function shown(text: string, secretId: string | undefined): string {
    return text.trim() || (secretId ? useSecretsState.find(secretId)?.name ?? "" : "");
  }

  // Moves the typed SSH secrets from this connection to the new host, identity and key, named secrets included.
  async function saveAsHost() {
    const ssh = unwrap(props.ssh);
    if (["keyFile", "agentSocket"].some(path => props.refs?.get(path))) {
      pushError(new Error("A saved host needs the key file or agent socket typed in. Take the secret off it first."));
      return;
    }
    const hostRefs = refsFor({ host: "host", port: "port" });
    const identityRefs = refsFor({ user: "user", "slot:sshPassword": "slot:password" });
    const keyRefs = refsFor({ "slot:sshKeyPassphrase": "slot:passphrase" });
    const hostText = shown(ssh.host, hostRefs.host);
    const userText = shown(ssh.user, identityRefs.user);
    if (!hostText || !userText) {
      pushError(new Error("Enter the SSH host and user first"));
      return;
    }
    setSaving(true);
    try {
      let auth: IdentityAuth;
      switch (ssh.auth) {
        case "publicKey":
          auth = { kind: "key", keyId: await keyForFile(ssh.keyFile.trim()) };
          break;
        case "agent":
          auth = { kind: "agent", socket: ssh.agentSocket.trim() };
          break;
        case "password":
          auth = { kind: "password" };
          break;
      }

      if (auth.kind !== "password") delete identityRefs["slot:password"];
      const identity = await sshState.saveIdentity({ id: "", label: `${userText} (${hostText})`, user: ssh.user, auth, secretRefs: identityRefs });
      const password = props.secrets.pending("sshPassword");
      if (auth.kind === "password" && typeof password === "string" && !identityRefs["slot:password"]) {
        await safeInvoke("set_owner_secret", { owner: { kind: "identity", id: identity.id }, slot: "password", value: password });
      }
      const passphrase = props.secrets.pending("sshKeyPassphrase");
      if (auth.kind === "key" && keyRefs["slot:passphrase"]) {
        await sshState.setKeySecretRefs(auth.keyId, keyRefs);
      } else if (auth.kind === "key" && typeof passphrase === "string") {
        await safeInvoke("set_owner_secret", { owner: { kind: "key", id: auth.keyId }, slot: "passphrase", value: passphrase });
      }

      const host = await sshState.saveHost({
        id: "",
        secretRefs: hostRefs,
        label: hostText,
        group: null,
        color: null,
        host: ssh.host,
        port: ssh.port,
        identityId: identity.id,
        jumps: [],
        proxyId: null,
        vpnId: null,
        keepaliveSecs: 30,
        agentForwarding: false,
        clipboardWrite: false,
        startupSnippetId: null,
      });
      props.secrets.setPending("sshPassword", undefined);
      props.secrets.setPending("sshKeyPassphrase", undefined);
      for (const path of ["host", "port", "user", "slot:sshPassword", "slot:sshKeyPassphrase"]) props.refs?.set(path, null);
      props.update(options => { options.hostId = host.id; });
      pushToast(`Saved ${host.label} as an SSH host`, "success", 3000);
    } catch (error) {
      pushError(error);
    } finally {
      setSaving(false);
    }
  }

  return (
    <FieldSection title="SSH" description={props.description}>
      <SegmentedControl
        fill
        value={source()}
        onChange={pickSource}
        options={[
          { value: "saved", label: "Saved host", icon: Server },
          { value: "inline", label: "Only for this connection", icon: Pencil },
        ]}
      />

      <Switch>
        <Match when={source() === "saved"}>
          <Show
            when={sshState.file.hosts.length > 0}
            fallback={<div class={styles.Note}>No saved hosts yet. Add one, or set up the tunnel only for this connection.</div>}
          >
            <Field label="Host" hint="The host's identity, jump hosts and proxy are used as they are. Its secrets stay with the host, not this connection.">
              <Select
                value={props.ssh.hostId}
                items={hostItems()}
                onChange={id => props.update(ssh => { ssh.hostId = id; })}
                placeholder={hostPlaceholder()}
              />
            </Field>
            <Show when={route().length > 0}>
              <RoutePreview hosts={route()} proxy={routeProxy()} vpn={routeVpn()} database={props.databaseTarget} />
            </Show>
          </Show>
          <div class={styles.Actions}>
            <Button size="sm" variant="subtle" onClick={newHost}>
              <Plus size={14} />
              New SSH host
            </Button>
            <Show when={savedHost()}>
              {host => (
                <Button size="sm" variant="ghost" onClick={() => editor.open(host())}>
                  <Pencil size={14} />
                  Edit {host().label}
                </Button>
              )}
            </Show>
          </div>
        </Match>

        <Match when={source() === "inline"}>
          <FieldRow>
            <Field label="SSH host" grow>
              <SecretInput
                path="host"
                refs={props.refs}
                value={props.ssh.host}
                onValue={value => props.update(ssh => { ssh.host = value; })}
                placeholder="bastion.example.com"
              />
            </Field>
            <Field label="Port" width={96}>
              <SecretInput
                path="port"
                refs={props.refs}
                type="number"
                value={props.ssh.port}
                onValue={value => props.update(ssh => { ssh.port = toPort(value); })}
              />
            </Field>
          </FieldRow>
          <FieldRow>
            <Field label="SSH user" grow>
              <SecretInput
                path="user"
                refs={props.refs}
                value={props.ssh.user}
                onValue={value => props.update(ssh => { ssh.user = value; })}
              />
            </Field>
            <Field label="Authentication" width={160}>
              <Select
                value={props.ssh.auth}
                items={SSH_AUTH}
                onChange={auth => props.update(ssh => { ssh.auth = auth; })}
              />
            </Field>
          </FieldRow>
          <Switch>
            <Match when={props.ssh.auth === "password"}>
              <Field label="SSH password">
                <SecretField slot="sshPassword" secrets={props.secrets} />
              </Field>
            </Match>
            <Match when={props.ssh.auth === "publicKey"}>
              <Field label="Private key file">
                <FilePathInput
                  path="keyFile"
                  refs={props.refs}
                  value={props.ssh.keyFile}
                  onValue={value => props.update(ssh => { ssh.keyFile = value; })}
                  placeholder="~/.ssh/id_ed25519"
                  dialogTitle="Choose an SSH private key"
                />
              </Field>
              <Field label="Key passphrase" hint="Only needed for encrypted keys.">
                <SecretField slot="sshKeyPassphrase" secrets={props.secrets} />
              </Field>
            </Match>
            <Match when={props.ssh.auth === "agent"}>
              <Field label="Agent socket" hint={AGENT_SOCKET_HINT}>
                <SecretInput
                  path="agentSocket"
                  refs={props.refs}
                  value={props.ssh.agentSocket}
                  onValue={value => props.update(ssh => { ssh.agentSocket = value; })}
                  placeholder={AGENT_SOCKET_PLACEHOLDER}
                />
              </Field>
            </Match>
          </Switch>
          <div class={styles.Actions}>
            <Button size="sm" variant="subtle" disabled={saving()} onClick={saveAsHost}>
              <Save size={14} />
              Save as an SSH host
            </Button>
            <span class={styles.ActionHint}>Other connections can use it too. Its login becomes an identity on the Secrets page.</span>
          </div>
        </Match>
      </Switch>
    </FieldSection>
  );
}

export default SshSection;
