import styles from "./HostEditor.module.scss";
import editorStyles from "@core/pages/Home/ConnectionEditor/ConnectionEditor.module.scss";
import { For, Match, Show, Switch, createEffect, createMemo, createSignal, on } from "solid-js";
import { createStore, produce, reconcile, unwrap } from "solid-js/store";
import { ArrowDown, ArrowUp, Link, Plus, Server, SlidersHorizontal, Trash2, User, X } from "@core/icons";
import { IdentityAuth, SshHost } from "@core/types";
import { safeInvoke } from "@core/helpers/safeInvoke";
import useHostEditorState from "@core/states/hostEditorState";
import useSshState from "@core/states/sshState";
import useSnippetsState from "@core/states/snippetsState";
import useVpnState from "@core/states/vpnState";
import useVpnEditorState from "@core/states/vpnEditorState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import Modal from "@core/components/Modal/Modal";
import Button from "@core/components/Button/Button";
import Field, { FieldRow } from "@core/components/Field/Field";
import Input from "@core/components/Input/Input";
import SecretInput from "@core/components/SecretInput/SecretInput";
import { SecretRefsEditor } from "@core/helpers/secretRefs";
import Select, { SelectItem } from "@core/components/Select/Select";
import SegmentedControl from "@core/components/SegmentedControl/SegmentedControl";
import SuggestInput from "@core/components/SuggestInput/SuggestInput";
import SyncField from "@core/components/SyncTarget/SyncField";
import { itemKey } from "@core/states/syncState";
import ColorSwatches from "@core/components/ColorSwatches/ColorSwatches";
import RoutePreview from "@core/components/RoutePreview/RoutePreview";
import Toggle from "@core/components/Switch/Switch";
import Note from "@core/components/Note/Note";
import { toPort } from "@core/databases/shared/fields";

const CUSTOM_LOGIN = "";
const IMPORT_VPN = "import:vpn";

type CustomAuth = IdentityAuth["kind"];

const KEEPALIVE: SelectItem<number>[] = [
  { value: 15, label: "Every 15 seconds" },
  { value: 30, label: "Every 30 seconds" },
  { value: 60, label: "Every minute" },
  { value: 0, label: "Off" },
];

function blankHost(): SshHost {
  return {
    id: "",
    label: "",
    group: null,
    color: null,
    host: "",
    port: 22,
    identityId: null,
    jumps: [],
    proxyId: null,
    vpnId: null,
    keepaliveSecs: 30,
    agentForwarding: false,
    clipboardWrite: false,
    startupSnippetId: null,
  };
}

function HostEditor() {
  const editor = useHostEditorState;
  const ssh = useSshState;
  const { confirm } = usePromptState;
  const { pushToast, pushError } = useToastState;

  const [draft, setDraft] = createStore<SshHost>(blankHost());
  const [jumpPick, setJumpPick] = createSignal<string | null>(null);
  const [customUser, setCustomUser] = createSignal("");
  const [customAuth, setCustomAuth] = createSignal<CustomAuth>("key");
  const [customKey, setCustomKey] = createSignal<string | null>(null);
  const [customPassword, setCustomPassword] = createSignal("");
  const [saving, setSaving] = createSignal(false);

  createEffect(on(editor.request, request => {
    if (!request) return;
    setDraft(reconcile(request.host ? JSON.parse(JSON.stringify(unwrap(request.host))) : blankHost()));
    if (!request.host) setDraft("identityId", ssh.file.identities[0]?.id ?? CUSTOM_LOGIN);
    setJumpPick(null);
    setCustomUser("");
    setCustomAuth(ssh.file.keys.length > 0 ? "key" : "agent");
    setCustomKey(ssh.file.keys[0]?.id ?? null);
    setCustomPassword("");
  }));

  const secretRefs: SecretRefsEditor = {
    get: key => draft.secretRefs?.[key],
    set: (key, secretId) => setDraft(produce(host => {
      const refs = host.secretRefs ??= {};
      if (secretId) refs[key] = secretId;
      else delete refs[key];
    })),
  };

  const isNew = createMemo(() => !draft.id);
  const syncKey = createMemo(() => (draft.id ? itemKey("sshHost", draft.id) : null));
  const title = createMemo(() => (isNew() ? "New SSH host": `Edit ${editor.request()?.host?.label ?? ""}`));
  const saveLabel = createMemo(() => (saving() ? "Saving" : isNew() ? "Add host" : "Save"));
  const customLogin = createMemo(() => (draft.identityId ?? CUSTOM_LOGIN) === CUSTOM_LOGIN);
  const identityHint = createMemo(() => (customLogin()
    ? "Saved as an identity named after this host, so other hosts can use it too."
    : "Changing the identity's password or key changes it for every host that uses it."));
  const groups = createMemo(() => [...new Set(ssh.file.hosts.flatMap(host => (host.group ? [host.group] : [])))].sort());

  const identityItems = createMemo<SelectItem<string>[]>(() => [
    ...ssh.file.identities.map(identity => ({ value: identity.id, label: `${identity.label} (${identity.user})` })),
    { value: CUSTOM_LOGIN, label: "New login for this host" },
  ]);
  const keyItems = createMemo<SelectItem<string | null>[]>(() => ssh.file.keys.map(key => ({ value: key.id, label: `${key.label} (${key.algorithm})` })));
  const keyHint = createMemo(() => (keyItems().length === 0 ? "No keys yet. Generate or import one on the Secrets page." : undefined));
  const proxyItems = createMemo<SelectItem<string | null>[]>(() => [
    { value: null, label: "None, connect directly" },
    ...ssh.file.proxies.map(proxy => ({ value: proxy.id, label: `${proxy.label} (${proxy.kind === "socks5" ? "SOCKS5" : "HTTP"})` })),
  ]);
  // Hosts that already jump through this one would make a loop. The backend checks deeper chains.
  const jumpChoices = createMemo<SelectItem<string | null>[]>(() => [
    { value: null, label: "Add a jump host" },
    ...ssh.file.hosts
      .filter(host => host.id !== draft.id && !draft.jumps.includes(host.id) && !(draft.id && host.jumps.includes(draft.id)))
      .map(host => ({ value: host.id, label: `${host.label} (${host.host})` })),
  ]);

  const routeHosts = createMemo(() => {
    const [first, ...rest] = draft.jumps;
    const self = { ...unwrap(draft), label: draft.label.trim() || "new host" } as SshHost;
    const before = first ? ssh.route(first) : [];
    return [...before, ...rest.flatMap(id => ssh.host(id) ?? []), self];
  });
  const routeProxy = createMemo(() => ssh.proxy(draft.proxyId) ?? (draft.jumps[0] ? ssh.routeProxy(draft.jumps[0]) : undefined));
  const inheritedVpn = createMemo(() => (draft.jumps[0] ? useVpnState.profile(ssh.routeVpnId(draft.jumps[0])) : undefined));
  const routeVpn = createMemo(() => useVpnState.profile(draft.vpnId) ?? inheritedVpn());
  const vpnItems = createMemo<SelectItem<string | null>[]>(() => [
    { value: null, label: inheritedVpn() ? `From the first jump (${inheritedVpn()!.label})` : "None" },
    ...useVpnState.file.profiles.map(profile => ({ value: profile.id, label: profile.label })),
    { value: IMPORT_VPN, label: "Import a VPN…" },
  ]);
  const vpnHint = createMemo(() => (routeVpn()
    ? "Fran opens its own tunnel when you connect, only for this host. A proxy is reached through it too."
    : undefined));

  function pickVpn(id: string | null) {
    if (id !== IMPORT_VPN) {
      setDraft("vpnId", id);
      return;
    }
    void useVpnEditorState.importFile(profile => setDraft("vpnId", profile.id));
  }
  const snippetItems = createMemo<SelectItem<string | null>[]>(() => [
    { value: null, label: "Nothing" },
    ...useSnippetsState.snippets.map(snippet => ({ value: snippet.id, label: snippet.label })),
  ]);

  function addJump() {
    const id = jumpPick();
    if (!id) return;
    setDraft("jumps", jumps => [...jumps, id]);
    setJumpPick(null);
  }

  function moveJump(index: number, by: number) {
    setDraft("jumps", produce(jumps => {
      const [moved] = jumps.splice(index, 1);
      jumps.splice(index + by, 0, moved);
    }));
  }

  function customIdentityAuth(): IdentityAuth {
    switch (customAuth()) {
      case "key": {
        const keyId = customKey();
        if (!keyId) throw new Error("Pick a key, or add one on the Secrets page first");
        return { kind: "key", keyId };
      }
      case "agent":
        return { kind: "agent", socket: "" };
      case "password":
        return { kind: "password" };
    }
  }

  async function save() {
    const request = editor.request();
    if (!request) return;
    setSaving(true);
    let createdIdentity: string | null = null;
    try {
      const host: SshHost = JSON.parse(JSON.stringify(unwrap(draft)));
      if (customLogin()) {
        const user = customUser().trim();
        if (!user) throw new Error("Enter the user to log in as");
        const identity = await ssh.saveIdentity({
          id: "",
          label: `${user} (${host.label.trim() || host.host.trim() || "new host"})`,
          user,
          auth: customIdentityAuth(),
        });
        createdIdentity = identity.id;
        if (identity.auth.kind === "password" && customPassword()) {
          await safeInvoke("set_owner_secret", { owner: { kind: "identity", id: identity.id }, slot: "password", value: customPassword() });
        }
        host.identityId = identity.id;
      }

      const saved = await ssh.saveHost(host);
      pushToast(isNew() ? `Added ${saved.label}` : `Saved ${saved.label}`, "success", 2500);
      request.onSaved?.(saved);
      editor.close();
    } catch (error) {
      if (createdIdentity) await ssh.deleteIdentity(createdIdentity).catch(() => undefined);
      pushError(error);
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    const confirmed = await confirm({
      title: `Delete ${draft.label}?`,
      message: "The host is removed. Its identity, keys and trusted host key stay on the Secrets page.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!confirmed) return;
    try {
      await ssh.deleteHost(draft.id);
      editor.close();
    } catch (error) {
      pushError(error);
    }
  }

  return (
    <Modal
      show={editor.request() !== null}
      onHide={editor.close}
      title={title()}
      width={600}
      footer={
        <>
          <Show when={!isNew()}>
            <Button variant="ghost" class={styles.Delete} onClick={remove}>
              <Trash2 size={14} />
              Delete
            </Button>
          </Show>
          <div class={styles.Spacer} />
          <Button variant="subtle" onClick={editor.close}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={saving()}>
            {saveLabel()}
          </Button>
        </>
      }
    >
      <div class={styles.Editor}>
        <FieldRow>
          <Field label="Name" grow>
            <Input value={draft.label} onValue={value => setDraft("label", value)} placeholder="api-01" autofocus />
          </Field>
          <Field label="Group" grow>
            <SuggestInput
              class={editorStyles.GroupInput}
              value={draft.group ?? ""}
              suggestions={groups()}
              onCommit={value => setDraft("group", value || null)}
              placeholder="No group"
            />
          </Field>
        </FieldRow>
        <FieldRow>
          <Field label="Address" grow>
            <SecretInput path="host" refs={secretRefs} value={draft.host} onValue={value => setDraft("host", value)} placeholder="10.0.3.11 or server.example.com" />
          </Field>
          <Field label="Port" width={96}>
            <SecretInput path="port" refs={secretRefs} type="number" value={draft.port} onValue={value => setDraft("port", toPort(value))} />
          </Field>
        </FieldRow>
        <Field label="Color">
          <ColorSwatches value={draft.color} onChange={color => setDraft("color", color)} />
        </Field>
        <SyncField itemKey={syncKey()} label={draft.label} category="sshHosts" />

        <section class={styles.Section}>
          <h3><User size={14} />Login</h3>
          <Field label="Identity" hint={identityHint()}>
            <Select value={draft.identityId ?? CUSTOM_LOGIN} items={identityItems()} onChange={id => setDraft("identityId", id)} />
          </Field>
          <Show when={customLogin()}>
            <FieldRow>
              <Field label="User" grow>
                <Input value={customUser()} onValue={setCustomUser} placeholder="deploy" />
              </Field>
              <Field label="Log in with">
                <SegmentedControl
                  value={customAuth()}
                  onChange={setCustomAuth}
                  options={[
                    { value: "key", label: "Key" },
                    { value: "agent", label: "Agent" },
                    { value: "password", label: "Password" },
                  ]}
                />
              </Field>
            </FieldRow>
            <Switch>
              <Match when={customAuth() === "key"}>
                <Field label="Key" hint={keyHint()}>
                  <Select value={customKey()} items={keyItems()} onChange={setCustomKey} placeholder="Pick a key" disabled={keyItems().length === 0} />
                </Field>
              </Match>
              <Match when={customAuth() === "password"}>
                <Field label="Password" hint="Saved to the vault. Leave empty to be asked when connecting.">
                  <Input type="password" value={customPassword()} onValue={setCustomPassword} />
                </Field>
              </Match>
            </Switch>
          </Show>
        </section>

        <section class={styles.Section}>
          <h3><Link size={14} />Route</h3>
          <p class={styles.Description}>
            Jump hosts are saved hosts this one is reached through, in order. The first one is reached through its own route.
            Each hop checks its own host key and logs in with its own identity.
          </p>
          <div class={styles.Chain}>
            <For each={draft.jumps}>
              {(id, index) => {
                const jump = createMemo(() => ssh.host(id));
                const jumpAddress = createMemo(() => {
                  const host = jump();
                  return host ? ssh.address(host) : "";
                });
                return (
                  <div class={styles.ChainItem}>
                    <span class={styles.Step}>{index() + 1}</span>
                    <span class={styles.ChainIcon} style={{ "--row-color": jump()?.color ?? "var(--accent)" }}><Server size={12} /></span>
                    <span class={styles.ChainName}>{jump()?.label ?? "Deleted host"}</span>
                    <span class={styles.ChainAddress}>{jumpAddress()}</span>
                    <Button icon size="sm" tooltip="Move up" disabled={index() === 0} onClick={() => moveJump(index(), -1)}>
                      <ArrowUp size={14} />
                    </Button>
                    <Button icon size="sm" tooltip="Move down" disabled={index() === draft.jumps.length - 1} onClick={() => moveJump(index(), 1)}>
                      <ArrowDown size={14} />
                    </Button>
                    <Button icon size="sm" tooltip="Remove" onClick={() => setDraft("jumps", jumps => jumps.filter((_, at) => at !== index()))}>
                      <X size={14} />
                    </Button>
                  </div>
                );
              }}
            </For>
            <Show when={jumpChoices().length > 1}>
              <div class={styles.AddJump}>
                <Select class={styles.Grow} value={jumpPick()} items={jumpChoices()} onChange={setJumpPick} />
                <Button variant="subtle" disabled={!jumpPick()} onClick={addJump}>
                  <Plus size={14} />
                  Add
                </Button>
              </div>
            </Show>
          </div>
          <Field label="VPN for the first hop" hint={vpnHint()}>
            <Select value={draft.vpnId} items={vpnItems()} onChange={pickVpn} />
          </Field>
          <Field label="Proxy for the first hop">
            <Select value={draft.proxyId} items={proxyItems()} onChange={id => setDraft("proxyId", id)} />
          </Field>
          <RoutePreview hosts={routeHosts()} proxy={routeProxy()} vpn={routeVpn()} />
        </section>

        <section class={styles.Section}>
          <h3><SlidersHorizontal size={14} />Advanced</h3>
          <div class={styles.SwitchRow}>
            <div class={styles.SwitchText}>
              <span class={styles.SwitchLabel}>Agent forwarding</span>
              <span class={styles.SwitchHint}>Lets this server use your SSH agent while a terminal is open.</span>
            </div>
            <Toggle checked={draft.agentForwarding} onChange={value => setDraft("agentForwarding", value)} />
          </div>
          <Show when={draft.agentForwarding}>
            <Note tone="warning">
              Anyone with root on <b>{draft.label.trim() || "this host"}</b> can log in to other servers as you while a terminal is open.
              Only turn this on for servers you control.
            </Note>
          </Show>
          <div class={styles.SwitchRow}>
            <div class={styles.SwitchText}>
              <span class={styles.SwitchLabel}>Let this server write to the clipboard</span>
              <span class={styles.SwitchHint}>For copying from tmux or vim through OSC 52. The server can't read your clipboard.</span>
            </div>
            <Toggle checked={draft.clipboardWrite} onChange={value => setDraft("clipboardWrite", value)} />
          </div>
          <FieldRow>
            <Field label="Keepalive" grow>
              <Select value={draft.keepaliveSecs} items={KEEPALIVE} onChange={secs => setDraft("keepaliveSecs", secs)} />
            </Field>
            <Field label="Run on connect" grow hint="Typed at the prompt after login, without pressing Enter.">
              <Select value={draft.startupSnippetId} items={snippetItems()} onChange={id => setDraft("startupSnippetId", id)} />
            </Field>
          </FieldRow>
        </section>
      </div>
    </Modal>
  );
}

export default HostEditor;
