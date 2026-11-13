import hostStyles from "../HostEditor/HostEditor.module.scss";
import formStyles from "@core/databases/shared/ConnectionForm.module.scss";
import editorStyles from "@core/pages/Home/ConnectionEditor/ConnectionEditor.module.scss";
import styles from "./VpnEditor.module.scss";
import { For, Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { createStore, produce, reconcile, unwrap } from "solid-js/store";
import { ArrowDown, ArrowUp, FileText, KeyRound, Monitor, Plus, Server, ShieldCheck, Trash2, User, X } from "@core/icons";
import { CertSummary, SecretRefs, TlsWrap, VerifyNameKind, VpnAuth, VpnProfile, VpnProto } from "@core/types";
import { PendingSecret, SecretEditor } from "@core/databases/types";
import { safeInvoke } from "@core/helpers/safeInvoke";
import useVpnEditorState from "@core/states/vpnEditorState";
import useVpnState from "@core/states/vpnState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import Modal from "../Modal/Modal";
import Button from "../Button/Button";
import Field, { FieldRow } from "../Field/Field";
import Input from "../Input/Input";
import SecretInput from "../SecretInput/SecretInput";
import Select, { SelectItem } from "../Select/Select";
import SegmentedControl from "../SegmentedControl/SegmentedControl";
import SuggestInput from "../SuggestInput/SuggestInput";
import ColorSwatches from "../ColorSwatches/ColorSwatches";
import SecretField from "../SecretField/SecretField";
import Toggle from "../Switch/Switch";
import Note from "../Note/Note";
import FilePathInput from "../FilePathInput/FilePathInput";
import WireGuardFields, { WIREGUARD_PORT } from "./WireGuardFields";
import { toPort } from "@core/databases/shared/fields";

type TlsWrapKind = TlsWrap["kind"];

const PROTOS: SelectItem<VpnProto>[] = [
  { value: "udp", label: "UDP" },
  { value: "tcp", label: "TCP" },
];

const TLS_WRAPS: SelectItem<TlsWrapKind>[] = [
  { value: "none", label: "None" },
  { value: "auth", label: "tls-auth" },
  { value: "crypt", label: "tls-crypt" },
  { value: "cryptV2", label: "tls-crypt-v2" },
];

const DIRECTIONS: SelectItem<number | null>[] = [
  { value: null, label: "No direction" },
  { value: 1, label: "1 (client)" },
  { value: 0, label: "0" },
];

const NAME_KINDS: SelectItem<VerifyNameKind>[] = [
  { value: "name", label: "Common name" },
  { value: "namePrefix", label: "Name starts with" },
  { value: "subject", label: "Whole subject" },
];

const OPENVPN_PORT = 1194;

const KINDS = [
  { value: "openVpn" as const, label: "OpenVPN" },
  { value: "wireGuard" as const, label: "WireGuard" },
];

function blankProfile(): VpnProfile {
  return {
    id: "",
    label: "",
    group: null,
    color: null,
    kind: "openVpn",
    remotes: [{ host: "", port: OPENVPN_PORT, proto: "udp" }],
    remoteRandom: false,
    auth: "cert",
    user: "",
    challenge: { kind: "none" },
    ca: "",
    cert: "",
    keyKind: null,
    verifyName: null,
    peerFingerprints: [],
    requireServerCert: true,
    tlsWrap: { kind: "none" },
    ciphers: [],
    fallbackCipher: null,
    authDigest: null,
    tlsVersionMin: null,
    renegSec: null,
    compress: "off",
    routeAll: "followServer",
    useVpnDns: true,
    needsSystem: [],
    systemOptions: [],
    pkcs11Provider: null,
    imported: null,
    wireGuard: {
      publicKey: null,
      peerPublicKey: "",
      allowedIps: ["0.0.0.0/0", "::/0"],
      addresses: [],
      dns: [],
      searchDomains: [],
      mtu: null,
      keepaliveSecs: null,
    },
  };
}

function tlsWrapOf(kind: TlsWrapKind, previous: TlsWrap): TlsWrap {
  if (kind === "auth") return { kind, direction: previous.kind === "auth" ? previous.direction : 1 };
  return { kind } as TlsWrap;
}

function CertList(props: { certs: CertSummary[] }) {
  return (
    <For each={props.certs}>
      {cert => (
        <span class={styles.Cert}>
          <ShieldCheck size={12} />
          <span class={styles.CertName}>{cert.subject}</span>
          <span class={styles.CertDate}>until {cert.notAfter}</span>
        </span>
      )}
    </For>
  );
}

function VpnEditor() {
  const editor = useVpnEditorState;
  const vpn = useVpnState;
  const { confirm } = usePromptState;
  const { pushToast, pushError } = useToastState;

  const [draft, setDraft] = createStore<VpnProfile>(blankProfile());
  const [pending, setPending] = createStore<Record<string, PendingSecret>>({});
  const [stored, setStored] = createSignal<string[]>([]);
  const [fingerprints, setFingerprints] = createSignal("");
  const [certs, setCerts] = createSignal<{ ca: CertSummary[], cert: CertSummary[] }>({ ca: [], cert: [] });
  const [saving, setSaving] = createSignal(false);
  const [generate, setGenerate] = createSignal(false);

  createEffect(on(editor.request, request => {
    if (!request) return;
    const initial: VpnProfile = request.profile ? JSON.parse(JSON.stringify(unwrap(request.profile))) : blankProfile();
    setDraft(reconcile(initial));
    setPending(reconcile({}));
    setGenerate(false);
    setFingerprints(initial.peerFingerprints.join("\n"));
    setStored([]);
    if (initial.id) {
      safeInvoke("get_owner_secrets", { owner: { kind: "vpn", id: initial.id } }).then(setStored).catch(() => setStored([]));
    }
  }));

  createEffect(on(() => [draft.ca, draft.cert] as const, ([ca, cert]) => {
    if (!editor.request()) return;
    safeInvoke("describe_vpn_certificates", { ca, cert }).then(setCerts).catch(() => setCerts({ ca: [], cert: [] }));
  }));

  const secrets: SecretEditor = {
    isStored: slot => stored().includes(slot),
    pending: slot => pending[slot],
    setPending: (slot, value) => setPending(slot, value),
    owner: () => (draft.id ? { kind: "vpn", id: draft.id } : null),
    refs: {
      get: key => draft.secretRefs?.[key],
      set: (key, secretId) => setDraft(produce(profile => {
        const refs = profile.secretRefs ??= {};
        if (secretId) refs[key] = secretId;
        else delete refs[key];
      })),
    },
  };
  const secretRefs = secrets.refs;

  // Server refs are keyed by position, so they move with their server. `from` is each server's old position.
  function moveRemoteRefs(from: number[]) {
    setDraft(produce(profile => {
      const old = profile.secretRefs ?? {};
      const next: SecretRefs = {};
      for (const [key, secretId] of Object.entries(old)) {
        if (!key.startsWith("remotes.")) next[key] = secretId;
      }
      from.forEach((oldIndex, index) => {
        for (const field of ["host", "port"]) {
          const secretId = old[`remotes.${oldIndex}.${field}`];
          if (secretId) next[`remotes.${index}.${field}`] = secretId;
        }
      });
      profile.secretRefs = next;
    }));
  }

  function removeRemote(index: number) {
    moveRemoteRefs(draft.remotes.map((_, at) => at).filter(at => at !== index));
    setDraft("remotes", items => items.filter((_, at) => at !== index));
  }

  const isNew = createMemo(() => !draft.id);
  const title = createMemo(() => (isNew() ? "New VPN" : `Edit ${editor.request()?.profile?.label ?? draft.label}`));
  const saveLabel = createMemo(() => (saving() ? "Saving" : isNew() ? "Add VPN" : "Save"));
  const groups = createMemo(() => [...new Set(vpn.file.profiles.flatMap(profile => (profile.group ? [profile.group] : [])))].sort());
  const usesCert = createMemo(() => draft.auth !== "userPass");
  const usesPassword = createMemo(() => draft.auth !== "cert");
  const hasChallenge = createMemo(() => draft.challenge.kind === "static");
  const challengeText = createMemo(() => (draft.challenge.kind === "static" ? draft.challenge.text : ""));
  const pendingKey = createMemo(() => pending.key);
  const keySaved = createMemo(() => draft.keyKind !== null && pendingKey() !== null);
  const keyStatus = createMemo(() => (keySaved() ? `${draft.keyKind} key in the vault` : "No key saved"));
  const tlsKeySaved = createMemo(() => stored().includes("tlsKey") && pending.tlsKey === undefined);
  const tlsKeyPlaceholder = createMemo(() => (tlsKeySaved()
    ? "Saved in the vault. Paste a new key to replace it."
    : "-----BEGIN OpenVPN Static key V1-----"));
  const authDirection = createMemo(() => (draft.tlsWrap.kind === "auth" ? draft.tlsWrap.direction : null));
  const keyText = createMemo(() => {
    const value = pendingKey();
    return typeof value === "string" ? value : "";
  });
  const tlsKeyText = createMemo(() => (typeof pending.tlsKey === "string" ? pending.tlsKey : ""));
  const verifyText = createMemo(() => draft.verifyName?.name ?? "");
  const verifyKind = createMemo<VerifyNameKind>(() => draft.verifyName?.kind ?? "name");
  const imported = createMemo(() => (editor.request()?.imported ?? false) || draft.imported !== null);
  const importInfo = createMemo(() => draft.imported);
  const sendsAllTraffic = createMemo(() => draft.routeAll === "followServer");
  const systemOption = (name: string) => draft.systemOptions.find(option => option[0] === name)?.[1] ?? null;
  const smartcardId = createMemo(() => systemOption("pkcs11-id"));
  const certStore = createMemo(() => systemOption("cryptoapicert"));
  const keyElsewhere = createMemo(() => smartcardId() !== null || certStore() !== null);
  const wireGuard = createMemo(() => draft.kind === "wireGuard");
  // Keyed on the request, so the WireGuard fields start over for each profile opened.
  const wireGuardRequest = createMemo(() => (wireGuard() ? editor.request() : null));
  const routeAllHint = createMemo(() => (wireGuard()
    ? "When the allowed IPs include 0.0.0.0/0 or ::/0. Off keeps only the narrower allowed IPs on it."
    : "When the server asks for it. Off keeps only the VPN's own networks on it. If the VPN has no IPv6, IPv6 traffic still goes out the normal way unless the server pushes block-ipv6."));
  const importHint = createMemo(() => (wireGuard()
    ? "Fran keeps what it needs. Scripts in the file never run."
    : "Fran keeps what it needs and never hands the original file to OpenVPN."));

  function setKind(kind: VpnProfile["kind"]) {
    const port = kind === "wireGuard" ? WIREGUARD_PORT : OPENVPN_PORT;
    const first = draft.remotes[0];
    setDraft("kind", kind);
    setDraft("remotes", [{ host: first?.host ?? "", port, proto: "udp" }]);
    moveRemoteRefs([0]);
    secretRefs?.set("remotes.0.port", null);
  }

  function updateRemote(index: number, change: (remote: VpnProfile["remotes"][number]) => void) {
    setDraft("remotes", index, produce(change));
  }

  function moveRemote(index: number, by: number) {
    const from = draft.remotes.map((_, at) => at);
    const [moved] = from.splice(index, 1);
    from.splice(index + by, 0, moved);
    moveRemoteRefs(from);
    setDraft("remotes", produce(remotes => {
      const [moved] = remotes.splice(index, 1);
      remotes.splice(index + by, 0, moved);
    }));
  }

  function setChallenge(on: boolean) {
    setDraft("challenge", on ? { kind: "static", echo: true, text: "Enter your one-time code" } : { kind: "none" });
  }

  // A generated key leaves the editor open afterwards, so its public key can be copied for the server.
  async function writeWireGuardSecrets(id: string): Promise<boolean> {
    const key = pending.private;
    let generated = false;
    if (generate()) {
      setDraft("wireGuard", "publicKey", (await vpn.generateWireGuardKey(id)).wireGuard.publicKey);
      generated = true;
    } else if (typeof key === "string" && key.trim()) {
      setDraft("wireGuard", "publicKey", (await vpn.setWireGuardKey(id, key)).wireGuard.publicKey);
    }
    const preshared = pending.presharedKey;
    if (typeof preshared === "string" && preshared.trim()) await safeInvoke("set_vpn_preshared_key", { id, key: preshared });
    if (preshared === null) await safeInvoke("set_vpn_preshared_key", { id, key: "" });
    setPending(reconcile({}));
    setGenerate(false);
    return generated;
  }

  async function writeSecrets(id: string) {
    const owner = { kind: "vpn", id } as const;
    const password = pending.password;
    if (typeof password === "string") await safeInvoke("set_owner_secret", { owner, slot: "password", value: password });
    if (password === null) await safeInvoke("clear_owner_secret", { owner, slot: "password" });
    const key = pending.key;
    if (typeof key === "string" && key.trim()) setDraft("keyKind", (await vpn.setKey(id, key)).keyKind);
    if (key === null) setDraft("keyKind", (await vpn.clearKey(id)).keyKind);
    const tlsKey = pending.tlsKey;
    if (typeof tlsKey === "string" && tlsKey.trim()) await safeInvoke("set_vpn_tls_key", { id, text: tlsKey });
    setPending(reconcile({}));
  }

  async function save() {
    const request = editor.request();
    if (!request) return;
    setSaving(true);
    try {
      const profile: VpnProfile = JSON.parse(JSON.stringify(unwrap(draft)));
      profile.peerFingerprints = fingerprints().split("\n").map(line => line.trim()).filter(Boolean);
      const saved = await vpn.save(profile);
      const added = isNew();
      // Kept, so a key that fails below doesn't add the profile a second time.
      setDraft("id", saved.id);
      let generated = false;
      if (wireGuard()) generated = await writeWireGuardSecrets(saved.id);
      else await writeSecrets(saved.id);
      pushToast(added ? `Added ${saved.label}` : `Saved ${saved.label}`, "success", 2500);
      const current = vpn.profile(saved.id) ?? saved;
      request.onSaved?.(current);
      if (generated) {
        pushToast("Give the server the new public key", "info", 4000);
        editor.open(current, request.onSaved);
      } else {
        editor.close();
      }
    } catch (error) {
      pushError(error);
    } finally {
      setSaving(false);
    }
  }

  async function remove() {
    const confirmed = await confirm({
      title: `Delete ${draft.label}?`,
      message: "The profile, its key and its saved password are removed.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!confirmed) return;
    try {
      await vpn.remove(draft.id);
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
      width={640}
      footer={
        <>
          <Show when={!isNew()}>
            <Button variant="ghost" class={hostStyles.Delete} onClick={remove}>
              <Trash2 size={14} />
              Delete
            </Button>
          </Show>
          <div class={hostStyles.Spacer} />
          <Button variant="subtle" onClick={editor.close}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={saving()}>{saveLabel()}</Button>
        </>
      }
    >
      <div class={hostStyles.Editor}>
        <Show when={isNew() && !imported()}>
          <Field label="Type">
            <SegmentedControl<VpnProfile["kind"]> value={draft.kind} onChange={setKind} options={KINDS} />
          </Field>
        </Show>

        <Show when={draft.needsSystem.length > 0}>
          <Note tone="warning">
            This VPN only works while it's on for the whole computer through the installed OpenVPN, also when Fran's VPN service is set
            up. {draft.needsSystem.join(". ")}.
          </Note>
        </Show>

        <FieldRow>
          <Field label="Name" grow>
            <Input value={draft.label} onValue={value => setDraft("label", value)} placeholder="Office" autofocus />
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
        <Field label="Color">
          <ColorSwatches value={draft.color} onChange={color => setDraft("color", color)} />
        </Field>

        <Show when={wireGuardRequest()} keyed>
          {_request => (
            <WireGuardFields
              draft={draft}
              setDraft={setDraft}
              pending={pending}
              setPending={setPending}
              stored={stored()}
              generate={generate()}
              setGenerate={setGenerate}
            />
          )}
        </Show>

        <Show when={!wireGuard()}>
        <section class={hostStyles.Section}>
          <h3><Server size={14} />Servers</h3>
          <p class={hostStyles.Description}>Tried in order until one answers. The server's own name is looked up on this computer.</p>
          <div class={hostStyles.Chain}>
            <For each={draft.remotes}>
              {(remote, index) => (
                <div class={styles.Remote}>
                  <SecretInput
                    path={`remotes.${index()}.host`}
                    refs={secretRefs}
                    class={hostStyles.Grow}
                    value={remote.host}
                    onValue={value => updateRemote(index(), item => { item.host = value; })}
                    placeholder="vpn.example.com"
                  />
                  <SecretInput
                    path={`remotes.${index()}.port`}
                    refs={secretRefs}
                    class={styles.Port}
                    type="number"
                    value={remote.port}
                    onValue={value => updateRemote(index(), item => { item.port = toPort(value); })}
                  />
                  <Select class={styles.Proto} value={remote.proto} items={PROTOS} onChange={proto => updateRemote(index(), item => { item.proto = proto; })} />
                  <Button icon size="sm" tooltip="Move up" disabled={index() === 0} onClick={() => moveRemote(index(), -1)}>
                    <ArrowUp size={14} />
                  </Button>
                  <Button icon size="sm" tooltip="Move down" disabled={index() === draft.remotes.length - 1} onClick={() => moveRemote(index(), 1)}>
                    <ArrowDown size={14} />
                  </Button>
                  <Button icon size="sm" tooltip="Remove" disabled={draft.remotes.length === 1} onClick={() => removeRemote(index())}>
                    <X size={14} />
                  </Button>
                </div>
              )}
            </For>
            <div class={styles.RemoteActions}>
              <Button size="sm" variant="subtle" onClick={() => setDraft("remotes", items => [...items, { host: "", port: 1194, proto: "udp" }])}>
                <Plus size={14} />
                Add server
              </Button>
              <Show when={draft.remotes.length > 1}>
                <Toggle checked={draft.remoteRandom} onChange={value => setDraft("remoteRandom", value)} label="Random order" />
              </Show>
            </div>
          </div>
        </section>

        <section class={hostStyles.Section}>
          <h3><User size={14} />Login</h3>
          <Field label="Log in with">
            <SegmentedControl<VpnAuth>
              value={draft.auth}
              onChange={auth => setDraft("auth", auth)}
              options={[
                { value: "cert", label: "Certificate" },
                { value: "userPass", label: "User and password" },
                { value: "certAndUserPass", label: "Both" },
              ]}
            />
          </Field>
          <Show when={usesPassword()}>
            <FieldRow>
              <Field label="User" grow>
                <SecretInput path="user" refs={secretRefs} value={draft.user} onValue={value => setDraft("user", value)} />
              </Field>
              <Field label="Password" grow>
                <SecretField slot="password" secrets={secrets} />
              </Field>
            </FieldRow>
            <div class={hostStyles.SwitchRow}>
              <div class={hostStyles.SwitchText}>
                <span class={hostStyles.SwitchLabel}>Asks for a one-time code</span>
                <span class={hostStyles.SwitchHint}>Fran asks for it on every connect and never saves it.</span>
              </div>
              <Toggle checked={hasChallenge()} onChange={setChallenge} />
            </div>
            <Show when={hasChallenge()}>
              <Field label="Prompt" hint="Shown when Fran asks for the code. The server checks it with the password.">
                <Input
                  value={challengeText()}
                  onValue={value => setDraft("challenge", challenge => (challenge.kind === "static" ? { ...challenge, text: value } : challenge))}
                />
              </Field>
            </Show>
          </Show>
          <Show when={usesCert()}>
            <Field label="Client certificate">
              <textarea
                class={formStyles.Textarea}
                spellcheck={false}
                value={draft.cert}
                onInput={event => setDraft("cert", event.currentTarget.value)}
                placeholder="-----BEGIN CERTIFICATE-----"
              />
              <CertList certs={certs().cert} />
            </Field>
            <Show when={certStore()}>
              {selector => (
                <Note tone="info">
                  The key is in the Windows certificate store ({selector()}). OpenVPN uses it from there while the VPN is on for this computer.
                </Note>
              )}
            </Show>
            <Show when={smartcardId()}>
              {id => (
                <Field
                  label="Smartcard library"
                  hint={`For smartcard ${id()}. It runs inside OpenVPN with admin rights, so only pick your card vendor's PKCS#11 library. The PIN is asked for each time.`}
                >
                  <FilePathInput
                    value={draft.pkcs11Provider ?? ""}
                    onValue={value => setDraft("pkcs11Provider", value.trim() ? value : null)}
                    placeholder="Choose the PKCS#11 library"
                    dialogTitle="Choose the smartcard library"
                  />
                </Field>
              )}
            </Show>
            <Show when={!keyElsewhere()}>
            <Field label="Client key" hint="Goes straight to the vault. Fran signs with it, OpenVPN never gets the key itself.">
              <div class={styles.KeyStatus}>
                <KeyRound size={14} class={keySaved() ? styles.Saved : undefined} />
                <span>{keyStatus()}</span>
                <Show when={keySaved()}>
                  <Button size="sm" variant="danger" onClick={() => setPending("key", null)}>Remove</Button>
                </Show>
                <Show when={pendingKey() === null}>
                  <span class={styles.Removed}>Removed on save</span>
                  <Button size="sm" onClick={() => setPending("key", undefined)}>Undo</Button>
                </Show>
              </div>
              <textarea
                class={formStyles.Textarea}
                spellcheck={false}
                value={keyText()}
                onInput={event => setPending("key", event.currentTarget.value || undefined)}
                placeholder="Paste a PEM private key to save a new one"
              />
            </Field>
            </Show>
          </Show>
        </section>

        <section class={hostStyles.Section}>
          <h3><ShieldCheck size={14} />Server check</h3>
          <Field label="CA certificate" hint="Fran refuses a server it can't check against the CA or a fingerprint.">
            <textarea
              class={formStyles.Textarea}
              spellcheck={false}
              value={draft.ca}
              onInput={event => setDraft("ca", event.currentTarget.value)}
              placeholder="-----BEGIN CERTIFICATE-----"
            />
            <CertList certs={certs().ca} />
          </Field>
          <div class={hostStyles.SwitchRow}>
            <div class={hostStyles.SwitchText}>
              <span class={hostStyles.SwitchLabel}>Check that it's a server certificate</span>
              <span class={hostStyles.SwitchHint}>Stops another client of the same CA from posing as the server.</span>
            </div>
            <Toggle checked={draft.requireServerCert} onChange={value => setDraft("requireServerCert", value)} />
          </div>
          <Show when={!draft.requireServerCert}>
            <Note tone="warning">Anyone with a client certificate from this CA could pose as the VPN server.</Note>
          </Show>
          <FieldRow>
            <Field label="Name to match" grow>
              <Input
                value={verifyText()}
                onValue={value => setDraft("verifyName", value.trim() ? { name: value, kind: verifyKind() } : null)}
                placeholder="Any name"
              />
            </Field>
            <Field label="Match" width={170}>
              <Select
                value={verifyKind()}
                items={NAME_KINDS}
                disabled={draft.verifyName === null}
                onChange={kind => setDraft("verifyName", current => (current ? { ...current, kind } : current))}
              />
            </Field>
          </FieldRow>
          <Field label="Server fingerprints" hint="SHA-256, one per line. Works with or without a CA.">
            <textarea
              class={formStyles.Textarea}
              spellcheck={false}
              value={fingerprints()}
              onInput={event => setFingerprints(event.currentTarget.value)}
              placeholder="AB:CD:..."
            />
          </Field>
          <FieldRow>
            <Field label="TLS wrapping" grow>
              <Select value={draft.tlsWrap.kind} items={TLS_WRAPS} onChange={kind => setDraft("tlsWrap", tlsWrapOf(kind, draft.tlsWrap))} />
            </Field>
            <Show when={draft.tlsWrap.kind === "auth"}>
              <Field label="Key direction" width={170}>
                <Select value={authDirection()} items={DIRECTIONS} onChange={direction => setDraft("tlsWrap", { kind: "auth", direction })} />
              </Field>
            </Show>
          </FieldRow>
          <Show when={draft.tlsWrap.kind !== "none"}>
            <Field label="TLS key" hint="Goes straight to the vault.">
              <textarea
                class={formStyles.Textarea}
                spellcheck={false}
                value={tlsKeyText()}
                onInput={event => setPending("tlsKey", event.currentTarget.value || undefined)}
                placeholder={tlsKeyPlaceholder()}
              />
            </Field>
          </Show>
        </section>
        </Show>

        <section class={hostStyles.Section}>
          <h3><Monitor size={14} />For this computer</h3>
          <p class={hostStyles.Description}>Only used while the VPN is on for the whole computer. Fran's own tunnels carry only Fran's connections.</p>
          <div class={hostStyles.SwitchRow}>
            <div class={hostStyles.SwitchText}>
              <span class={hostStyles.SwitchLabel}>Send all traffic through the VPN</span>
              <span class={hostStyles.SwitchHint}>{routeAllHint()}</span>
            </div>
            <Toggle checked={sendsAllTraffic()} onChange={value => setDraft("routeAll", value ? "followServer" : "vpnNetworksOnly")} />
          </div>
          <div class={hostStyles.SwitchRow}>
            <div class={hostStyles.SwitchText}>
              <span class={hostStyles.SwitchLabel}>Use the VPN's DNS</span>
              <span class={hostStyles.SwitchHint}>
                Fran's own connections through it look names up there, and so does the computer. On Linux the computer switches with Fran's
                VPN service and systemd-resolved, or with OpenVPN 2.7.
              </span>
            </div>
            <Toggle checked={draft.useVpnDns} onChange={value => setDraft("useVpnDns", value)} />
          </div>
        </section>

        <Show when={imported() && importInfo()}>
          {info => (
            <section class={hostStyles.Section}>
              <h3><FileText size={14} />From {info().fileName}</h3>
              <p class={hostStyles.Description}>{importHint()}</p>
              <Show when={info().used.length > 0}>
                <div class={styles.Options}>
                  <span class={styles.OptionsTitle}>Used</span>
                  <span class={styles.Used}>{info().used.join(", ")}</span>
                </div>
              </Show>
              <For each={[
                { title: "Left out for safety", notes: info().dropped, tone: styles.Dropped },
                { title: "Needs the installed OpenVPN", notes: info().systemOnly, tone: styles.Dropped },
                { title: "Not needed", notes: info().ignored, tone: "" },
              ]}>
                {group => (
                  <Show when={group.notes.length > 0}>
                    <div class={styles.Options}>
                      <span class={styles.OptionsTitle}>{group.title}</span>
                      <ul class={styles.NoteList}>
                        <For each={group.notes}>
                          {item => (
                            <li>
                              <code class={group.tone}>{item.option}</code>
                              <span>{item.reason}</span>
                            </li>
                          )}
                        </For>
                      </ul>
                    </div>
                  </Show>
                )}
              </For>
            </section>
          )}
        </Show>
      </div>
    </Modal>
  );
}

export default VpnEditor;
