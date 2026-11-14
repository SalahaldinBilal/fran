import styles from "./Secrets.module.scss";
import formStyles from "@core/databases/shared/ConnectionForm.module.scss";
import { For, Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { save } from "@tauri-apps/plugin-dialog";
import { Copy, Download, FileKey, Info, KeyRound, Lock, Pencil, Plus, Trash2, Upload } from "@core/icons";
import useSshState from "@core/states/sshState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { copyText } from "@core/helpers/clipboard";
import { withUserCheck } from "@core/helpers/revealSecret";
import { createOwnerSecrets } from "@core/helpers/ownerSecrets";
import SecretField from "@core/components/SecretField/SecretField";
import { KeyAlgorithm, KeyMeta } from "@core/types";
import Modal from "@core/components/Modal/Modal";
import Button from "@core/components/Button/Button";
import Field from "@core/components/Field/Field";
import Input from "@core/components/Input/Input";
import SegmentedControl from "@core/components/SegmentedControl/SegmentedControl";
import FilePathInput from "@core/components/FilePathInput/FilePathInput";
import EmptyState from "@core/components/EmptyState/EmptyState";
import { tooltip } from "@core/components/Tooltip/Tooltip";

const COLUMNS = "minmax(180px, 1.3fr) 100px minmax(160px, 2fr) 90px 120px";

const ALGORITHM_HINTS: Record<KeyAlgorithm, string> = {
  ed25519: "Short, fast, and accepted by every OpenSSH from 6.5 on. The right pick unless a server is very old.",
  ecdsaP256: "For servers that require NIST curves.",
  rsa4096: "Only for old servers that don't know Ed25519. Takes a few seconds to make.",
};

function GenerateKeyModal(props: { show: boolean, onClose: () => void, onCreated: (key: KeyMeta) => void }) {
  const { pushError } = useToastState;
  const [label, setLabel] = createSignal("");
  const [algorithm, setAlgorithm] = createSignal<KeyAlgorithm>("ed25519");
  const [comment, setComment] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const hint = createMemo(() => ALGORITHM_HINTS[algorithm()]);
  const buttonLabel = createMemo(() => (busy() ? "Generating" : "Generate"));
  const commentPlaceholder = createMemo(() => label() || "you@laptop");

  async function generate() {
    setBusy(true);
    try {
      const key = await safeInvoke("generate_key", { label: label(), algorithm: algorithm(), comment: comment() });
      useSshState.addKey(key);
      setLabel("");
      setComment("");
      props.onCreated(key);
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
      title="Generate key"
      width={440}
      footer={
        <>
          <Button variant="subtle" onClick={props.onClose}>Cancel</Button>
          <Button variant="primary" disabled={busy() || label().trim() === ""} onClick={generate}>{buttonLabel()}</Button>
        </>
      }
    >
      <div class={styles.Form}>
        <Field label="Name">
          <Input value={label()} onValue={setLabel} placeholder="work-laptop" autofocus />
        </Field>
        <Field label="Type" hint={hint()}>
          <SegmentedControl
            fill
            value={algorithm()}
            onChange={setAlgorithm}
            options={[
              { value: "ed25519", label: "Ed25519" },
              { value: "ecdsaP256", label: "ECDSA P-256" },
              { value: "rsa4096", label: "RSA 4096" },
            ]}
          />
        </Field>
        <Field label="Comment" hint="Added to the end of the public key so you can tell it apart in authorized_keys.">
          <Input value={comment()} onValue={setComment} placeholder={commentPlaceholder()} />
        </Field>
        <p class={styles.FormNote}>The key is made on this computer and goes straight into the vault.</p>
      </div>
    </Modal>
  );
}

function KeyReadyModal(props: { keyMeta: KeyMeta | null, onClose: () => void }) {
  const title = createMemo(() => `${props.keyMeta?.label ?? ""} is ready`);

  return (
    <Modal
      show={props.keyMeta !== null}
      onHide={props.onClose}
      title={title()}
      width={500}
      footer={
        <>
          <Button variant="subtle" onClick={() => copyText(props.keyMeta?.publicKey ?? "", "the public key")}>
            <Copy size={14} />
            Copy public key
          </Button>
          <Button variant="primary" onClick={props.onClose}>Done</Button>
        </>
      }
    >
      <div class={styles.Form}>
        <Field label="Public key" hint="Add this line to ~/.ssh/authorized_keys on each server that should accept the key.">
          <div class={styles.Public}>{props.keyMeta?.publicKey}</div>
        </Field>
        <Field label="Fingerprint">
          <div class={styles.Public}>{props.keyMeta?.fingerprint}</div>
        </Field>
      </div>
    </Modal>
  );
}

function ImportKeyModal(props: { show: boolean, onClose: () => void }) {
  const { pushToast, pushError } = useToastState;
  const [source, setSource] = createSignal<"paste" | "file">("paste");
  const [path, setPath] = createSignal("");
  const [text, setText] = createSignal("");
  const [label, setLabel] = createSignal("");
  const [mode, setMode] = createSignal<"vault" | "file">("vault");
  const [passphrase, setPassphrase] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const pasting = createMemo(() => source() === "paste");
  const toVault = createMemo(() => pasting() || mode() === "vault");
  const ready = createMemo(() => !busy() && (pasting() ? text().trim() !== "" : path().trim() !== ""));
  const labelPlaceholder = createMemo(() => (pasting() ? "Taken from the key's comment" : "Taken from the file name"));
  const modeNote = createMemo(() => {
    if (pasting()) return "The key goes straight into the vault, which is encrypted. Fran never shows it again, only its public half.";
    return mode() === "vault"
      ? "An unencrypted copy goes into the vault, which is encrypted itself. The file on disk isn't touched."
      : "Fran reads the file each time you connect and asks for its passphrase if it has one. Moving or deleting the file breaks the hosts that use it.";
  });

  async function run() {
    setBusy(true);
    try {
      const secret = toVault() && passphrase() ? passphrase() : null;
      const key = pasting()
        ? await safeInvoke("import_key_text", { text: text(), label: label(), passphrase: secret })
        : await safeInvoke("import_key", { path: path(), label: label(), toVault: toVault(), passphrase: secret });
      useSshState.addKey(key);
      pushToast(`Imported ${key.label}`, "success", 2500);
      setPath("");
      setText("");
      setLabel("");
      setPassphrase("");
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
      title="Import key"
      width={460}
      footer={
        <>
          <Button variant="subtle" onClick={props.onClose}>Cancel</Button>
          <Button variant="primary" disabled={!ready()} onClick={run}>Import</Button>
        </>
      }
    >
      <div class={styles.Form}>
        <Field label="Where from">
          <SegmentedControl
            fill
            value={source()}
            onChange={setSource}
            options={[
              { value: "paste", label: "Paste it" },
              { value: "file", label: "A file" },
            ]}
          />
        </Field>
        <Show
          when={pasting()}
          fallback={
            <Field label="Key file">
              <FilePathInput value={path()} onValue={setPath} placeholder="~/.ssh/id_ed25519" dialogTitle="Choose an SSH private key" />
            </Field>
          }
        >
          <Field label="Private key" hint="OpenSSH, PKCS#8 or PKCS#1 (PEM).">
            <textarea
              class={formStyles.Textarea}
              spellcheck={false}
              value={text()}
              onInput={event => setText(event.currentTarget.value)}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
            />
          </Field>
        </Show>
        <Field label="Name">
          <Input value={label()} onValue={setLabel} placeholder={labelPlaceholder()} />
        </Field>
        <Show when={!pasting()}>
          <Field label="Keep it">
            <SegmentedControl
              fill
              value={mode()}
              onChange={setMode}
              options={[
                { value: "vault", label: "Copy into the vault" },
                { value: "file", label: "Keep using the file" },
              ]}
            />
          </Field>
        </Show>
        <Show when={toVault()}>
          <Field label="Passphrase" hint="Only for keys that have one. It's used once to open the key and isn't saved.">
            <Input type="password" value={passphrase()} onValue={setPassphrase} />
          </Field>
        </Show>
        <p class={styles.FormNote}>{modeNote()}</p>
      </div>
    </Modal>
  );
}

function ExportKeyModal(props: { keyMeta: KeyMeta | null, onClose: () => void }) {
  const { pushToast, pushError } = useToastState;
  const [passphrase, setPassphrase] = createSignal("");
  const [again, setAgain] = createSignal("");
  const ready = createMemo(() => passphrase().length > 0 && passphrase() === again());
  const mismatch = createMemo(() => (again() !== "" && passphrase() !== again() ? "The passphrases don't match" : undefined));
  const title = createMemo(() => `Export ${props.keyMeta?.label ?? ""}`);

  function close() {
    setPassphrase("");
    setAgain("");
    props.onClose();
  }

  async function run() {
    const key = props.keyMeta;
    if (!key || !ready()) return;
    try {
      const path = await save({ title: `Save ${key.label}`, defaultPath: key.label.replace(/[^\w.-]+/g, "_") });
      if (!path) return;
      const exported = await withUserCheck(options => safeInvoke("export_key", { id: key.id, path, passphrase: passphrase(), options }));
      if (exported === null) return;
      pushToast(`Saved ${key.label} to ${path}`, "success", 4000);
      close();
    } catch (error) {
      pushError(error);
    }
  }

  return (
    <Modal
      show={props.keyMeta !== null}
      onHide={close}
      title={title()}
      width={440}
      footer={
        <>
          <Button variant="subtle" onClick={close}>Cancel</Button>
          <Button variant="danger" disabled={!ready()} onClick={run}>Choose file</Button>
        </>
      }
    >
      <div class={styles.Form}>
        <p class={styles.FormNote}>
          The private key is written to a file you pick, protected with a new passphrase.
          Anyone with that file and passphrase can log in wherever this key is trusted.
        </p>
        <Field label="Passphrase">
          <Input type="password" value={passphrase()} onValue={setPassphrase} autofocus />
        </Field>
        <Field label="Passphrase again" hint={mismatch()}>
          <Input type="password" value={again()} onValue={setAgain} />
        </Field>
      </div>
    </Modal>
  );
}

// A key file's passphrase: saved in the vault, taken from a secret, or asked for on connect.
function PassphraseModal(props: { keyMeta: KeyMeta | null, onClose: () => void }) {
  const ssh = useSshState;
  const { pushError } = useToastState;
  const secrets = createOwnerSecrets();
  const [busy, setBusy] = createSignal(false);
  const title = createMemo(() => `Passphrase for ${props.keyMeta?.label ?? ""}`);

  createEffect(on(() => props.keyMeta, key => {
    if (key) void secrets.reset({ kind: "key", id: key.id }, key.secretRefs);
  }));

  async function save() {
    const key = props.keyMeta;
    if (!key) return;
    setBusy(true);
    try {
      await ssh.setKeySecretRefs(key.id, secrets.refs.snapshot());
      await secrets.apply({ kind: "key", id: key.id });
      props.onClose();
    } catch (error) {
      pushError(error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      show={props.keyMeta !== null}
      onHide={props.onClose}
      title={title()}
      width={440}
      footer={
        <>
          <Button variant="subtle" onClick={props.onClose}>Cancel</Button>
          <Button variant="primary" disabled={busy()} onClick={save}>Save</Button>
        </>
      }
    >
      <div class={styles.Form}>
        <Field label="Passphrase" hint="Left empty, it's asked for when you connect.">
          <SecretField slot="passphrase" secrets={secrets.editor} />
        </Field>
      </div>
    </Modal>
  );
}

function KeysView() {
  const ssh = useSshState;
  const { confirm, askForText } = usePromptState;
  const { pushError } = useToastState;
  const [generating, setGenerating] = createSignal(false);
  const [importing, setImporting] = createSignal(false);
  const [ready, setReady] = createSignal<KeyMeta | null>(null);
  const [exporting, setExporting] = createSignal<KeyMeta | null>(null);
  const [passphraseFor, setPassphraseFor] = createSignal<KeyMeta | null>(null);

  const hasRsa = createMemo(() => ssh.file.keys.filter(key => key.algorithm === "RSA").map(key => key.label));

  function users(key: KeyMeta): string[] {
    return ssh.file.identities.flatMap(identity => (identity.auth.kind === "key" && identity.auth.keyId === key.id ? [identity.label] : []));
  }

  async function rename(key: KeyMeta) {
    const label = await askForText({ title: "Rename key", label: "Name", initial: key.label, confirmLabel: "Rename" });
    if (label) await ssh.renameKey(key.id, label).catch(pushError);
  }

  async function remove(key: KeyMeta) {
    const confirmed = await confirm({
      title: `Delete ${key.label}?`,
      message: key.storage.kind === "vault"
        ? "The private key is removed from the vault for good. Servers that only accept this key will refuse you."
        : "Fran forgets the key. The file on disk stays where it is.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (confirmed) await ssh.deleteKey(key.id).catch(pushError);
  }

  return (
    <>
      <div class={styles.Head}>
        <h2>SSH keys</h2>
        <Button variant="subtle" onClick={() => setImporting(true)}>
          <Upload size={14} />
          Import
        </Button>
        <Button variant="primary" onClick={() => setGenerating(true)}>
          <Plus size={14} />
          Generate key
        </Button>
      </div>
      <p class={styles.Description}>
        SSH keys used by your identities.
      </p>

      <div class={styles.List} style={{ "--columns": COLUMNS }}>
        <div class={styles.ListHead}><span>Name</span><span>Type</span><span>Fingerprint</span><span>Stored in</span><span /></div>
        <Show
          when={ssh.file.keys.length > 0}
          fallback={<div class={styles.Empty}><EmptyState icon={KeyRound} title="No keys yet" description="Generate one, or import a key file you already use." /></div>}
        >
          <For each={ssh.file.keys}>
            {key => {
              const usedBy = createMemo(() => users(key));
              const usedText = createMemo(() => (usedBy().length > 0 ? `Used by ${usedBy().join(", ")}` : "Not used yet"));
              const path = createMemo(() => (key.storage.kind === "file" ? key.storage.path : ""));
              return (
                <div class={styles.ListRow}>
                  <div class={styles.Name}>
                    <span class={styles.ItemIcon}><KeyRound size={15} /></span>
                    <span class={styles.NameText}><b>{key.label}</b><small>{usedText()}</small></span>
                  </div>
                  <span class={styles.Cell}>{key.algorithm}</span>
                  <span class={`${styles.Cell} ${styles.Mono}`} ref={element => tooltip(element, () => key.fingerprint)}>{key.fingerprint}</span>
                  <span class={styles.Cell}>
                    <Show
                      when={key.storage.kind === "file"}
                      fallback={<span class={`${styles.Badge} ${styles.Ok}`}><Lock size={11} />Vault</span>}
                    >
                      <span class={styles.Badge} ref={element => tooltip(element, path)}><FileKey size={11} />File</span>
                    </Show>
                  </span>
                  <div class={styles.Tools}>
                    <Button icon size="sm" tooltip="Copy public key" onClick={() => copyText(key.publicKey, "the public key")}><Copy size={14} /></Button>
                    <Button icon size="sm" tooltip="Rename" onClick={() => rename(key)}><Pencil size={14} /></Button>
                    <Show
                      when={key.storage.kind === "vault"}
                      fallback={<Button icon size="sm" tooltip="Passphrase" onClick={() => setPassphraseFor(key)}><Lock size={14} /></Button>}
                    >
                      <Button icon size="sm" tooltip="Export private key" onClick={() => setExporting(key)}><Download size={14} /></Button>
                    </Show>
                    <Button icon size="sm" tooltip="Delete" onClick={() => remove(key)}><Trash2 size={14} /></Button>
                  </div>
                </div>
              );
            }}
          </For>
        </Show>
      </div>

      <Show when={hasRsa().length > 0}>
        <div class={`${styles.Note} ${styles.Warn}`}>
          <Info size={14} />
          <span>
            <b>{hasRsa().join(", ")}</b> won't work on servers that only accept SHA-1 RSA signatures. Use an Ed25519 key for those.
          </span>
        </div>
      </Show>

      <GenerateKeyModal
        show={generating()}
        onClose={() => setGenerating(false)}
        onCreated={key => {
          setGenerating(false);
          setReady(key);
        }}
      />
      <KeyReadyModal keyMeta={ready()} onClose={() => setReady(null)} />
      <ImportKeyModal show={importing()} onClose={() => setImporting(false)} />
      <ExportKeyModal keyMeta={exporting()} onClose={() => setExporting(null)} />
      <PassphraseModal keyMeta={passphraseFor()} onClose={() => setPassphraseFor(null)} />
    </>
  );
}

export default KeysView;
