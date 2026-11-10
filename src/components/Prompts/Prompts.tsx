import styles from "./Prompts.module.scss";
import { For, Show, createEffect, createMemo, createSignal } from "solid-js";
import { createStore } from "solid-js/store";
import { ShieldAlert, ShieldCheck, ShieldQuestionMark } from "lucide-solid";
import usePromptState from "@core/states/promptState";
import { HopPosition } from "@core/types";
import Modal from "../Modal/Modal";
import Button from "../Button/Button";
import Field from "../Field/Field";
import Input from "../Input/Input";
import Switch from "../Switch/Switch";

function SecretsPrompt() {
  const { secretsRequest } = usePromptState;
  const [values, setValues] = createStore<Record<string, string>>({});
  const [save, setSave] = createSignal(false);

  createEffect(() => {
    if (!secretsRequest()) return;
    setValues(Object.fromEntries(secretsRequest()!.slots.map(slot => [slot.id, ""])));
    setSave(false);
  });

  function submit() {
    secretsRequest()?.resolve({ values: { ...values }, save: save() });
  }

  return (
    <Modal
      show={secretsRequest() !== null}
      onHide={() => secretsRequest()?.resolve(null)}
      title={secretsRequest()?.title ?? ""}
      subtitle={secretsRequest()?.connectionName}
      width={420}
      footer={
        <>
          <Button variant="subtle" onClick={() => secretsRequest()?.resolve(null)}>Cancel</Button>
          <Button variant="primary" onClick={submit}>{secretsRequest()?.submitLabel}</Button>
        </>
      }
    >
      <form
        class={styles.Form}
        onSubmit={event => {
          event.preventDefault();
          submit();
        }}
      >
        <For each={secretsRequest()?.slots ?? []}>
          {(slot, index) => {
            const inputType = createMemo(() => (slot.oneTime ? "text" : "password"));
            const hint = createMemo(() => (slot.oneTime ? "Asked for on every connect, never saved." : undefined));
            return (
              <Field label={slot.label} hint={hint()}>
                <Input
                  type={inputType()}
                  autofocus={index() === 0}
                  value={values[slot.id] ?? ""}
                  onValue={value => setValues(slot.id, value)}
                />
              </Field>
            );
          }}
        </For>
        <button type="submit" hidden />
        <Show when={secretsRequest()?.canSave}>
          <Switch checked={save()} onChange={setSave} label="Save in the vault" />
        </Show>
      </form>
    </Modal>
  );
}

const KEY_FILES: Record<string, string> = {
  "ssh-ed25519": "ssh_host_ed25519_key.pub",
  "ecdsa-sha2-nistp256": "ssh_host_ecdsa_key.pub",
  "ecdsa-sha2-nistp384": "ssh_host_ecdsa_key.pub",
  "ecdsa-sha2-nistp521": "ssh_host_ecdsa_key.pub",
};

function hostKeyFile(algorithm: string): string {
  return KEY_FILES[algorithm] ?? "ssh_host_rsa_key.pub";
}

function HopNote(props: { hop: HopPosition | null }) {
  return (
    <Show when={props.hop}>
      {hop => (
        <p class={styles.HopNote}>
          This is hop {hop().index} of {hop().total} on the way to <b>{hop().target}</b>. Every hop is checked on its own.
        </p>
      )}
    </Show>
  );
}

function UnknownKeyPrompt() {
  const { hostKeyRequest } = usePromptState;

  return (
    <Modal
      show={hostKeyRequest() !== null}
      onHide={() => hostKeyRequest()?.resolve(false)}
      title="New host key"
      width={520}
      footer={
        <>
          <Button variant="subtle" onClick={() => hostKeyRequest()?.resolve(false)}>Cancel</Button>
          <Button variant="primary" onClick={() => hostKeyRequest()?.resolve(true)}>Trust and connect</Button>
        </>
      }
    >
      <Show when={hostKeyRequest()?.detail}>
        {detail => (
          <div class={styles.HostKey}>
            <div class={styles.HostKeyLead}>
              <ShieldQuestionMark size={20} />
              <p>
                Fran hasn't connected to <b>{detail().key.host}:{detail().key.port}</b> before.
                Check that this is the server's key before trusting it.
              </p>
            </div>
            <div class={styles.Fingerprint}>
              <span>{detail().key.algorithm} fingerprint</span>
              {detail().key.fingerprint}
            </div>
            <Show
              when={detail().opensshTrusted}
              fallback={
                <p class={styles.Check}>
                  On the server, <code>ssh-keygen -lf /etc/ssh/{hostKeyFile(detail().key.algorithm)}</code> prints the same
                  fingerprint. Or compare it with what the server's admin gave you.
                </p>
              }
            >
              <div class={styles.Trusted}>
                <ShieldCheck size={15} />
                <span>OpenSSH on this computer already trusts this key. Fran keeps its own list, so it asks once.</span>
              </div>
            </Show>
            <HopNote hop={detail().hop} />
          </div>
        )}
      </Show>
    </Modal>
  );
}

function ChangedKeyPrompt() {
  const { changedKeyRequest } = usePromptState;
  const [typed, setTyped] = createSignal("");

  createEffect(() => {
    if (changedKeyRequest()) setTyped("");
  });

  const host = createMemo(() => changedKeyRequest()?.detail.key.host ?? "");
  const matches = createMemo(() => host() !== "" && typed().trim().toLowerCase() === host().toLowerCase());
  const trustedOn = createMemo(() => {
    const added = changedKeyRequest()?.detail.knownAdded;
    return added ? ` on ${new Date(added).toLocaleDateString()}` : "";
  });

  function replace() {
    if (matches()) changedKeyRequest()?.resolve(typed().trim());
  }

  return (
    <Modal
      show={changedKeyRequest() !== null}
      onHide={() => changedKeyRequest()?.resolve(null)}
      title="Host key changed"
      width={520}
      footer={
        <>
          <Button variant="subtle" onClick={() => changedKeyRequest()?.resolve(null)}>Close</Button>
          <Button variant="danger" disabled={!matches()} onClick={replace}>Replace trusted key</Button>
        </>
      }
    >
      <Show when={changedKeyRequest()?.detail}>
        {detail => (
          <form
            class={styles.HostKey}
            onSubmit={event => {
              event.preventDefault();
              replace();
            }}
          >
            <div class={`${styles.HostKeyLead} ${styles.Danger}`}>
              <ShieldAlert size={20} />
              <p>
                The key for <b>{detail().key.host}:{detail().key.port}</b> isn't the one you trusted{trustedOn()}.
                Someone may be intercepting the connection, or the server was reinstalled. The connection was stopped.
              </p>
            </div>
            <div class={`${styles.Fingerprint} ${styles.Old}`}>
              <span>Trusted key, {detail().knownAlgorithm}</span>
              {detail().knownFingerprint}
            </div>
            <div class={styles.Fingerprint}>
              <span>Key the server sent, {detail().key.algorithm}</span>
              {detail().key.fingerprint}
            </div>
            <HopNote hop={detail().hop} />
            <Field label={`Type ${detail().key.host} to replace the trusted key`} hint="Only do this if you know why the key changed.">
              <Input value={typed()} onValue={setTyped} placeholder={detail().key.host} mono />
            </Field>
            <button type="submit" hidden />
          </form>
        )}
      </Show>
    </Modal>
  );
}

function ConfirmPrompt() {
  const { confirmRequest } = usePromptState;

  return (
    <Modal
      show={confirmRequest() !== null}
      onHide={() => confirmRequest()?.resolve(false)}
      title={confirmRequest()?.title}
      width={420}
      footer={
        <>
          <Button variant="subtle" onClick={() => confirmRequest()?.resolve(false)}>Cancel</Button>
          <Button
            variant={confirmRequest()?.danger ? "danger" : "primary"}
            onClick={() => confirmRequest()?.resolve(true)}
          >
            {confirmRequest()?.confirmLabel}
          </Button>
        </>
      }
    >
      <p class={styles.Message}>{confirmRequest()?.message}</p>
    </Modal>
  );
}

function TextPrompt() {
  const { textRequest } = usePromptState;
  const [value, setValue] = createSignal("");

  createEffect(() => {
    const request = textRequest();
    if (request) setValue(request.initial);
  });

  function submit() {
    const trimmed = value().trim();
    if (trimmed) textRequest()?.resolve(trimmed);
  }

  return (
    <Modal
      show={textRequest() !== null}
      onHide={() => textRequest()?.resolve(null)}
      title={textRequest()?.title}
      width={400}
      footer={
        <>
          <Button variant="subtle" onClick={() => textRequest()?.resolve(null)}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={!value().trim()}>
            {textRequest()?.confirmLabel}
          </Button>
        </>
      }
    >
      <form
        class={styles.Form}
        onSubmit={event => {
          event.preventDefault();
          submit();
        }}
      >
        <Field label={textRequest()?.label ?? ""}>
          <Input value={value()} onValue={setValue} autofocus />
        </Field>
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}

function Prompts() {
  return (
    <>
      <SecretsPrompt />
      <UnknownKeyPrompt />
      <ChangedKeyPrompt />
      <ConfirmPrompt />
      <TextPrompt />
    </>
  );
}

export default Prompts;
