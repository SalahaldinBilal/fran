import styles from "./Secrets.module.scss";
import { For, Show, createMemo, createSignal } from "solid-js";
import { Copy, KeyRound, Pencil, Plus, Trash2, TriangleAlert } from "@core/icons";
import useSecretsState from "@core/states/secretsState";
import useToastState from "@core/states/toastState";
import { errorMessage } from "@core/helpers/errors";
import { copySecret } from "@core/helpers/revealSecret";
import { SecretInfo } from "@core/types";
import { confirmDeleteSecret, usedByText } from "@core/components/SecretEditor/SecretEditor";
import Button from "@core/components/Button/Button";
import EmptyState from "@core/components/EmptyState/EmptyState";

const COLUMNS = "minmax(180px, 1.4fr) 150px minmax(140px, 1.4fr) 96px";

function SecretRow(props: { secret: SecretInfo }) {
  const secrets = useSecretsState;
  const [busy, setBusy] = createSignal(false);
  const usedBy = createMemo(() => usedByText(props.secret));

  async function copy() {
    setBusy(true);
    try {
      await copySecret({ kind: "secret", id: props.secret.id }, "value", `the secret ${props.secret.name}`);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!await confirmDeleteSecret(props.secret)) return;
    await secrets.remove(props.secret.id).catch(useToastState.pushError);
  }

  return (
    <div class={styles.ListRow}>
      <div class={styles.Name}>
        <span class={styles.ItemIcon}><KeyRound size={15} /></span>
        <span class={styles.NameText}>
          <b class={styles.Mono}>{props.secret.name}</b>
          <Show when={props.secret.note}><small>{props.secret.note}</small></Show>
        </span>
      </div>
      <span class={styles.Cell}>
        <Show when={props.secret.hasValue} fallback={<span class={styles.Badge}>No value here</span>}>
          <span class={`${styles.Badge} ${styles.Ok}`}>In the vault</span>
        </Show>
      </span>
      <span class={styles.Cell}>{usedBy()}</span>
      <div class={styles.Tools}>
        <Button icon size="sm" tooltip="Copy the value" disabled={busy() || !props.secret.hasValue} onClick={copy}><Copy size={14} /></Button>
        <Button icon size="sm" tooltip="Edit" onClick={() => secrets.openEditor(props.secret)}><Pencil size={14} /></Button>
        <Button icon size="sm" tooltip="Delete" onClick={remove}><Trash2 size={14} /></Button>
      </div>
    </div>
  );
}

function NamedSecretsView() {
  const secrets = useSecretsState;

  return (
    <>
      <div class={styles.Head}>
        <h2>Secrets</h2>
        <Button variant="primary" onClick={() => secrets.openEditor(null)}>
          <Plus size={14} />
          New secret
        </Button>
      </div>
      <p class={styles.Description}>
        A value with a name that any field of a connection, SSH host, identity, proxy or VPN can use, like a host, a user or a password.
        Change it here and everything that uses it follows. Fields only save the secret's name, the value stays in the vault.
      </p>

      <Show when={secrets.loadError()}>
        <div class={`${styles.Note} ${styles.Warn}`} style={{ "margin-bottom": "14px" }}>
          <TriangleAlert size={15} />
          <span>The secrets couldn't be read. {errorMessage(secrets.loadError())}</span>
        </div>
      </Show>

      <div class={styles.List} style={{ "--columns": COLUMNS }}>
        <div class={styles.ListHead}><span>Name</span><span>Value</span><span>Used by</span><span /></div>
        <Show
          when={secrets.secrets.length > 0}
          fallback={
            <div class={styles.Empty}>
              <EmptyState icon={KeyRound} title="No secrets yet" description="Add one here, or with the key button in any field." />
            </div>
          }
        >
          <For each={secrets.secrets}>
            {secret => <SecretRow secret={secret} />}
          </For>
        </Show>
      </div>
    </>
  );
}

export default NamedSecretsView;
