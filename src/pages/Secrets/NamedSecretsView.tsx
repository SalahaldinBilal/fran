import styles from "./Secrets.module.scss";
import { For, Show, createMemo, createSignal } from "solid-js";
import { Copy, KeyRound, Link2, Pencil, Plus, Trash2, TriangleAlert } from "@core/icons";
import { cloudModule } from "@core/clouds";
import useSecretsState from "@core/states/secretsState";
import useSyncState from "@core/states/syncState";
import useToastState from "@core/states/toastState";
import { errorMessage } from "@core/helpers/errors";
import { copySecret } from "@core/helpers/revealSecret";
import { SecretInfo } from "@core/types";
import { syncMenu } from "@core/helpers/syncTargets";
import { itemKey } from "@core/states/syncState";
import useContextMenuState from "@core/states/contextMenuState";
import { deleteSecret, usedByText } from "@core/components/SecretEditor/SecretEditor";
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
    await deleteSecret(props.secret).catch(useToastState.pushError);
  }

  return (
    <div
      class={styles.ListRow}
      onContextMenu={event => {
        const items = syncMenu(itemKey("secret", props.secret.id), props.secret.name, "secrets");
        if (items.length > 0) useContextMenuState.openContextMenu(event, items);
      }}
    >
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
  const stores = createMemo(() => useSyncState.view.clouds.filter(cloud => cloudModule(cloud.kind).secretStore));

  return (
    <>
      <div class={styles.Head}>
        <h2>Secrets</h2>
        <div class={styles.HeadTools}>
          <For each={stores()}>
            {cloud => (
              <Button variant="subtle" onClick={() => secrets.openLink(cloud.identity)}>
                <Link2 size={14} />
                Link from {cloud.name}
              </Button>
            )}
          </For>
          <Button variant="primary" onClick={() => secrets.openEditor(null)}>
            <Plus size={14} />
            New secret
          </Button>
        </div>
      </div>
      <p class={styles.Description}>
        Named values that any field can use instead of typing them in.
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
