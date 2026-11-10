import styles from "./Secrets.module.scss";
import { For, Show, createMemo } from "solid-js";
import { Cog, Lock } from "lucide-solid";
import useSavedSecretsState from "@core/states/savedSecretsState";
import EmptyState from "@core/components/EmptyState/EmptyState";

const COLUMNS = "minmax(180px, 1.4fr) minmax(200px, 2fr)";

function InternalKeysView() {
  const saved = useSavedSecretsState;
  const keys = createMemo(() => saved.secrets.filter(secret => secret.group === "internal" || secret.group === "unknown"));

  return (
    <>
      <div class={styles.Head}>
        <h2>Fran's own keys</h2>
      </div>
      <p class={styles.Description}>
        Keys Fran made for itself, like the one that encrypts agent history. They're never shown, since they're of no use outside this Fran.
      </p>
      <div class={styles.List} style={{ "--columns": COLUMNS }}>
        <div class={styles.ListHead}><span>Protects</span><span>What</span></div>
        <Show
          when={keys().length > 0}
          fallback={<div class={styles.Empty}><EmptyState icon={Lock} title="None yet" description="They're made the first time agent history or terminal logs are saved." /></div>}
        >
          <For each={keys()}>
            {secret => {
              const name = createMemo(() => secret.ownerLabel ?? secret.id);
              return (
                <div class={styles.ListRow}>
                  <div class={styles.Name}>
                    <span class={styles.ItemIcon}><Cog size={15} /></span>
                    <span class={styles.NameText}><b>{name()}</b></span>
                  </div>
                  <span class={styles.Cell}>{secret.label}</span>
                </div>
              );
            }}
          </For>
        </Show>
      </div>
    </>
  );
}

export default InternalKeysView;
