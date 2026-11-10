import styles from "./SshImport.module.scss";
import { For, Show } from "solid-js";
import { Check } from "lucide-solid";
import { ImportCandidate } from "@core/types";

export type SshImportListProps = {
  candidates: ImportCandidate[],
  skippedPatterns: string[],
  picked: Set<string>,
  onToggle: (alias: string) => void,
};

function describe(candidate: ImportCandidate): string {
  const port = candidate.port !== 22 ? `:${candidate.port}` : "";
  return `${candidate.user}@${candidate.host}${port}`;
}

function SshImportList(props: SshImportListProps) {
  return (
    <div class={styles.List}>
      <For each={props.candidates}>
        {candidate => (
          <button
            type="button"
            class={styles.Row}
            classList={{ [styles.Disabled]: candidate.skipReason !== null }}
            disabled={candidate.skipReason !== null}
            onClick={() => props.onToggle(candidate.alias)}
          >
            <span class={styles.Check} classList={{ [styles.On]: props.picked.has(candidate.alias) }}>
              <Check size={12} />
            </span>
            <span class={styles.Text}>
              <span class={styles.Alias}>{candidate.alias}</span>
              <span class={styles.Detail}>{candidate.skipReason ?? describe(candidate)}</span>
            </span>
            <Show when={candidate.skipReason === null}>
              <span class={styles.Badges}>
                <Show when={candidate.jumps.length > 0}>
                  <span class={styles.Badge}>via {candidate.jumps.join(", ")}</span>
                </Show>
                <span class={styles.Badge}>{candidate.identityFile ?? "SSH agent"}</span>
              </span>
            </Show>
          </button>
        )}
      </For>
      <For each={props.skippedPatterns}>
        {pattern => (
          <div class={`${styles.Row} ${styles.Disabled}`}>
            <span class={styles.Check} />
            <span class={styles.Text}>
              <span class={styles.Alias}>{pattern}</span>
              <span class={styles.Detail}>Patterns are skipped</span>
            </span>
          </div>
        )}
      </For>
    </div>
  );
}

export default SshImportList;
