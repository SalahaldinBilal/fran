import styles from "./SyncField.module.scss";
import { Show, createMemo } from "solid-js";
import { Check, ChevronDown, Cloud as CloudIcon, CloudOff } from "@core/icons";
import useSyncState from "@core/states/syncState";
import useContextMenuState from "@core/states/contextMenuState";
import { homeLabel, syncChoices, targetId } from "@core/helpers/syncTargets";
import { SyncCategory } from "@core/types";
import Field from "../Field/Field";
import { tooltip } from "../Tooltip/Tooltip";

export type SyncFieldProps = {
  // Null while the item isn't saved. It then follows its group or category.
  itemKey: string | null,
  label: string,
  category: SyncCategory,
};

// The editor's "Sync to" line. It changes the route right away, apart from the editor's Save.
function SyncField(props: SyncFieldProps) {
  const sync = useSyncState;
  const shown = createMemo(() => props.itemKey !== null && syncChoices(props.category, "item").some(choice => choice.target?.kind === "cloud"));
  const route = createMemo(() => sync.itemRoute(props.itemKey ?? ""));
  const home = createMemo(() => sync.home(props.itemKey ?? "") ?? null);
  const where = createMemo(() => home()?.name ?? homeLabel(props.itemKey ?? ""));
  const synced = createMemo(() => home() !== null);
  const why = createMemo(() => (route() === null ? "by default" : "chosen for this one"));
  const text = createMemo(() => (route()?.kind === "local" ? "Kept on this computer" : synced() ? `Syncs to ${where()}` : "Not synced"));

  function open(event: MouseEvent & { currentTarget: HTMLElement }) {
    const key = props.itemKey;
    if (!key) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const current = targetId(route());
    const choices = syncChoices(props.category, "item", homeLabel(key));
    useContextMenuState.openMenuAt(
      { x: rect.left, y: rect.bottom + 4 },
      choices.map(choice => ({
        label: choice.label,
        hint: choice.hint,
        icon: choice.id === current ? Check : undefined,
        onSelect: () => void sync.setItemRoute(key, props.label, choice.target),
      })),
    );
  }

  return (
    <Show when={shown()}>
      <Field label="Sync to" grow>
        <button type="button" class={styles.Line} ref={element => tooltip(element, () => "Applies right away, without Save")} onClick={open}>
          <span class={styles.Icon} classList={{ [styles.On]: synced() }}>
            <Show when={synced()} fallback={<CloudOff size={13} />}><CloudIcon size={13} /></Show>
          </span>
          <span class={styles.Text}>
            <strong>{text()}</strong>
            <span class={styles.Why}>{why()}</span>
          </span>
          <ChevronDown size={14} class={styles.Arrow} />
        </button>
      </Field>
    </Show>
  );
}

export default SyncField;
