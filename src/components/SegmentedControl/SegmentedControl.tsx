import styles from "./SegmentedControl.module.scss";
import { For, Show } from "solid-js";
import { Dynamic } from "@solidjs/web";
import { LucideIcon } from "@core/icons";

export type SegmentedOption<T> = {
  value: T,
  label: string,
  icon?: LucideIcon,
  count?: number,
};

export type SegmentedControlProps<T> = {
  value: T,
  options: readonly SegmentedOption<T>[],
  onChange: (value: T) => void,
  fill?: boolean,
};

function SegmentedControl<T>(props: SegmentedControlProps<T>) {
  return (
    <div class={[styles.Control, { [styles.Fill]: props.fill ?? false }]} role="radiogroup">
      <For each={props.options} keyed={entry => entry.value}>
        {option => (
          <button
            type="button"
            role="radio"
            aria-checked={option().value === props.value ? "true" : "false"}
            class={[styles.Option, { [styles.Selected]: option().value === props.value }]}
            onClick={() => props.onChange(option().value)}
          >
            <Show when={option().icon}>
              {icon => <Dynamic component={icon()} size={14} />}
            </Show>
            {option().label}
            <Show when={option().count !== undefined}>
              <span class={styles.Count}>{option().count}</span>
            </Show>
          </button>
        )}
      </For>
    </div>
  );
}

export default SegmentedControl;
