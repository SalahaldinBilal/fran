import styles from "./ColorSwatches.module.scss";
import { For, Show, createMemo, createSignal } from "solid-js";
import { Pipette } from "lucide-solid";
import ColorPicker from "@core/components/ColorPicker/ColorPicker";
import { tooltip } from "@core/components/Tooltip/Tooltip";

export const COLORS = ["#4a88c7", "#4fa37a", "#c9a34a", "#d07a3c", "#c75450", "#9a6fc4", "#7d8590"];

export type ColorSwatchesProps = {
  value: string | null,
  onChange: (color: string | null) => void,
};

function ColorSwatches(props: ColorSwatchesProps) {
  const [pickerAnchor, setPickerAnchor] = createSignal<HTMLElement | null>(null);
  const customColor = createMemo(() => (props.value !== null && !COLORS.includes(props.value) ? props.value : null));

  return (
    <div class={styles.Colors}>
      <button
        class={`${styles.Swatch} ${styles.None}`}
        classList={{ [styles.Selected]: props.value === null }}
        aria-label="Default color"
        onClick={() => props.onChange(null)}
      />
      <For each={COLORS}>
        {color => (
          <button
            class={styles.Swatch}
            classList={{ [styles.Selected]: props.value === color }}
            style={{ "--swatch": color }}
            aria-label={color}
            onClick={() => props.onChange(color)}
          />
        )}
      </For>
      <button
        ref={element => tooltip(element, () => "Custom color")}
        class={`${styles.Swatch} ${styles.Custom}`}
        classList={{ [styles.Selected]: customColor() !== null }}
        style={{ "--swatch": customColor() ?? undefined }}
        aria-label="Custom color"
        aria-expanded={pickerAnchor() !== null}
        onClick={event => setPickerAnchor(pickerAnchor() ? null : event.currentTarget)}
      >
        <Show when={customColor() === null}>
          <Pipette size={11} />
        </Show>
      </button>
      <Show when={pickerAnchor()}>
        {anchor => (
          <ColorPicker
            anchor={anchor()}
            value={customColor() ?? props.value ?? COLORS[0]}
            onChange={hex => props.onChange(hex)}
            onClose={() => setPickerAnchor(null)}
          />
        )}
      </Show>
    </div>
  );
}

export default ColorSwatches;
