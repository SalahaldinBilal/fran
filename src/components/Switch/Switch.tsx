import styles from "./Switch.module.scss";

export type SwitchProps = {
  checked: boolean,
  // `event` is the click that flipped it, so callers can read its modifier keys.
  onChange: (checked: boolean, event: MouseEvent | null) => void,
  disabled?: boolean,
  label?: string,
};

function Switch(props: SwitchProps) {
  let lastClick: MouseEvent | null = null;

  return (
    <label class={[styles.Switch, { [styles.Disabled]: props.disabled ?? false }]}>
      <input
        type="checkbox"
        checked={props.checked}
        disabled={props.disabled}
        onClick={event => { lastClick = event; }}
        onChange={event => {
          const next = event.currentTarget.checked;
          const click = lastClick;
          lastClick = null;
          // Stays as the prop says until the owner changes it, so a cancelled change doesn't leave it flipped.
          event.currentTarget.checked = props.checked;
          props.onChange(next, click);
        }}
      />
      <span class={[styles.Track, { [styles.Checked]: props.checked }]}>
        <span class={styles.Thumb} />
      </span>
      {props.label}
    </label>
  );
}

export default Switch;
