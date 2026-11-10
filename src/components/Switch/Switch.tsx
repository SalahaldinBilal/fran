import styles from "./Switch.module.scss";

export type SwitchProps = {
  checked: boolean,
  onChange: (checked: boolean) => void,
  disabled?: boolean,
  label?: string,
};

function Switch(props: SwitchProps) {
  return (
    <label class={styles.Switch} classList={{ [styles.Disabled]: props.disabled ?? false }}>
      <input
        type="checkbox"
        checked={props.checked}
        disabled={props.disabled}
        onChange={event => {
          const next = event.currentTarget.checked;
          // Stays as the prop says until the owner changes it, so a cancelled change doesn't leave it flipped.
          event.currentTarget.checked = props.checked;
          props.onChange(next);
        }}
      />
      <span class={styles.Track} classList={{ [styles.Checked]: props.checked }}>
        <span class={styles.Thumb} />
      </span>
      {props.label}
    </label>
  );
}

export default Switch;
