import styles from "./Button.module.scss";
import { JSX } from "@solidjs/web";
import { tooltip } from "../Tooltip/Tooltip";

export type ButtonVariant = "ghost" | "subtle" | "primary" | "danger";

export type ButtonProps = {
  variant?: ButtonVariant,
  size?: "sm" | "md",
  icon?: boolean,
  active?: boolean,
  tooltip?: string,
  type?: "button" | "submit",
  disabled?: boolean,
  class?: string,
  style?: JSX.CSSProperties,
  children?: JSX.Element,
  onClick?: JSX.EventHandler<HTMLButtonElement, MouseEvent>,
  ref?: (element: HTMLButtonElement) => void,
};

function Button(props: ButtonProps) {
  const attachTooltip = tooltip(() => props.tooltip);

  return (
    <button
      ref={button => {
        attachTooltip(button);
        props.ref?.(button);
      }}
      type={props.type ?? "button"}
      class={[styles.Button, styles[props.variant ?? "ghost"], props.class, {
        [styles.Small]: props.size === "sm",
        [styles.Icon]: props.icon ?? false,
        [styles.Active]: props.active ?? false,
      }]}
      style={props.style}
      disabled={props.disabled}
      aria-label={props.icon ? props.tooltip : undefined}
      onClick={event => props.onClick?.(event)}
    >
      {props.children}
    </button>
  );
}

export default Button;
