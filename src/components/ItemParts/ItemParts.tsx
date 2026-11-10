import styles from "./ItemParts.module.scss";
import { JSX } from "solid-js";

export type ItemIconProps = {
  color?: string | null,
  size?: "sm" | "lg",
  children: JSX.Element,
};

// The tinted tile that leads every card and row, so databases, hosts and forwards look like one family.
export function ItemIcon(props: ItemIconProps) {
  return (
    <span
      class={styles.Icon}
      classList={{ [styles.Large]: props.size === "lg" }}
      style={{ "--item-color": props.color ?? "var(--row-color, var(--accent))" }}
    >
      {props.children}
    </span>
  );
}

export type ItemBadgeProps = {
  tone?: "neutral" | "warning",
  children: JSX.Element,
};

export function ItemBadge(props: ItemBadgeProps) {
  return <span class={styles.Badge} classList={{ [styles.Warning]: props.tone === "warning" }}>{props.children}</span>;
}
