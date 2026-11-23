import styles from "./Note.module.scss";
import { createMemo } from "solid-js";
import { JSX } from "@solidjs/web";
import { Info, TriangleAlert } from "@core/icons";

export type NoteProps = {
  tone?: "info" | "warning",
  children: JSX.Element,
};

function Note(props: NoteProps) {
  const warning = createMemo(() => props.tone === "warning");
  return (
    <div class={[styles.Note, { [styles.Warning]: warning() }]}>
      {warning() ? <TriangleAlert size={14} class={styles.Icon} /> : <Info size={14} class={styles.Icon} />}
      <span>{props.children}</span>
    </div>
  );
}

export default Note;
