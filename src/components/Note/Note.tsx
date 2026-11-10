import styles from "./Note.module.scss";
import { JSX, createMemo } from "solid-js";
import { Info, TriangleAlert } from "lucide-solid";

export type NoteProps = {
  tone?: "info" | "warning",
  children: JSX.Element,
};

function Note(props: NoteProps) {
  const warning = createMemo(() => props.tone === "warning");
  return (
    <div class={styles.Note} classList={{ [styles.Warning]: warning() }}>
      {warning() ? <TriangleAlert size={14} class={styles.Icon} /> : <Info size={14} class={styles.Icon} />}
      <span>{props.children}</span>
    </div>
  );
}

export default Note;
