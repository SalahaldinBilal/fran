import styles from "./CodeView.module.scss";
import { onCleanup, onSettled } from "solid-js";
import { EditorState } from "@codemirror/state";
import { EditorView, drawSelection, highlightActiveLine, keymap, lineNumbers } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { bracketMatching, foldGutter, foldKeymap, syntaxHighlighting } from "@codemirror/language";
import { searchKeymap } from "@codemirror/search";
import { json } from "@codemirror/lang-json";
import { SQLDialect, StandardSQL, sql } from "@codemirror/lang-sql";
import { editorTheme, highlightStyle } from "../SqlEditor/theme";

export type CodeViewApi = {
  text: () => string,
  setText: (text: string) => void,
  focus: () => void,
};

export type CodeViewProps = {
  value: string,
  language: "json" | "sql" | "text",
  // For "sql". Standard SQL when the database isn't known.
  dialect?: SQLDialect,
  readOnly?: boolean,
  onChange?: (text: string) => void,
  onReady?: (api: CodeViewApi) => void,
};

function CodeView(props: CodeViewProps) {
  let container!: HTMLDivElement;
  let view: EditorView | undefined;

  function language() {
    switch (props.language) {
      case "json": return json();
      case "sql": return sql({ dialect: props.dialect ?? StandardSQL });
      case "text": return [];
    }
  }

  onSettled(() => {
    const readOnly = props.readOnly ?? false;
    view = new EditorView({
      parent: container,
      state: EditorState.create({
        doc: props.value,
        extensions: [
          lineNumbers(),
          foldGutter(),
          drawSelection(),
          highlightActiveLine(),
          bracketMatching(),
          history(),
          syntaxHighlighting(highlightStyle),
          keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap, ...foldKeymap, indentWithTab]),
          language(),
          EditorView.lineWrapping,
          EditorState.readOnly.of(readOnly),
          EditorView.updateListener.of(update => {
            if (update.docChanged) props.onChange?.(update.state.doc.toString());
          }),
          editorTheme,
        ],
      }),
    });

    const editor = view;
    props.onReady?.({
      text: () => editor.state.doc.toString(),
      setText: text => editor.dispatch({ changes: { from: 0, to: editor.state.doc.length, insert: text } }),
      focus: () => editor.focus(),
    });
  });

  onCleanup(() => view?.destroy());

  return <div ref={container} class={styles.CodeView} />;
}

export default CodeView;
