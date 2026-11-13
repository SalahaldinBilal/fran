import styles from "./Panels.module.scss";
import { JSX, Show } from "solid-js";
import { Dynamic } from "solid-js/web";
import { LucideIcon, X } from "@core/icons";
import { TileControls } from "@core/components/Tiling/TileLayout";
import Button from "@core/components/Button/Button";

export type PanelFrameProps = {
  title: string,
  icon: LucideIcon,
  count?: number | null,
  actions?: JSX.Element,
  controls: TileControls,
  children: JSX.Element,
};

function PanelFrame(props: PanelFrameProps) {
  return (
    <section class={styles.Frame}>
      <header
        class={styles.Header}
        onPointerDown={event => {
          if ((event.target as Element).closest("button, input")) return;
          props.controls.grab(event);
        }}
      >
        <Dynamic component={props.icon} size={15} class={styles.Icon} />
        <h2 class={styles.Title}>{props.title}</h2>
        <Show when={props.count !== undefined && props.count !== null}>
          <span class={styles.Count}>{props.count}</span>
        </Show>
        <div class={styles.Actions}>
          {props.actions}
          <Button icon size="sm" tooltip="Hide panel" onClick={props.controls.remove}>
            <X size={14} />
          </Button>
        </div>
      </header>
      <div class={styles.Body}>{props.children}</div>
    </section>
  );
}

export default PanelFrame;
