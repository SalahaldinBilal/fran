import styles from "./Modal.module.scss";
import { Show, children, createEffect, createMemo, createSignal, onSettled } from "solid-js";
import { JSX, Portal } from "@solidjs/web";
import { createSwitchTransition } from "@solid-primitives/transition-group";
import { makeEventListener } from "@solid-primitives/event-listener";
import { X } from "@core/icons";
import Button from "../Button/Button";
import useModalState from "@core/states/modalState";

export type ModalProps = {
  show: boolean,
  onHide?: () => void,
  title?: JSX.Element,
  subtitle?: JSX.Element,
  footer?: JSX.Element,
  width?: number,
  dismissible?: boolean,
  children: JSX.Element,
};

function Modal(props: ModalProps) {
  const dismissible = createMemo(() => props.dismissible ?? true);
  const [layer, setLayer] = createSignal(0);
  const backdropStyle = createMemo(() => ({ "z-index": `calc(var(--z-modal) + ${layer()})` }));

  onSettled(() => useModalState.track(() => props.show));

  createEffect(() => props.show, show => {
    if (!show) return;
    const { layer: next, release } = useModalState.nextLayer();
    setLayer(next);
    return release;
  });

  makeEventListener(window, "keydown", event => {
    if (props.show && dismissible() && event.key === "Escape") props.onHide?.();
  });

  const dialog = children(() => (
    <Show when={props.show}>
      <div
        class={styles.Backdrop}
        style={backdropStyle()}
        onMouseDown={event => {
          if (event.target === event.currentTarget && dismissible()) props.onHide?.();
        }}
      >
        <div
          class={styles.Dialog}
          role="dialog"
          aria-modal="true"
          style={{ width: props.width ? `${props.width}px` : undefined }}
        >
          <div class={styles.Header}>
            <div class={styles.Titles}>
              <div class={styles.Title}>{props.title}</div>
              <Show when={props.subtitle}>
                <div class={styles.Subtitle}>{props.subtitle}</div>
              </Show>
            </div>
            <Show when={dismissible()}>
              <Button icon size="sm" tooltip="Close" onClick={() => props.onHide?.()}>
                <X size={16} />
              </Button>
            </Show>
          </div>
          <div class={styles.Content}>{props.children}</div>
          <Show when={props.footer}>
            <div class={styles.Footer}>{props.footer}</div>
          </Show>
        </div>
      </div>
    </Show>
  ));

  const rendered = createSwitchTransition(() => dialog.toArray()[0] as HTMLElement | undefined, {
    onEnter(element, done) {
      element.classList.add(styles.Entering);
      element.addEventListener("animationend", () => {
        element.classList.remove(styles.Entering);
        done();
      }, { once: true });
    },
    onExit(element, done) {
      element.classList.add(styles.Exiting);
      element.addEventListener("animationend", done, { once: true });
    },
  });

  return <Portal>{rendered()}</Portal>;
}

export default Modal;
