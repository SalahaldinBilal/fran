import styles from "./WindowControls.module.scss";
import { Show, createSignal, onCleanup, onSettled } from "solid-js";
import { getCurrentWindow } from "@tauri-apps/api/window";
import useToastState from "@core/states/toastState";
import { skipsConfirm } from "@core/helpers/platform";
import { quitApp } from "@core/helpers/tray";

function WindowControls() {
  const appWindow = getCurrentWindow();
  const [maximized, setMaximized] = createSignal(false);
  let unlistenResize: (() => void) | undefined;

  onCleanup(() => unlistenResize?.());

  async function watchMaximized() {
    setMaximized(await appWindow.isMaximized());
    unlistenResize = await appWindow.onResized(async () => setMaximized(await appWindow.isMaximized()));
  }

  onSettled(() => {
    void watchMaximized();
  });

  return (
    <div class={styles.WindowControls}>
      <button class={styles.Control} aria-label="Minimize" onClick={() => appWindow.minimize()}>
        <svg viewBox="0 0 10 10" aria-hidden="true">
          <path d="M0 5.5h10" />
        </svg>
      </button>
      <button
        class={styles.Control}
        aria-label={maximized() ? "Restore" : "Maximize"}
        onClick={() => appWindow.toggleMaximize()}
      >
        <svg viewBox="0 0 10 10" aria-hidden="true">
          <Show when={maximized()} fallback={<rect x="0.5" y="0.5" width="9" height="9" rx="1.5" />}>
            <path d="M2.5 2.5V2a1.5 1.5 0 0 1 1.5-1.5h4A1.5 1.5 0 0 1 9.5 2v4A1.5 1.5 0 0 1 8 7.5h-.5" />
            <rect x="0.5" y="2.5" width="7" height="7" rx="1.5" />
          </Show>
        </svg>
      </button>
      <button
        class={`${styles.Control} ${styles.Close}`}
        aria-label="Close"
        onClick={event => {
          if (skipsConfirm(event)) void quitApp(true).catch(useToastState.pushError);
          else void appWindow.close();
        }}
      >
        <svg viewBox="0 0 10 10" aria-hidden="true">
          <path d="M.5.5l9 9M9.5.5l-9 9" />
        </svg>
      </button>
    </div>
  );
}

export default WindowControls;
