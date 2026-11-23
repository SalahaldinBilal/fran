import styles from "./UpdateBanner.module.scss";
import { Match, Show, Switch, createMemo, createSignal } from "solid-js";
import { ArrowUp, CircleAlert, Download, RotateCw, X } from "@core/icons";
import useUpdaterState from "@core/states/updaterState";
import useWorkspaceState from "@core/states/workspaceState";
import Button from "../Button/Button";

// Shown on every page while an update is waiting. Closing it only lasts until the next start.
function UpdateBanner() {
  const updater = useUpdaterState;
  const [closed, setClosed] = createSignal(false);

  const version = createMemo(() => updater.update()?.version ?? "");
  const shown = createMemo(() => {
    if (closed() || !updater.update()) return false;
    return ["available", "downloading", "ready", "error"].includes(updater.phase());
  });
  const percent = createMemo(() => {
    const { downloaded, total } = updater.progress();
    return total ? Math.min(100, Math.round((downloaded / total) * 100)) : null;
  });
  const title = createMemo(() => {
    switch (updater.phase()) {
      case "downloading": return percent() === null ? `Downloading Fran ${version()}` : `Downloading Fran ${version()}, ${percent()}%`;
      case "ready": return `Fran ${version()} is installed`;
      case "error": return `Fran ${version()} couldn't be installed`;
      default: return `Fran ${version()} is available`;
    }
  });
  const detail = createMemo(() => {
    switch (updater.phase()) {
      case "ready": return "Restart Fran to start using it.";
      case "error": return updater.error();
      default: {
        const current = updater.currentVersion() ? `You have ${updater.currentVersion()}.` : "";
        return updater.selfUpdate ? current : `${current} Update it through Nix.`.trim();
      }
    }
  });
  const failed = createMemo(() => updater.phase() === "error");

  return (
    <Show when={shown()}>
      <div class={[styles.Banner, { [styles.Failed]: failed() }]} role="status">
        <span class={styles.Icon}>
          {failed() ? <CircleAlert size={16} /> : <ArrowUp size={17} strokeWidth={2.5} />}
        </span>
        <div class={styles.Text}>
          <span class={styles.Title}>{title()}</span>
          <Show when={detail()}>
            <span class={styles.Detail}>{detail()}</span>
          </Show>
        </div>
        <div class={styles.Actions}>
          <Button size="sm" variant="subtle" onClick={() => useWorkspaceState.openSettings("updates")}>What's new</Button>
          <Show when={updater.selfUpdate}>
            <Switch>
              <Match when={updater.phase() === "ready"}>
                <Button size="sm" variant="primary" onClick={() => void updater.restart()}>
                  <RotateCw size={14} />
                  Restart
                </Button>
              </Match>
              <Match when={updater.phase() !== "downloading"}>
                <Button size="sm" variant="primary" onClick={() => void updater.install()}>
                  <Download size={14} />
                  {failed() ? "Try again" : "Install"}
                </Button>
              </Match>
            </Switch>
          </Show>
          <Button icon size="sm" tooltip="Close until Fran starts again" onClick={() => setClosed(true)}>
            <X size={15} />
          </Button>
        </div>
        <Show when={updater.phase() === "downloading"}>
          <div class={styles.Progress}>
            <div class={[styles.Fill, { [styles.Indeterminate]: percent() === null }]} style={{ width: `${percent() ?? 30}%` }} />
          </div>
        </Show>
      </div>
    </Show>
  );
}

export default UpdateBanner;
