import styles from "./VpnLogModal.module.scss";
import { For, Show, createEffect, createMemo, createSignal } from "solid-js";
import { CircleAlert, Copy, Trash2 } from "@core/icons";
import useVpnState from "@core/states/vpnState";
import useToastState from "@core/states/toastState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { copyText } from "@core/helpers/clipboard";
import { VpnLogLine } from "@core/types";
import Modal from "../Modal/Modal";
import Button from "../Button/Button";
import SegmentedControl from "../SegmentedControl/SegmentedControl";

type Filter = "all" | "errors";

const REFRESH_MS = 1500;

const FILTERS = [
  { value: "all" as const, label: "Everything" },
  { value: "errors" as const, label: "Errors" },
];

function clock(at: number): string {
  return new Date(at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function VpnLogModal() {
  const vpn = useVpnState;
  const { pushError } = useToastState;
  const [lines, setLines] = createSignal<VpnLogLine[]>([]);
  const [filter, setFilter] = createSignal<Filter>("all");
  let list: HTMLDivElement | undefined;

  const profile = createMemo(() => vpn.profile(vpn.logFor()));
  const status = createMemo(() => {
    const id = vpn.logFor();
    return id ? vpn.status(id) : undefined;
  });
  const vpnName = createMemo(() => (profile()?.kind === "wireGuard" ? "WireGuard" : "OpenVPN"));
  const shown = createMemo(() => (filter() === "errors" ? lines().filter(line => line.error) : lines()));
  const lastError = createMemo(() => status()?.lastError ?? null);
  const hasLines = createMemo(() => lines().length > 0);
  const hasShown = createMemo(() => shown().length > 0);
  const emptyText = createMemo(() =>
    filter() === "errors" ? "No errors logged since Fran started." : "Nothing logged since Fran started. Connect once and it fills in.",
  );

  async function refresh(quiet: boolean) {
    const id = vpn.logFor();
    if (!id) return;
    const nearBottom = !list || list.scrollHeight - list.scrollTop - list.clientHeight < 40;
    try {
      setLines(await safeInvoke("get_vpn_log", { profileId: id }));
    } catch (error) {
      if (!quiet) pushError(error);
      return;
    }
    if (nearBottom && list) list.scrollTop = list.scrollHeight;
  }

  // Lines also arrive while nothing in the status changes, like during a slow connect.
  createEffect(() => vpn.logFor(), id => {
    if (!id) {
      setLines([]);
      setFilter("all");
      return;
    }
    queueMicrotask(() => void refresh(false));
    const timer = setInterval(() => void refresh(true), REFRESH_MS);
    return () => clearInterval(timer);
  });

  function copyAll() {
    const text = shown()
      .map(line => `${new Date(line.at).toISOString()} ${line.source === "fran" ? "Fran" : vpnName()}${line.error ? " ERROR" : ""} ${line.text}`)
      .join("\n");
    void copyText(text, "the log");
  }

  async function clear() {
    const id = vpn.logFor();
    if (!id) return;
    try {
      await safeInvoke("clear_vpn_log", { profileId: id });
      setLines([]);
    } catch (error) {
      pushError(error);
    }
  }

  return (
    <Modal
      show={vpn.logFor() !== null}
      onHide={() => vpn.closeLog()}
      title="VPN log"
      subtitle={profile()?.label}
      width={760}
      footer={
        <>
          <Button variant="subtle" disabled={!hasLines()} onClick={() => void clear()}>
            <Trash2 size={14} />
            Clear
          </Button>
          <Button variant="subtle" disabled={!hasShown()} onClick={copyAll}>
            <Copy size={14} />
            Copy
          </Button>
          <Button variant="primary" onClick={() => vpn.closeLog()}>Close</Button>
        </>
      }
    >
      <div class={styles.Body}>
        <Show when={lastError()}>
          {message => (
            <div class={styles.LastError}>
              <CircleAlert size={15} />
              <span>{message()}</span>
            </div>
          )}
        </Show>
        <div class={styles.Bar}>
          <SegmentedControl<Filter> value={filter()} options={FILTERS} onChange={setFilter} />
          <span class={styles.Hint}>Kept in memory until Fran quits. Passwords and session tokens are left out.</span>
        </div>
        <div class={styles.Lines} ref={element => (list = element)}>
          <For each={shown()} fallback={<div class={styles.Empty}>{emptyText()}</div>}>
            {line => (
              <div class={[styles.Line, { [styles.Error]: line.error }]}>
                <span class={styles.Time}>{clock(line.at)}</span>
                <span class={[styles.Source, { [styles.Fran]: line.source === "fran" }]}>
                  {line.source === "fran" ? "Fran" : vpnName()}
                </span>
                <span class={styles.Text}>{line.text}</span>
              </div>
            )}
          </For>
        </div>
      </div>
    </Modal>
  );
}

export default VpnLogModal;
