import styles from "./Sftp.module.scss";
import { For, Show, createMemo, createSignal } from "solid-js";
import { ArrowDownToLine, ArrowUpFromLine, ChevronDown, ChevronRight, RotateCw, X } from "@core/icons";
import useSftpState, { TransferItem, isFinished } from "@core/states/sftpState";
import { formatBytes, plural } from "@core/helpers";
import Button from "@core/components/Button/Button";
import Switch from "@core/components/Switch/Switch";

function statusText(item: TransferItem): string {
  switch (item.status) {
    case "waiting": return "Waiting for a free slot";
    case "scanning": return item.files > 0 ? `Counting, ${plural(item.files, "file")} so far (${formatBytes(item.bytes)})` : "Counting what's in the folder";
    case "conflict": return "Waiting for you";
    case "running": {
      const total = item.totalBytes > 0 ? ` of ${formatBytes(item.totalBytes)}` : "";
      const speed = item.speed !== null ? ` · ${formatBytes(item.speed)}/s` : "";
      return `${formatBytes(item.bytes)}${total}${speed}`;
    }
    case "done": {
      const files = item.totalFiles > 1 ? `${plural(item.files, "file")}, ` : "";
      return `Done, ${files}${formatBytes(item.bytes)}`;
    }
    case "cancelled": return "Cancelled";
    case "failed": return item.error ?? "Failed";
  }
}

function TransferRow(props: { tabId: string, item: TransferItem }) {
  const sftp = useSftpState;
  const [forAll, setForAll] = createSignal(false);
  const [showSkipped, setShowSkipped] = createSignal(false);

  const upload = createMemo(() => props.item.direction === "upload");
  const active = createMemo(() => !isFinished(props.item));
  const percent = createMemo(() => {
    if (props.item.status === "done") return 100;
    if (props.item.totalBytes <= 0) return 0;
    return Math.min(100, (props.item.bytes / props.item.totalBytes) * 100);
  });
  const conflictName = createMemo(() => {
    const path = props.item.conflict?.path ?? "";
    return path.split(/[\\/]/).pop() || path;
  });
  const conflictWhat = createMemo(() => (props.item.conflict?.isDir ? "A folder" : "A file"));
  const destination = createMemo(() => `${upload() ? "to" : "into"} ${props.item.targetDir}`);
  const status = createMemo(() => statusText(props.item));

  return (
    <div class={styles.Transfer} classList={{ [styles.TransferFailed]: props.item.status === "failed" }}>
      <div class={styles.TransferTop}>
        <span class={styles.TransferIcon} classList={{ [styles.Up]: upload() }}>
          <Show when={upload()} fallback={<ArrowDownToLine size={13} />}>
            <ArrowUpFromLine size={13} />
          </Show>
        </span>
        <span class={styles.TransferText}>
          <span class={styles.TransferName}>{props.item.name}</span>
          <span class={styles.TransferSub}>{destination()}</span>
        </span>
        <span class={styles.TransferStatus}>{status()}</span>
        <Show when={active()}>
          <Button icon size="sm" tooltip="Cancel" disabled={!props.item.transferId} onClick={() => sftp.cancel(props.tabId, props.item.key)}>
            <X size={13} />
          </Button>
        </Show>
        <Show when={props.item.status === "failed" || props.item.status === "cancelled"}>
          <Button icon size="sm" tooltip="Try again" onClick={() => sftp.retry(props.tabId, props.item.key)}>
            <RotateCw size={12} />
          </Button>
        </Show>
      </div>

      <Show when={props.item.status === "running" || props.item.status === "conflict" || props.item.status === "done"}>
        <div class={styles.Progress}>
          <div class={styles.ProgressFill} classList={{ [styles.ProgressDone]: props.item.status === "done" }} style={{ width: `${percent()}%` }} />
        </div>
      </Show>
      <Show when={props.item.status === "running" && props.item.current && props.item.totalFiles > 1}>
        <span class={styles.TransferCurrent}>{props.item.current}</span>
      </Show>

      <Show when={props.item.conflict}>
        <div class={styles.ConflictBar}>
          <span class={styles.ConflictText}>{conflictWhat()} named <strong>{conflictName()}</strong> is already there.</span>
          <Show when={props.item.totalFiles > 1}>
            <Switch checked={forAll()} onChange={setForAll} label="Same for the rest" />
          </Show>
          <Button size="sm" variant="ghost" onClick={() => void sftp.answerConflict(props.tabId, props.item.key, "skip", forAll())}>Skip</Button>
          <Button size="sm" variant="subtle" onClick={() => void sftp.answerConflict(props.tabId, props.item.key, "keepBoth", forAll())}>Keep both</Button>
          <Button size="sm" variant="danger" onClick={() => void sftp.answerConflict(props.tabId, props.item.key, "overwrite", forAll())}>Overwrite</Button>
        </div>
      </Show>

      <Show when={props.item.skipped.length > 0}>
        <button type="button" class={styles.SkippedToggle} onClick={() => setShowSkipped(!showSkipped())}>
          <Show when={showSkipped()} fallback={<ChevronRight size={12} />}>
            <ChevronDown size={12} />
          </Show>
          {plural(props.item.skipped.length, "item")} skipped
        </button>
        <Show when={showSkipped()}>
          <ul class={styles.SkippedList}>
            <For each={props.item.skipped}>
              {skipped => (
                <li>
                  <code>{skipped.path}</code>
                  <span>{skipped.reason}</span>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Show>
    </div>
  );
}

function TransferQueue(props: { tabId: string }) {
  const sftp = useSftpState;
  const [collapsed, setCollapsed] = createSignal(false);

  const items = createMemo(() => sftp.tab(props.tabId)?.transfers ?? []);
  const running = createMemo(() => items().filter(item => !isFinished(item)).length);
  const finished = createMemo(() => items().length - running());
  const waiting = createMemo(() => items().some(item => item.status === "conflict"));
  const summary = createMemo(() => {
    if (items().length === 0) return "Drag files between the panes, or use Upload and Download.";
    const parts: string[] = [];
    if (running() > 0) parts.push(`${running()} running`);
    if (finished() > 0) parts.push(`${finished()} finished`);
    return parts.join(", ");
  });

  return (
    <section class={styles.Queue} classList={{ [styles.QueueOpen]: items().length > 0 && !collapsed() }}>
      <header class={styles.QueueHead}>
        <button
          type="button"
          class={styles.QueueToggle}
          disabled={items().length === 0}
          onClick={() => setCollapsed(!collapsed())}
        >
          <Show when={items().length > 0 && !collapsed()} fallback={<ChevronRight size={13} />}>
            <ChevronDown size={13} />
          </Show>
          <span class={styles.QueueTitle}>Transfers</span>
          <Show when={waiting()}>
            <span class={styles.QueueAttention}>Needs an answer</span>
          </Show>
          <span class={styles.QueueSummary}>{summary()}</span>
        </button>
        <Show when={finished() > 0}>
          <Button size="sm" variant="ghost" onClick={() => sftp.clearFinished(props.tabId)}>Clear finished</Button>
        </Show>
      </header>
      <Show when={items().length > 0 && !collapsed()}>
        <div class={styles.QueueList}>
          <For each={items()}>{item => <TransferRow tabId={props.tabId} item={item} />}</For>
        </div>
      </Show>
    </section>
  );
}

export default TransferQueue;
