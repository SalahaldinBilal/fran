import styles from "./ActivityTab.module.scss";
import { For, Show, createMemo } from "solid-js";
import { Copy, Info, RotateCw, TriangleAlert } from "@core/icons";
import { ActivityNotice, SetupStep } from "@core/types";
import { copyText } from "@core/helpers/clipboard";
import Button from "@core/components/Button/Button";

function NoticeStep(props: { step: SetupStep }) {
  const sql = createMemo(() => props.step.language === "sql");
  const copyLabel = createMemo(() => (sql() ? "Copy SQL" : "Copy setting"));

  return (
    <li class={styles.Step}>
      <div class={styles.StepLabel}>
        <span>{props.step.label}</span>
        <Show when={props.step.restart}>
          <span class={styles.RestartBadge}>
            <RotateCw size={11} />
            Needs a restart
          </span>
        </Show>
      </div>
      <Show when={props.step.code}>
        {code => (
          <div class={styles.StepCode}>
            <pre>{code()}</pre>
            <Button icon size="sm" tooltip={copyLabel()} onClick={() => copyText(code(), sql() ? "SQL" : "setting")}>
              <Copy size={14} />
            </Button>
          </div>
        )}
      </Show>
    </li>
  );
}

export type ActivityNoticeViewProps = {
  notice: ActivityNotice,
  compact?: boolean,
};

function ActivityNoticeView(props: ActivityNoticeViewProps) {
  const unavailable = createMemo(() => props.notice.kind === "unavailable");

  return (
    <div class={styles.Notice} classList={{ [styles.NoticeCompact]: props.compact ?? false, [styles.NoticeLimited]: !unavailable() }}>
      <div class={styles.NoticeHead}>
        {unavailable() ? <Info size={16} class={styles.NoticeIcon} /> : <TriangleAlert size={16} class={styles.NoticeIcon} />}
        <div class={styles.NoticeTitle}>{props.notice.title}</div>
      </div>
      <div class={styles.NoticeDetail}>{props.notice.detail}</div>

      <Show when={props.notice.steps.length > 0}>
        <ol class={styles.Steps}>
          <For each={props.notice.steps}>
            {step => <NoticeStep step={step} />}
          </For>
        </ol>
        <div class={styles.NoticeFoot}>Fran doesn't change server settings itself. Run these where you manage the server.</div>
      </Show>
    </div>
  );
}

export default ActivityNoticeView;
