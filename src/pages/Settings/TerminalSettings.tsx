import styles from "./Settings.module.scss";
import { For, Match, Show, Switch as Branch, createEffect, createMemo, createSignal } from "solid-js";
import { CircleAlert, ScrollText, Trash2 } from "lucide-solid";
import useSettingsState, {
  TERMINAL_CURSORS, TERMINAL_FONT_SIZES, TERMINAL_FONTS, TERMINAL_LOG_DAYS, TERMINAL_SCROLLBACK, TerminalCursor,
} from "@core/states/settingsState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import useLockState from "@core/states/lockState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage } from "@core/helpers/errors";
import { terminalToText } from "@core/helpers/terminalText";
import { formatBytes } from "@core/helpers";
import { TerminalLogSession } from "@core/types";
import Select, { SelectItem } from "@core/components/Select/Select";
import Switch from "@core/components/Switch/Switch";
import Button from "@core/components/Button/Button";
import Modal from "@core/components/Modal/Modal";
import CodeView from "@core/components/CodeView/CodeView";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Spinner from "@core/components/Spinner/Spinner";
import { SettingGroup, SettingRow, SettingsPage } from "./SettingsLayout";

const CURSOR_LABELS: Record<TerminalCursor, string> = { block: "Block", bar: "Bar", underline: "Underline" };

const FONT_ITEMS: SelectItem<string>[] = TERMINAL_FONTS.map(font => ({ value: font, label: font || "App default" }));
const SIZE_ITEMS: SelectItem<number>[] = TERMINAL_FONT_SIZES.map(size => ({ value: size, label: `${size} px` }));
const CURSOR_ITEMS: SelectItem<TerminalCursor>[] = TERMINAL_CURSORS.map(cursor => ({ value: cursor, label: CURSOR_LABELS[cursor] }));
const SCROLLBACK_ITEMS: SelectItem<number>[] = TERMINAL_SCROLLBACK.map(lines => ({ value: lines, label: `${lines.toLocaleString()} lines` }));
const LOG_DAY_ITEMS: SelectItem<number>[] = TERMINAL_LOG_DAYS.map(days => ({ value: days, label: `${days} days` }));

const DAY_MS = 86_400_000;
const timeFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

type Viewing = { session: TerminalLogSession, text: string | null, error: string | null };

function TerminalLogs() {
  const { settings } = useSettingsState;
  const [sessions, setSessions] = createSignal<TerminalLogSession[] | null>(null);
  const [size, setSize] = createSignal(0);
  const [error, setError] = createSignal<string | null>(null);
  const [viewing, setViewing] = createSignal<Viewing | null>(null);

  async function load() {
    setError(null);
    try {
      const to = Date.now();
      const from = to - settings.terminal.logDays * DAY_MS;
      setSessions(await safeInvoke("list_terminal_logs", { from, to }));
      setSize(await safeInvoke("get_terminal_log_size"));
    } catch (failure) {
      setSessions([]);
      setError(errorMessage(failure));
    }
  }

  createEffect(() => {
    if (!useLockState.locked()) void load();
  });

  async function view(session: TerminalLogSession) {
    setViewing({ session, text: null, error: null });
    try {
      const raw = await safeInvoke("get_terminal_log", { terminalId: session.terminalId, from: session.startedAt, to: session.endedAt });
      setViewing(current => current && { ...current, text: terminalToText(raw) });
    } catch (failure) {
      setViewing(current => current && { ...current, error: errorMessage(failure) });
    }
  }

  async function clearAll() {
    const confirmed = await usePromptState.confirm({
      title: "Delete every terminal log?",
      message: `${formatBytes(size())} of saved terminal output will be deleted. It can't be undone.`,
      confirmLabel: "Delete",
      danger: true,
    });
    if (!confirmed) return;
    try {
      await safeInvoke("clear_terminal_logs");
      await load();
    } catch (failure) {
      useToastState.pushError(failure);
    }
  }

  const subtitle = createMemo(() => {
    const current = viewing();
    return current ? timeFormat.format(new Date(current.session.startedAt)) : "";
  });

  return (
    <SettingGroup
      title="Saved logs"
      after={
        <Show when={size() > 0}>
          <div class={styles.FormActions}>
            <Button variant="ghost" onClick={() => void clearAll()}>
              <Trash2 size={13} />
              Delete all ({formatBytes(size())})
            </Button>
          </div>
        </Show>
      }
    >
      <Branch>
        <Match when={sessions() === null}>
          <div class={styles.LogEmpty}><Spinner size={14} /></div>
        </Match>
        <Match when={error()}>
          {message => <div class={styles.LogEmpty}>{message()}</div>}
        </Match>
        <Match when={sessions()!.length === 0}>
          <div class={styles.LogEmpty}>No terminal logs from the last {settings.terminal.logDays} days.</div>
        </Match>
        <Match when={true}>
          <div class={styles.LogList}>
            <For each={sessions()}>
              {session => (
                <div class={styles.LogRow}>
                  <span class={styles.LogText}>
                    <strong>{session.hostLabel}</strong>
                    <span>{timeFormat.format(new Date(session.startedAt))}, {formatBytes(session.bytes)}</span>
                  </span>
                  <Button size="sm" variant="subtle" onClick={() => void view(session)}>
                    <ScrollText size={13} />
                    Read
                  </Button>
                </div>
              )}
            </For>
          </div>
        </Match>
      </Branch>

      <Modal show={viewing() !== null} onHide={() => setViewing(null)} title={viewing()?.session.hostLabel} subtitle={subtitle()} width={860}>
        <div class={styles.LogView}>
          <Branch>
            <Match when={viewing()?.error}>
              {message => <EmptyState tone="danger" icon={CircleAlert} title="This log can't be read" description={message()} />}
            </Match>
            <Match when={viewing()?.text !== null && viewing()?.text !== undefined}>
              <CodeView value={viewing()?.text ?? ""} language="text" readOnly />
            </Match>
            <Match when={true}>
              <Spinner size={18} />
            </Match>
          </Branch>
        </div>
      </Modal>
    </SettingGroup>
  );
}

function TerminalSettings() {
  const { settings, updateTerminal } = useSettingsState;

  return (
    <SettingsPage title="Terminal" description="Defaults for every terminal. Colors follow the app theme.">
      <SettingGroup>
        <SettingRow name="Font" hint="A font that isn't installed falls back to the app's monospace font.">
          <Select value={settings.terminal.fontFamily} items={FONT_ITEMS} onChange={fontFamily => updateTerminal({ fontFamily })} />
        </SettingRow>
        <SettingRow name="Size">
          <Select value={settings.terminal.fontSize} items={SIZE_ITEMS} onChange={fontSize => updateTerminal({ fontSize })} />
        </SettingRow>
        <SettingRow name="Cursor">
          <Select value={settings.terminal.cursorStyle} items={CURSOR_ITEMS} onChange={cursorStyle => updateTerminal({ cursorStyle })} />
        </SettingRow>
        <SettingRow name="Scrollback" hint="Lines kept per pane, in memory only.">
          <Select value={settings.terminal.scrollback} items={SCROLLBACK_ITEMS} onChange={scrollback => updateTerminal({ scrollback })} />
        </SettingRow>
        <SettingRow name="Copy on select" hint="Selected text goes to the clipboard right away.">
          <Switch checked={settings.terminal.copyOnSelect} onChange={copyOnSelect => updateTerminal({ copyOnSelect })} />
        </SettingRow>
      </SettingGroup>

      <SettingGroup title="Logs">
        <SettingRow
          name="Save terminal output"
          hint="What terminals print is saved, encrypted with a key in the vault. What you type is never saved. Applies to terminals opened from now on."
        >
          <Switch checked={settings.terminal.logOutput} onChange={logOutput => updateTerminal({ logOutput })} />
        </SettingRow>
        <SettingRow name="Keep logs for" hint="Older days are deleted when Fran starts.">
          <Select value={settings.terminal.logDays} items={LOG_DAY_ITEMS} onChange={logDays => updateTerminal({ logDays })} />
        </SettingRow>
      </SettingGroup>

      <TerminalLogs />
    </SettingsPage>
  );
}

export default TerminalSettings;
