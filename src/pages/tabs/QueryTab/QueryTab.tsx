import styles from "./QueryTab.module.scss";
import {
  Accessor, For, Match, Owner, Show, Switch, createEffect, createMemo, createRoot, createSignal, getOwner, on, onCleanup, runWithOwner,
  untrack,
} from "solid-js";
import { Channel } from "@tauri-apps/api/core";
import {
  ArrowDownToLine, Check, CircleAlert, CircleCheck, Layers, Lock, Pencil, Play, Plus, Save, Search, Square, StepForward,
  Table2, Undo2, WandSparkles,
} from "@core/icons";
import { databaseModule } from "@core/databases";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage, isAppError } from "@core/helpers/errors";
import { formatDuration, plural } from "@core/helpers";
import { skipsConfirm } from "@core/helpers/platform";
import { buildCatalog, buildCompletionSchema } from "@core/helpers/catalog";
import {
  EditCheck, EditTarget, RowEdits, createRowEdits, findEditTarget, previewRowChanges, runRowChanges,
} from "@core/helpers/rowEdits";
import useWorkspaceState, { QueryTabState } from "@core/states/workspaceState";
import useSavedQueriesState from "@core/states/savedQueriesState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import { ResultSet, RunOutcome, StatementOutcome, StatementRange, TransactionState } from "@core/types";
import { statementAt } from "@core/helpers/statements";
import SqlEditor, { SqlEditorApi } from "@core/components/SqlEditor/SqlEditor";
import ResultGrid, { GridEditing } from "@core/components/ResultGrid/ResultGrid";
import ReviewSqlModal, { ApplySafety } from "@core/components/ReviewSqlModal/ReviewSqlModal";
import PendingChanges from "@core/components/PendingChanges/PendingChanges";
import Button from "@core/components/Button/Button";
import Input from "@core/components/Input/Input";
import Select from "@core/components/Select/Select";
import Spinner from "@core/components/Spinner/Spinner";
import EmptyState from "@core/components/EmptyState/EmptyState";
import { tooltip } from "@core/components/Tooltip/Tooltip";
import useSettingsState, { ROW_LIMITS } from "@core/states/settingsState";

export type QueryTabProps = {
  sessionId: string,
  database: string,
  tab: QueryTabState,
  active: boolean,
};

type ResultEntry = {
  set: ResultSet,
  label: string,
  edits: RowEdits,
  editing: Accessor<GridEditing | undefined>,
  target: Accessor<EditTarget | null>,
  readOnlyReason: Accessor<string | null>,
  replaceRows: (rows: ResultSet["rows"]) => void,
};

// `inTransaction`: the tab had a transaction open when the review started, so the changes join it.
type Review = { entry: ResultEntry, target: EditTarget, statements: string[], inTransaction: boolean };
// `inTransaction`: a transaction was open before or after the statement, so it opened, ran in or ended one.
type ShownOutcome = RunOutcome & { inTransaction: boolean };
type RunMode = "current" | "after" | "all";
type RunStat = { label: string, value: string, hint: string };

const SPLIT_DELAY = 200;
const TRANSACTION_CHECK_MS = 30_000;
type View = number | "messages";

function outcomeSummary(outcome: StatementOutcome): string {
  if (outcome.error) {
    const detail = outcome.error.detail;
    const errorCode = detail.kind === "database" ? detail.code ?? detail.sqlState : null;
    const code = errorCode !== null ? `Error ${errorCode}: ` : "";
    return `${code}${outcome.error.message}`;
  }

  if (outcome.resultSets.length > 0) {
    return outcome.resultSets
      .map(set => `${plural(set.rows.length, "row")} returned${set.truncated ? " (limit reached)" : ""}`)
      .join(", ");
  }

  const parts = [`${plural(outcome.affectedRows, "row")} affected`];
  if (outcome.lastInsertId) parts.push(`last insert id ${outcome.lastInsertId}`);
  if (outcome.warnings > 0) parts.push(plural(outcome.warnings, "warning"));
  if (outcome.info) parts.push(outcome.info);
  return parts.join(", ");
}

function QueryTab(props: QueryTabProps) {
  const workspace = useWorkspaceState;
  const savedQueries = useSavedQueriesState;
  const { askForText, confirm } = usePromptState;
  const { pushError, pushToast } = useToastState;

  const [running, setRunning] = createSignal(false);
  const [startedAt, setStartedAt] = createSignal(0);
  const [now, setNow] = createSignal(Date.now());
  const rowLimit = createMemo(() => props.tab.rowLimit);
  const [outcomes, setOutcomes] = createSignal<ShownOutcome[]>([]);
  const [runError, setRunError] = createSignal<unknown>(null);
  const [view, setView] = createSignal<View>("messages");
  const [editorShare, setEditorShare] = createSignal(0.45);
  const [hasRun, setHasRun] = createSignal(false);
  const [saving, setSaving] = createSignal(false);
  const [review, setReview] = createSignal<Review | null>(null);
  const [roundTrip, setRoundTrip] = createSignal(0);
  const [filterText, setFilterText] = createSignal("");
  const filter = createMemo(() => filterText().trim());

  const [statementRanges, setStatementRanges] = createSignal<StatementRange[]>([]);

  let editor: SqlEditorApi | undefined;
  let contextId: number | null = null;
  let splitTimer: ReturnType<typeof setTimeout> | undefined;
  onCleanup(() => clearTimeout(splitTimer));
  let body!: HTMLDivElement;

  const session = createMemo(() => workspace.store.sessions[props.sessionId]);
  const transaction = createMemo<TransactionState>(() => session()?.transactions[props.tab.id] ?? "none");
  const transactionHint = createMemo(() => (transaction() === "failed"
    ? "A statement failed inside the transaction. Only ROLLBACK works on this tab's connection until then."
    : "Changes made in this tab stay invisible to other connections and can be undone until COMMIT."));
  const kind = untrack(() => workspace.store.sessions[props.sessionId].info.kind);
  const dialect = databaseModule(kind).sqlDialect;

  const catalog = createMemo(() => {
    const current = session();
    return current ? buildCatalog(current, props.database) : null;
  });
  const completionSchema = createMemo(() => {
    const current = session();
    return current ? buildCompletionSchema(current) : undefined;
  });

  function createResultEntry(set: ResultSet, label: string): ResultEntry {
    const [rows, setRows] = createSignal(set.rows);
    const source = createMemo<ResultSet>(() => ({ ...set, rows: rows() }));
    const [check, setCheck] = createSignal<EditCheck | null>(null);
    const target = createMemo(() => {
      const current = check();
      return current && "target" in current ? current.target : null;
    });
    const readOnlyReason = createMemo(() => {
      const current = check();
      return current && "reason" in current ? current.reason : null;
    });

    if (set.columns.length > 0) {
      findEditTarget(props.sessionId, set.columns).then(setCheck, error => setCheck({ reason: errorMessage(error) }));
    }

    const edits = createRowEdits(source);
    const editing = createMemo(() => (target() ? edits.editing : undefined));

    return { set, label, edits, editing, target, readOnlyReason, replaceRows: setRows };
  }

  const [resultEntries, setResultEntries] = createSignal<ResultEntry[]>([]);
  let resultsOwner: Owner | null = null;
  let disposeResults: (() => void) | undefined;
  onCleanup(() => disposeResults?.());

  function clearResults() {
    disposeResults?.();
    createRoot(dispose => {
      disposeResults = dispose;
      resultsOwner = getOwner();
    });
    setOutcomes([]);
    setResultEntries([]);
  }

  function addOutcome(outcome: ShownOutcome) {
    const count = resultEntries().length;
    const entries = runWithOwner(resultsOwner, () =>
      outcome.resultSets.map((set, index) => createResultEntry(set, `Result ${count + index + 1}`)),
    ) ?? [];
    setOutcomes(current => [...current, outcome]);
    setResultEntries(current => [...current, ...entries]);
  }

  const runStats = createMemo<RunStat[]>(() => {
    const ran = outcomes();
    if (running() || ran.length === 0) return [];
    const server = ran.reduce((sum, outcome) => sum + outcome.executionMs, 0);
    const fetch = ran.reduce((sum, outcome) => sum + outcome.fetchMs, 0);
    const network = ran[0].networkMs;

    const stats: RunStat[] = [
      { label: "Server", value: formatDuration(server), hint: "Time until the server replied, with the network round trip taken out" },
    ];
    if (network !== null) {
      stats.push({ label: "Network", value: formatDuration(network), hint: "One round trip to the server, measured with a ping before the run" });
    }
    stats.push(
      { label: "Fetch", value: formatDuration(fetch), hint: "Receiving and converting the rows after the server replied" },
      { label: "Total", value: formatDuration(roundTrip()), hint: "From sending the query until the results reached the app" },
    );
    return stats;
  });
  const failed = createMemo(() => runError() !== null || outcomes().some(outcome => outcome.error));
  const reviewSafety = createMemo<ApplySafety>(() => (review()?.inTransaction ? { kind: "openTransaction" } : { kind: "transaction" }));
  const pendingChanges = createMemo(() => resultEntries().reduce((sum, entry) => sum + entry.edits.changeCount(), 0));
  const activeResult = createMemo(() => {
    const current = view();
    return typeof current === "number" ? resultEntries()[current] : undefined;
  });

  createEffect(() => {
    if (!running()) return;
    const timer = setInterval(() => setNow(Date.now()), 100);
    onCleanup(() => clearInterval(timer));
  });

  createEffect(() => {
    if (props.active) queueMicrotask(() => editor?.focus());
  });

  // The server can close an idle connection on its own (timeouts, restarts), which rolls the transaction back.
  createEffect(on(transaction, state => {
    if (state === "none") return;
    const timer = setInterval(() => void checkTransaction(), TRANSACTION_CHECK_MS);
    onCleanup(() => clearInterval(timer));
  }));

  async function checkTransaction() {
    const id = contextId;
    if (id === null || running() || transaction() === "none") return;
    let state: TransactionState;
    try {
      state = await safeInvoke("check_transaction", { sessionId: props.sessionId, contextId: id });
    } catch {
      return;
    }
    if (state === "none" && transaction() !== "none" && !running()) {
      workspace.setTabTransaction(props.sessionId, props.tab.id, "none");
      pushToast(`The connection of ${props.tab.title} closed, so the server rolled back its open transaction.`, "error", 8000);
    }
  }

  onCleanup(() => {
    if (contextId !== null) {
      safeInvoke("close_query_context", { sessionId: props.sessionId, contextId }).catch(() => {});
    }
  });

  // Saving copies the text into a new saved query. The tab stays an ordinary tab.
  async function saveAsQuery() {
    if (!editor || saving()) return;
    const sql = editor.text();
    const profile = session()?.profile;
    if (!profile || !sql.trim()) return;

    const name = await askForText({ title: "Save as query", label: "Name", initial: props.tab.title, confirmLabel: "Save" });
    if (!name) return;

    setSaving(true);
    try {
      const saved = await savedQueries.save({
        id: "",
        name,
        sql,
        connectionId: profile.id,
        database: props.database,
        updatedAt: 0,
      });
      pushToast(`Saved as ${saved.name}`, "success", 2000);
    } catch (error) {
      pushError(error);
    } finally {
      setSaving(false);
    }
  }

  function formatSql() {
    if (!editor) return;
    const selection = editor.selection();
    const partial = selection.text.trim() !== "";
    const source = partial ? selection.text : editor.text();
    if (!source.trim()) return;

    let formatted: string;
    try {
      formatted = databaseModule(kind).formatSql(source, useSettingsState.settings.format);
    } catch (error) {
      pushError(error);
      return;
    }
    if (formatted !== source) {
      if (partial) editor.replace(selection.from, selection.to, formatted);
      else editor.setText(formatted);
    }
    editor.focus();
  }

  function changeRowLimit(limit: number) {
    const sql = workspace.setRowLimit(props.sessionId, props.database, props.tab.id, limit);
    if (sql !== null) editor?.setText(sql);
  }

  async function ensureContext(): Promise<number> {
    if (contextId === null) {
      contextId = await safeInvoke("open_query_context", { sessionId: props.sessionId, database: props.database });
    }
    return contextId;
  }

  function scheduleSplit(text: string) {
    clearTimeout(splitTimer);
    splitTimer = setTimeout(async () => {
      try {
        const ranges = await safeInvoke("split_sql", { kind, sql: text });
        if (editor?.text() === text) setStatementRanges(ranges);
      } catch {
        setStatementRanges([]);
      }
    }, SPLIT_DELAY);
  }

  // "after" runs the statement at the cursor and everything below it, ignoring any selection.
  async function statementToRun(mode: RunMode): Promise<string | null> {
    if (!editor) return null;

    const selection = editor.selection();
    if (mode !== "after" && selection.text.trim()) return selection.text;

    const text = editor.text();
    if (mode === "all") return text;

    const ranges = await safeInvoke("split_sql", { kind, sql: text });
    const index = statementAt(ranges, mode === "after" ? selection.from : editor.cursor());
    if (index === -1) return null;
    return mode === "after" ? text.slice(ranges[index].start) : ranges[index].text;
  }

  // `given` runs that SQL instead of the editor's, for Commit and Rollback. `force` drops unapplied grid changes without asking.
  async function run(mode: RunMode, given?: string, force = false) {
    if (running()) return;

    if (!force && pendingChanges() > 0) {
      const discard = await confirm({
        title: "Discard changes?",
        message: `${plural(pendingChanges(), "unapplied change")} in the results will be lost.`,
        confirmLabel: "Discard and run",
        danger: true,
      });
      if (!discard) return;
    }

    let sql: string | null;
    try {
      sql = given ?? await statementToRun(mode);
    } catch (error) {
      pushError(error);
      return;
    }
    if (!sql?.trim()) return;

    setRunning(true);
    setStartedAt(Date.now());
    setNow(Date.now());
    setRunError(null);
    setHasRun(true);

    const received: RunOutcome[] = [];
    let before = transaction();
    let expected = Infinity;
    let finished = false;
    let allReceived!: () => void;
    const receivedAll = new Promise<void>(resolve => { allReceived = resolve; });

    const channel = new Channel<RunOutcome>();
    channel.onmessage = outcome => {
      if (finished) return;
      if (received.length === 0) {
        clearResults();
        setView("messages");
      }
      received.push(outcome);
      addOutcome({ ...outcome, inTransaction: before !== "none" || outcome.transaction !== "none" });
      before = outcome.transaction;
      workspace.setTabTransaction(props.sessionId, props.tab.id, outcome.transaction);
      if (received.length >= expected) allReceived();
    };

    try {
      const id = await ensureContext();
      const sent = performance.now();
      expected = await safeInvoke("execute_query", {
        sessionId: props.sessionId,
        contextId: id,
        sql,
        rowLimit: rowLimit(),
        onOutcome: channel,
      });
      // Channel messages can arrive after the command's reply, so wait for the count it sent.
      if (received.length >= expected) allReceived();
      await receivedAll;
      setRoundTrip(performance.now() - sent);

      if (received.length === 0) clearResults();
      const only = received.length === 1 ? received[0] : null;
      if (only && only.resultSets.length > 0 && !only.error) setView(0);

      const changes = received.flatMap(outcome => (outcome.schemaChange ? [outcome.schemaChange] : []));
      void workspace.applySchemaChanges(props.sessionId, props.database, changes);
    } catch (error) {
      if (isAppError(error) && error.detail.kind === "notFound") contextId = null;
      if (received.length === 0) clearResults();
      setRunError(error);
      setView("messages");
      void refreshTransaction();
    } finally {
      finished = true;
      setRunning(false);
    }
  }

  // A separate connection would sit outside the user's transaction and wait on the rows it locked, so grid changes
  // run on the tab's own connection and become part of it. Resolves to an error message, or null.
  async function runInOpenTransaction(statements: string[]): Promise<string | null> {
    const received: RunOutcome[] = [];
    let expected = Infinity;
    let allReceived!: () => void;
    const receivedAll = new Promise<void>(resolve => { allReceived = resolve; });
    const channel = new Channel<RunOutcome>();
    channel.onmessage = outcome => {
      received.push(outcome);
      workspace.setTabTransaction(props.sessionId, props.tab.id, outcome.transaction);
      if (received.length >= expected) allReceived();
    };

    try {
      const id = await ensureContext();
      const sql = statements.map(statement => `${statement};`).join("\n");
      expected = await safeInvoke("execute_query", { sessionId: props.sessionId, contextId: id, sql, rowLimit: 0, onOutcome: channel });
      if (received.length >= expected) allReceived();
      await receivedAll;
    } catch (error) {
      void refreshTransaction();
      return errorMessage(error);
    }

    const index = received.findIndex(outcome => outcome.error !== null);
    if (index === -1) return null;
    const kept = index > 0 ? " The ones before it are part of the transaction, so Rollback undoes them." : "";
    return `Statement ${index + 1} failed: ${received[index].error?.message ?? "unknown error"}.${kept}`;
  }

  // A run can fail before any statement, like when a reconnect lost the open transaction, so Rust is asked.
  async function refreshTransaction() {
    const id = contextId;
    if (id === null) {
      workspace.setTabTransaction(props.sessionId, props.tab.id, "none");
      return;
    }
    try {
      const state = await safeInvoke("get_transaction_state", { sessionId: props.sessionId, contextId: id });
      workspace.setTabTransaction(props.sessionId, props.tab.id, state);
    } catch {
      workspace.setTabTransaction(props.sessionId, props.tab.id, "none");
    }
  }

  async function startReview(entry: ResultEntry) {
    const target = entry.target();
    if (!target) return;
    try {
      const statements = await previewRowChanges(props.sessionId, target, entry.edits.changes());
      setReview({ entry, target, statements, inTransaction: transaction() === "open" });
    } catch (error) {
      pushError(error);
    }
  }

  async function applyReview(): Promise<string | null> {
    const current = review();
    if (!current) return null;

    const failure = current.inTransaction
      ? await runInOpenTransaction(current.statements)
      : await runRowChanges(props.sessionId, current.target.database, current.statements);
    if (failure) return failure;

    const applied = current.entry.edits.changeCount();
    const inserted = current.entry.edits.changes().some(change => change.kind === "insert");
    current.entry.replaceRows(current.entry.edits.savedRows());
    const where = current.inTransaction ? " in the open transaction. Commit to keep them." : ".";
    pushToast(
      inserted
        ? `Applied ${plural(applied, "change")}${where} Run the query again to see the new rows.`
        : `Applied ${plural(applied, "change")}${where}`,
      "success",
      inserted || current.inTransaction ? 4000 : 2500,
    );
    return null;
  }

  async function stop() {
    if (contextId === null) return;
    try {
      await safeInvoke("cancel_query", { sessionId: props.sessionId, contextId });
    } catch (error) {
      pushError(error);
    }
  }

  function startResize(event: MouseEvent) {
    event.preventDefault();
    const rect = body.getBoundingClientRect();

    function onMove(move: MouseEvent) {
      setEditorShare(Math.min(0.85, Math.max(0.12, (move.clientY - rect.top) / rect.height)));
    }

    function onUp() {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.removeProperty("cursor");
    }

    document.body.style.cursor = "row-resize";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }

  return (
    <div class={styles.QueryTab}>
      <div class={styles.Toolbar}>
        <Button variant="primary" size="sm" onClick={event => run("all", undefined, skipsConfirm(event))} disabled={running()} tooltip="Run everything, or the selection (Ctrl+Shift+Enter)">
          <Play size={12} />
          Run all
        </Button>
        <Button size="sm" onClick={event => run("current", undefined, skipsConfirm(event))} disabled={running()} tooltip="Run the highlighted statement, or the selection (Ctrl+Enter)">
          <StepForward size={14} />
          Run
        </Button>
        <Button size="sm" onClick={event => run("after", undefined, skipsConfirm(event))} disabled={running()} tooltip="Run the highlighted statement and everything after it">
          <ArrowDownToLine size={14} />
          Run all after
        </Button>
        <Button size="sm" onClick={stop} disabled={!running()} tooltip="Stop the running query">
          <Square size={12} />
          Stop
        </Button>
        <div class={styles.Separator} />
        <Select size="sm" value={rowLimit()} items={ROW_LIMITS} onChange={changeRowLimit} />
        <Button size="sm" onClick={formatSql} tooltip="Format the SQL, or only the selection (Shift+Alt+F)">
          <WandSparkles size={14} />
          Format
        </Button>
        <Button size="sm" onClick={saveAsQuery} disabled={saving()} tooltip="Save as a new saved query (Ctrl+S)">
          <Save size={14} />
          Save as query
        </Button>
        <div class={styles.Spacer} />
        <Show when={transaction() !== "none"}>
          <div class={styles.Transaction} classList={{ [styles.TransactionFailed]: transaction() === "failed" }}>
            <span class={styles.TransactionLabel} ref={element => tooltip(element, transactionHint)}>
              <Layers size={13} />
              {transaction() === "failed" ? "Transaction failed" : "Transaction open"}
            </span>
            <Show when={transaction() === "open"}>
              <Button size="sm" variant="subtle" disabled={running()} onClick={event => run("all", "COMMIT", skipsConfirm(event))} tooltip="Run COMMIT in this tab">
                <Check size={13} />
                Commit
              </Button>
            </Show>
            <Button size="sm" variant="subtle" disabled={running()} onClick={event => run("all", "ROLLBACK", skipsConfirm(event))} tooltip="Run ROLLBACK in this tab">
              <Undo2 size={13} />
              Rollback
            </Button>
          </div>
        </Show>
        <Show when={running()}>
          <span class={styles.Status}>
            <Spinner size={12} />
            Running {formatDuration(now() - startedAt())}
          </span>
        </Show>
      </div>

      <div ref={body} class={styles.Body}>
        <div class={styles.EditorPane} style={{ height: `${editorShare() * 100}%` }}>
          <SqlEditor
            initialValue={untrack(() => workspace.queryText(props.tab))}
            dialect={dialect}
            schema={completionSchema()}
            defaultSchema={props.database}
            catalog={catalog()}
            statements={statementRanges()}
            onChange={text => {
              workspace.setQueryText(props.sessionId, props.tab.id, text);
              scheduleSplit(text);
            }}
            onRunCurrent={() => run("current")}
            onRunAll={() => run("all")}
            onSave={saveAsQuery}
            onFormat={formatSql}
            onReady={api => {
              editor = api;
              scheduleSplit(api.text());
              if (props.active) api.focus();
              if (untrack(() => props.tab.runOnOpen)) {
                workspace.clearRunOnOpen(props.sessionId, props.database, props.tab.id);
                run("all");
              }
            }}
          />
        </div>

        <div class={styles.Splitter} onMouseDown={startResize} />

        <div class={styles.ResultsPane}>
          <Show
            when={hasRun()}
            fallback={
              <EmptyState
                title="No results yet"
                description="Ctrl+Enter runs the statement under the cursor. Ctrl+Shift+Enter runs the whole editor or the selection."
              />
            }
          >
            <div class={styles.ResultTabs}>
              <For each={resultEntries()}>
                {(entry, index) => (
                  <button
                    class={styles.ResultTab}
                    classList={{ [styles.Active]: view() === index() }}
                    onClick={() => setView(index())}
                  >
                    <Table2 size={14} />
                    {entry.label}
                    <span class={styles.Count}>{entry.set.rows.length.toLocaleString()}</span>
                  </button>
                )}
              </For>
              <button
                class={styles.ResultTab}
                classList={{ [styles.Active]: view() === "messages", [styles.HasError]: failed() }}
                onClick={() => setView("messages")}
              >
                {failed() ? <CircleAlert size={14} /> : <CircleCheck size={14} />}
                Messages
              </button>
              <div class={styles.Spacer} />
              <Show when={activeResult()}>
                {entry => (
                  <>
                    <Input
                      class={`${styles.Filter} ${filter() ? styles.Filtering : ""}`}
                      value={filterText()}
                      placeholder="Filter rows"
                      onValue={setFilterText}
                      clearable
                      before={<Search size={12} />}
                    />
                    <Show
                      when={entry().target()}
                      fallback={
                        <Show when={entry().readOnlyReason()}>
                          {reason => (
                            <span class={styles.EditState} ref={element => tooltip(element, reason)}>
                              <Lock size={12} />
                              Read only
                            </span>
                          )}
                        </Show>
                      }
                    >
                      {target => (
                        <>
                          <span
                            class={styles.EditState}
                            ref={element => tooltip(element, () => `Double-click a cell to edit. Changes are written to ${target().database}.${target().table}.`)}
                          >
                            <Pencil size={12} />
                            {target().table}
                          </span>
                          <Button size="sm" class={styles.AddRow} onClick={() => entry().edits.addRow()} tooltip={`Add a row to ${target().table}`}>
                            <Plus size={14} />
                            Add row
                          </Button>
                        </>
                      )}
                    </Show>
                    <Show when={entry().edits.changeCount() > 0}>
                      <PendingChanges
                        count={entry().edits.changeCount()}
                        onDiscard={entry().edits.discard}
                        onApply={() => startReview(entry())}
                      />
                    </Show>
                  </>
                )}
              </Show>
            </div>

            <div class={styles.ResultContent}>
              <Switch>
                <Match when={activeResult()}>
                  {entry => (
                    <>
                      <div class={styles.Grid}>
                        <ResultGrid
                          columns={entry().set.columns}
                          rows={entry().edits.rows()}
                          editing={entry().editing()}
                          highlight={filter()}
                          filter
                          sessionId={props.sessionId}
                        />
                      </div>
                      <Show when={entry().set.truncated}>
                        <div class={styles.Truncated}>
                          Showing the first {entry().set.rows.length.toLocaleString()} rows. Raise the limit to see more.
                        </div>
                      </Show>
                    </>
                  )}
                </Match>
                <Match when={view() === "messages"}>
                  <div class={styles.Messages}>
                    <Show when={runStats().length > 0}>
                      <div class={styles.Stats}>
                        <For each={runStats()}>
                          {stat => (
                            <span class={styles.Stat} ref={element => tooltip(element, () => stat.hint)}>
                              <span class={styles.StatLabel}>{stat.label}</span>
                              <span class={styles.StatValue}>{stat.value}</span>
                            </span>
                          )}
                        </For>
                      </div>
                    </Show>
                    <Show when={runError()}>
                      <div class={`${styles.Message} ${styles.Failed}`}>
                        <CircleAlert size={14} />
                        <span class={styles.MessageText}>{errorMessage(runError())}</span>
                      </div>
                    </Show>
                    <For each={outcomes()}>
                      {(outcome, index) => (
                        <div
                          class={styles.Message}
                          classList={{ [styles.Failed]: outcome.error !== null, [styles.InTransaction]: outcome.inTransaction }}
                        >
                          {outcome.error ? <CircleAlert size={14} /> : <CircleCheck size={14} />}
                          <span class={styles.Index}>{index() + 1}</span>
                          <span class={styles.Sql} ref={element => tooltip(element, () => outcome.sql)}>
                            {outcome.sql.replace(/\s+/g, " ")}
                          </span>
                          <span class={styles.MessageText}>{outcomeSummary(outcome)}</span>
                          <span
                            class={styles.Duration}
                            ref={element => tooltip(element, () => `Server ${formatDuration(outcome.executionMs)}, fetch ${formatDuration(outcome.fetchMs)}`)}
                          >
                            {formatDuration(outcome.executionMs)}
                            <Show when={outcome.fetchMs >= 1}>
                              <span class={styles.FetchPart}> + {formatDuration(outcome.fetchMs)} fetch</span>
                            </Show>
                          </span>
                        </div>
                      )}
                    </For>
                  </div>
                </Match>
              </Switch>
            </div>
          </Show>
        </div>
      </div>

      <ReviewSqlModal
        statements={review()?.statements ?? null}
        title="Apply changes"
        description={review() ? `Row changes to ${review()!.target.database}.${review()!.target.table}` : ""}
        dialect={dialect}
        safety={reviewSafety()}
        onApply={applyReview}
        onClose={() => setReview(null)}
      />
    </div>
  );
}

export default QueryTab;
