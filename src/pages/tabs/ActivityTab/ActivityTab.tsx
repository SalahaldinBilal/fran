import styles from "./ActivityTab.module.scss";
import { For, Match, Show, Switch, createEffect, createMemo, createSignal, onCleanup, untrack } from "solid-js";
import { ArrowDown, ArrowUp, CircleAlert, Copy, Info, Pause, Play, RefreshCw, Search, SquareTerminal } from "@core/icons";
import useWorkspaceState from "@core/states/workspaceState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage } from "@core/helpers/errors";
import { copyText } from "@core/helpers/clipboard";
import { formatCount, formatDuration, plural } from "@core/helpers";
import { HistoryOrder, QueryHistory, RunningQueries, StatementStats } from "@core/types";
import Button from "@core/components/Button/Button";
import Input from "@core/components/Input/Input";
import SegmentedControl, { SegmentedOption } from "@core/components/SegmentedControl/SegmentedControl";
import Spinner from "@core/components/Spinner/Spinner";
import EmptyState from "@core/components/EmptyState/EmptyState";
import { tooltip } from "@core/components/Tooltip/Tooltip";
import ActivityNoticeView from "./ActivityNoticeView";

type View = "history" | "running";
type SortKey = HistoryOrder;
type Sort = { key: SortKey, descending: boolean };

const RUNNING_REFRESH_MS = 3000;
const ORDER_LABELS: Record<HistoryOrder, string> = {
  calls: "calls",
  totalMs: "total time",
  meanMs: "mean time",
  maxMs: "max time",
  rows: "rows",
};

export type ActivityTabProps = {
  sessionId: string,
  database: string,
  tabId: string,
};

function formatSpan(ms: number): string {
  if (ms < 60_000) return formatDuration(ms);
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${minutes} min ${Math.floor((ms % 60_000) / 1000)} s`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

function formatRunning(ms: number, wholeSeconds: boolean): string {
  if (wholeSeconds && ms < 60_000) return ms < 1000 ? "under 1 s" : `${Math.floor(ms / 1000)} s`;
  return formatSpan(ms);
}

function matches(needle: string, values: Array<string | null>): boolean {
  return values.some(value => value?.toLowerCase().includes(needle));
}

function SortHeader(props: { label: string, sortKey: SortKey, sort: Sort, onSort: (key: SortKey) => void }) {
  const current = createMemo(() => props.sort.key === props.sortKey);
  return (
    <th class={styles.Numeric}>
      <button type="button" class={styles.SortButton} classList={{ [styles.Sorted]: current() }} onClick={() => props.onSort(props.sortKey)}>
        {props.label}
        <Show when={current()}>
          {props.sort.descending ? <ArrowDown size={12} /> : <ArrowUp size={12} />}
        </Show>
      </button>
    </th>
  );
}

function ActivityTab(props: ActivityTabProps) {
  const workspace = useWorkspaceState;
  const support = untrack(() => workspace.store.sessions[props.sessionId].info.activity);

  const [view, setView] = createSignal<View>(support.history ? "history" : "running");
  const [history, setHistory] = createSignal<QueryHistory | null>(null);
  const [running, setRunning] = createSignal<RunningQueries | null>(null);
  const [errors, setErrors] = createSignal<Record<View, unknown>>({ history: null, running: null });
  const [loading, setLoading] = createSignal<Record<View, boolean>>({ history: false, running: false });
  const [filter, setFilter] = createSignal("");
  const [sort, setSort] = createSignal<Sort>({ key: "meanMs", descending: true });
  // The column the server picked the loaded statements by.
  const [fetchedBy, setFetchedBy] = createSignal<HistoryOrder>("meanMs");
  const [expanded, setExpanded] = createSignal<string | null>(null);
  const [paused, setPaused] = createSignal(false);

  const views = createMemo(() => {
    const options: SegmentedOption<View>[] = [];
    if (support.history) options.push({ value: "history", label: "History", count: history()?.statements.length });
    if (support.running) options.push({ value: "running", label: "Running now", count: running()?.queries.length });
    return options;
  });

  const visible = createMemo(() => {
    const session = workspace.store.sessions[props.sessionId];
    return workspace.store.activeGlobalTabId === props.sessionId
      && session?.selectedDatabase === props.database
      && session.scopes[props.database]?.activeTabId === props.tabId;
  });

  const error = createMemo(() => errors()[view()]);
  const busy = createMemo(() => loading()[view()]);
  const filtering = createMemo(() => filter().trim() !== "");
  const pauseLabel = createMemo(() => (paused() ? "Resume updates" : "Pause updates"));
  const errorTitle = createMemo(() => (view() === "history" ? "Couldn't read the query history" : "Couldn't list running queries"));
  const emptyHistoryTitle = createMemo(() => (filtering() ? "No statements match the filter" : "No statements recorded yet"));
  const emptyHistoryDetail = createMemo(() => (filtering() ? undefined : "The server hasn't counted any statements since its statistics were last reset."));
  const emptyRunningTitle = createMemo(() => (filtering() ? "No queries match the filter" : "Nothing running right now"));
  const emptyRunningDetail = createMemo(() => (filtering() ? undefined : "Queries from every client show here while they run."));

  const statements = createMemo(() => {
    const needle = filter().trim().toLowerCase();
    const all = history()?.statements ?? [];
    const found = needle ? all.filter(stats => matches(needle, [stats.text, stats.sample, stats.database, stats.user])) : all;
    const { key, descending } = sort();
    return [...found].sort((a, b) => {
      const difference = (a[key] ?? -1) - (b[key] ?? -1);
      return descending ? -difference : difference;
    });
  });

  const queries = createMemo(() => {
    const needle = filter().trim().toLowerCase();
    const all = running()?.queries ?? [];
    return needle ? all.filter(query => matches(needle, [query.text, query.user, query.database, query.client, query.state])) : all;
  });

  const hasMax = createMemo(() => history()?.statements.some(stats => stats.maxMs !== null) ?? false);
  const hasRows = createMemo(() => history()?.statements.some(stats => stats.rows !== null) ?? false);
  const hasExamined = createMemo(() => history()?.statements.some(stats => stats.rowsExamined !== null) ?? false);
  const hasUser = createMemo(() => history()?.statements.some(stats => stats.user !== null) ?? false);
  const historyColumns = createMemo(() => 4 + Number(hasMax()) + Number(hasRows()) + Number(hasExamined()) + Number(hasUser()));

  async function load(target: View) {
    if (untrack(loading)[target]) return;
    setLoading(current => ({ ...current, [target]: true }));
    try {
      if (target === "history") {
        const order = untrack(sort).key;
        setHistory(await safeInvoke("get_query_history", { sessionId: props.sessionId, order }));
        setFetchedBy(order);
      } else {
        setRunning(await safeInvoke("get_running_queries", { sessionId: props.sessionId }));
      }
      setErrors(current => ({ ...current, [target]: null }));
    } catch (loadError) {
      setErrors(current => ({ ...current, [target]: loadError }));
    } finally {
      setLoading(current => ({ ...current, [target]: false }));
    }
  }

  createEffect(() => {
    if (visible() && view() === "history" && untrack(history) === null && untrack(errors).history === null) {
      void load("history");
    }
  });

  createEffect(() => {
    if (!visible() || view() !== "running" || paused()) return;
    untrack(() => void load("running"));
    const timer = setInterval(() => void load("running"), RUNNING_REFRESH_MS);
    onCleanup(() => clearInterval(timer));
  });

  function changeSort(key: SortKey) {
    setSort(current => (current.key === key ? { key, descending: !current.descending } : { key, descending: true }));
  }

  function toggle(id: string) {
    setExpanded(current => (current === id ? null : id));
  }

  function openInQuery(sql: string) {
    workspace.newQueryTab(props.sessionId, props.database, sql);
  }

  function statementSql(stats: StatementStats): string {
    return stats.sample ?? stats.text;
  }

  // Sorting only reorders what was loaded. When the server had more, another column may pick other statements.
  const sortHint = createMemo(() => {
    const current = history();
    if (!current?.limited || sort().key === fetchedBy()) return null;
    const count = current.statements.length;
    return `These are the top ${count} by ${ORDER_LABELS[fetchedBy()]}. Reload to get the top ${count} by ${ORDER_LABELS[sort().key]}.`;
  });

  const footer = createMemo(() => {
    if (view() === "history") {
      const current = history();
      if (!current || current.statements.length === 0) return null;
      const shown = current.limited
        ? `Top ${current.statements.length} statements by ${ORDER_LABELS[fetchedBy()]}`
        : plural(current.statements.length, "statement");
      const parts = [`${shown} from ${current.source}`];
      if (current.since) parts.push(`counting since ${current.since}`);
      return parts.join(", ");
    }
    const current = running();
    if (!current) return null;
    const state = paused() ? "updates paused" : `updates every ${RUNNING_REFRESH_MS / 1000} s`;
    return `${plural(current.queries.length, "query", "queries")} running, ${state}`;
  });

  return (
    <div class={styles.ActivityTab}>
      <div class={styles.Toolbar}>
        <span class={styles.Title}>Slow queries</span>
        <Show when={views().length > 1}>
          <SegmentedControl value={view()} options={views()} onChange={next => { setView(next); setExpanded(null); }} />
        </Show>
        <div class={styles.Spacer} />
        <Input
          type="search"
          value={filter()}
          onValue={setFilter}
          placeholder="Filter statements"
          clearable
          before={<Search size={14} class={styles.SearchIcon} />}
          class={styles.Filter}
        />
        <Show when={busy()}><Spinner size={14} /></Show>
        <Show when={view() === "running"}>
          <Button icon size="sm" tooltip={pauseLabel()} onClick={() => setPaused(current => !current)}>
            {paused() ? <Play size={14} /> : <Pause size={14} />}
          </Button>
        </Show>
        <Button icon size="sm" tooltip="Reload" disabled={busy()} onClick={() => load(view())}>
          <RefreshCw size={14} />
        </Button>
      </div>

      <div class={styles.Content}>
        <Switch>
          <Match when={error()}>
            <EmptyState
              tone="danger"
              icon={CircleAlert}
              title={errorTitle()}
              description={errorMessage(error())}
              actions={<Button variant="subtle" onClick={() => load(view())}>Try again</Button>}
            />
          </Match>

          <Match when={view() === "history" && history()}>
            {current => (
              <Show
                when={current().notice?.kind !== "unavailable"}
                fallback={<div class={styles.NoticeWrap}><ActivityNoticeView notice={current().notice!} /></div>}
              >
                <div class={styles.TableWrap}>
                  <Show when={current().notice}>
                    {notice => <ActivityNoticeView notice={notice()} compact />}
                  </Show>
                  <Show when={sortHint()}>
                    {hint => (
                      <div class={styles.SortHint}>
                        <Info size={14} class={styles.SortHintIcon} />
                        <span>{hint()}</span>
                        <Button size="sm" variant="subtle" disabled={busy()} onClick={() => load("history")}>
                          <RefreshCw size={14} />
                          Reload
                        </Button>
                      </div>
                    )}
                  </Show>
                  <Show
                    when={statements().length > 0}
                    fallback={
                      <EmptyState title={emptyHistoryTitle()} description={emptyHistoryDetail()} />
                    }
                  >
                    <table class={styles.Table}>
                      <thead>
                        <tr>
                          <th class={styles.StatementColumn}>Statement</th>
                          <th>Database</th>
                          <Show when={hasUser()}><th>User</th></Show>
                          <SortHeader label="Calls" sortKey="calls" sort={sort()} onSort={changeSort} />
                          <SortHeader label="Total" sortKey="totalMs" sort={sort()} onSort={changeSort} />
                          <SortHeader label="Mean" sortKey="meanMs" sort={sort()} onSort={changeSort} />
                          <Show when={hasMax()}><SortHeader label="Max" sortKey="maxMs" sort={sort()} onSort={changeSort} /></Show>
                          <Show when={hasRows()}><SortHeader label="Rows" sortKey="rows" sort={sort()} onSort={changeSort} /></Show>
                          <Show when={hasExamined()}><th class={styles.Numeric}>Examined</th></Show>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={statements()}>
                          {stats => (
                            <>
                              <tr class={styles.Row} classList={{ [styles.Open]: expanded() === stats.id }} onClick={() => toggle(stats.id)}>
                                <td class={styles.Statement}><span>{stats.text}</span></td>
                                <td class={styles.Muted}>{stats.database ?? ""}</td>
                                <Show when={hasUser()}><td class={styles.Muted}>{stats.user ?? ""}</td></Show>
                                <td class={styles.Numeric}>{stats.calls.toLocaleString()}</td>
                                <td class={`${styles.Numeric} ${styles.Strong}`}>{formatSpan(stats.totalMs)}</td>
                                <td class={styles.Numeric}>{formatSpan(stats.meanMs)}</td>
                                <Show when={hasMax()}>
                                  <td class={styles.Numeric}>{stats.maxMs === null ? "" : formatSpan(stats.maxMs)}</td>
                                </Show>
                                <Show when={hasRows()}>
                                  <td class={styles.Numeric}>{stats.rows === null ? "" : formatCount(stats.rows)}</td>
                                </Show>
                                <Show when={hasExamined()}>
                                  <td class={styles.Numeric}>{stats.rowsExamined === null ? "" : formatCount(stats.rowsExamined)}</td>
                                </Show>
                              </tr>
                              <Show when={expanded() === stats.id}>
                                <tr class={styles.DetailRow}>
                                  <td colSpan={historyColumns()}>
                                    <div class={styles.Detail}>
                                      <pre class={styles.Sql}>{stats.text}</pre>
                                      <Show when={stats.sample && stats.sample !== stats.text}>
                                        <div class={styles.DetailLabel}>A recent run</div>
                                        <pre class={styles.Sql}>{stats.sample}</pre>
                                      </Show>
                                      <div class={styles.DetailBar}>
                                        <Show when={stats.lastSeen}>
                                          <span class={styles.Muted}>Last run {stats.lastSeen}</span>
                                        </Show>
                                        <div class={styles.Spacer} />
                                        <Button size="sm" onClick={() => copyText(statementSql(stats), "statement")}>
                                          <Copy size={14} />
                                          Copy
                                        </Button>
                                        <Button size="sm" onClick={() => openInQuery(statementSql(stats))}>
                                          <SquareTerminal size={14} />
                                          Open in a query tab
                                        </Button>
                                      </div>
                                    </div>
                                  </td>
                                </tr>
                              </Show>
                            </>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </Show>
                </div>
              </Show>
            )}
          </Match>

          <Match when={view() === "running" && running()}>
            {current => (
              <div class={styles.TableWrap}>
                <Show when={current().notice}>
                  {notice => <ActivityNoticeView notice={notice()} compact />}
                </Show>
                <Show
                  when={queries().length > 0}
                  fallback={
                    <EmptyState title={emptyRunningTitle()} description={emptyRunningDetail()} />
                  }
                >
                  <table class={styles.Table}>
                    <thead>
                      <tr>
                        <th class={styles.Numeric}>Running for</th>
                        <th class={styles.StatementColumn}>Statement</th>
                        <th>State</th>
                        <th>User</th>
                        <th>Database</th>
                        <th>Client</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={queries()}>
                        {query => (
                          <>
                            <tr class={styles.Row} classList={{ [styles.Open]: expanded() === query.id }} onClick={() => toggle(query.id)}>
                              <td class={`${styles.Numeric} ${styles.Strong}`}>
                                {query.runningMs === null ? "" : formatRunning(query.runningMs, current().wholeSeconds)}
                              </td>
                              <td class={styles.Statement}>
                                <span>{query.text ?? ""}</span>
                              </td>
                              <td class={styles.Muted}>
                                <span class={styles.Ellipsis} ref={element => tooltip(element, () => query.state ?? "")}>{query.state ?? ""}</span>
                              </td>
                              <td class={styles.Muted}>{query.user ?? ""}</td>
                              <td class={styles.Muted}>{query.database ?? ""}</td>
                              <td class={styles.Muted}>{query.client ?? ""}</td>
                            </tr>
                            <Show when={expanded() === query.id && query.text}>
                              {text => (
                                <tr class={styles.DetailRow}>
                                  <td colSpan={6}>
                                    <div class={styles.Detail}>
                                      <pre class={styles.Sql}>{text()}</pre>
                                      <div class={styles.DetailBar}>
                                        <span class={styles.Muted}>Session {query.id}</span>
                                        <div class={styles.Spacer} />
                                        <Button size="sm" onClick={() => copyText(text(), "statement")}>
                                          <Copy size={14} />
                                          Copy
                                        </Button>
                                        <Button size="sm" onClick={() => openInQuery(text())}>
                                          <SquareTerminal size={14} />
                                          Open in a query tab
                                        </Button>
                                      </div>
                                    </div>
                                  </td>
                                </tr>
                              )}
                            </Show>
                          </>
                        )}
                      </For>
                    </tbody>
                  </table>
                </Show>
              </div>
            )}
          </Match>

          <Match when={true}>
            <div class={styles.Center}><Spinner size={20} /></div>
          </Match>
        </Switch>
      </div>

      <Show when={footer()}>
        {text => <div class={styles.Footer}>{text()}</div>}
      </Show>
    </div>
  );
}

export default ActivityTab;
