import { createMemo, createRoot, createSignal, createStore, reconcile } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { immediateWrite } from "@core/helpers/immediateWrite";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { withConnectPrompts } from "@core/helpers/connectFlow";
import { errorMessage } from "@core/helpers/errors";
import {
  AgentApproval, AgentConfig, AgentDatabases, AgentHistoryEntry, AgentServerStatus, AgentSessionInfo, ConnectionProfile,
} from "@core/types";
import useToastState from "./toastState";

export type AgentsView = "activity" | "access" | "server";

export type DatabaseList = {
  list: AgentDatabases | null,
  listedAt: number | null,
  loading: boolean,
  error: string | null,
};

const DEFAULT_CONFIG: AgentConfig = {
  enabled: false,
  port: 3726,
  allowRawSql: true,
  allowChanges: true,
  historyEnabled: true,
  historyDays: 30,
  queryTimeoutSecs: 60,
  notifyApprovals: true,
};

function useAgentStateInner() {
  const { pushError } = useToastState;
  const [config, writeConfig] = createStore<AgentConfig>({ ...DEFAULT_CONFIG });
  const setConfig = immediateWrite(writeConfig);
  const [status, setStatus] = createSignal<AgentServerStatus>({ running: false, port: null, error: null });
  const [sessions, writeSessions] = createStore<AgentSessionInfo[]>([]);
  const setSessions = immediateWrite(writeSessions);
  const [approvals, writeApprovals] = createStore<AgentApproval[]>([]);
  const setApprovals = immediateWrite(writeApprovals);
  const [view, setView] = createSignal<AgentsView>("activity");
  const [reviewingId, setReviewingId] = createSignal<string | null>(null);
  const reviewing = createMemo(() => approvals.find(approval => approval.id === reviewingId()));
  const [databaseLists, writeDatabaseLists] = createStore<Record<string, DatabaseList>>({});
  const setDatabaseLists = immediateWrite(writeDatabaseLists);
  const seenApprovals = new Set<string>();
  const historyListeners = new Set<(entry: AgentHistoryEntry) => void>();

  async function refreshSessions() {
    setSessions(reconcile(await safeInvoke("list_agent_sessions"), "id"));
  }

  // A change that just came in opens its review, unless another one is already open.
  async function refreshApprovals() {
    const list = await safeInvoke("list_agent_approvals");
    setApprovals(reconcile(list, "id"));
    const fresh = list.find(approval => !seenApprovals.has(approval.id));
    for (const approval of list) seenApprovals.add(approval.id);
    if (!list.some(approval => approval.id === reviewingId())) setReviewingId(fresh?.id ?? null);
  }

  async function load() {
    try {
      setConfig(reconcile(await safeInvoke("get_agent_config")));
      setStatus(await safeInvoke("get_agent_status"));
      await Promise.all([refreshSessions(), refreshApprovals()]);
    } catch (error) {
      pushError(error);
    }
  }

  async function update(patch: Partial<AgentConfig>) {
    const previous = { ...config };
    const next = { ...previous, ...patch };
    setConfig(reconcile(next));
    try {
      setStatus(await safeInvoke("set_agent_config", { config: next }));
    } catch (error) {
      setConfig(reconcile(previous));
      pushError(error);
    }
  }

  async function closeSession(id: string) {
    try {
      await safeInvoke("close_agent_session", { id });
    } catch (error) {
      pushError(error);
    }
  }

  async function answer(id: string, approved: boolean) {
    await safeInvoke("answer_agent_request", { id, approved });
    setReviewingId(approvals.find(approval => approval.id !== id)?.id ?? null);
  }

  function review(id: string) {
    setReviewingId(id);
  }

  function closeReview() {
    setReviewingId(null);
  }

  // Kept until Refresh, so expanding a connection again doesn't reconnect.
  async function listDatabases(profile: ConnectionProfile, refresh = false) {
    const known = databaseLists[profile.id];
    if (known?.loading || (known?.list && !refresh)) return;
    function patchList(patch: Partial<DatabaseList>) {
      setDatabaseLists(lists => {
        Object.assign(lists[profile.id], patch);
      });
    }

    const list = known?.list ?? null;
    const listedAt = known?.listedAt ?? null;
    setDatabaseLists(lists => {
      lists[profile.id] = { list, listedAt, loading: true, error: null };
    });
    try {
      const fetched = await withConnectPrompts(
        { connectionId: profile.id, connectionName: profile.name },
        secrets => safeInvoke("list_agent_databases", { connectionId: profile.id, secrets }),
      );
      if (fetched) {
        patchList({ list: fetched, listedAt: Date.now(), loading: false, error: null });
      } else {
        patchList({ loading: false, error: "Fran needs to connect to list the databases." });
      }
    } catch (error) {
      patchList({ loading: false, error: errorMessage(error) });
    }
  }

  function onHistoryAdded(listener: (entry: AgentHistoryEntry) => void): () => void {
    historyListeners.add(listener);
    return () => historyListeners.delete(listener);
  }

  function address(): string {
    return `127.0.0.1:${status().port ?? config.port}/mcp`;
  }

  function url(): string {
    return `http://${address()}`;
  }

  listen<AgentServerStatus>("agent-status-changed", event => setStatus(event.payload));
  listen("agent-sessions-changed", () => refreshSessions().catch(pushError));
  listen("agent-approvals-changed", () => refreshApprovals().catch(pushError));
  listen<AgentHistoryEntry>("agent-history-added", event => {
    for (const listener of historyListeners) listener(event.payload);
  });

  return {
    config,
    status,
    sessions,
    approvals,
    view,
    setView,
    reviewing,
    databaseLists,
    listDatabases,
    load,
    update,
    closeSession,
    answer,
    review,
    closeReview,
    onHistoryAdded,
    address,
    url,
  };
}

const useAgentState = createRoot(useAgentStateInner);
export default useAgentState;
