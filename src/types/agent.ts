import { DatabaseKind } from "./connection";

export type AgentMode = "off" | "readOnly" | "ask" | "write";

export type DatabaseRule = { name: string, mode: AgentMode };

// On Postgres and D1 the names are the databases a session opens.
export type AgentAccess = {
  mode: AgentMode,
  // Whether databases without a rule get `mode`. False hides them.
  allDatabases: boolean,
  exceptions: DatabaseRule[],
};

// `bound`: a session is tied to one of these, so raw SQL can't reach the others.
export type AgentDatabases = {
  bound: boolean,
  databases: { name: string, system: boolean }[],
};

export type AgentConfig = {
  enabled: boolean,
  port: number,
  allowRawSql: boolean,
  allowChanges: boolean,
  historyEnabled: boolean,
  historyDays: number,
  queryTimeoutSecs: number,
  notifyApprovals: boolean,
};

export type AgentServerStatus = {
  running: boolean,
  port: number | null,
  error: string | null,
};

export type AgentSessionInfo = {
  id: string,
  connectionId: string,
  connectionName: string,
  kind: DatabaseKind,
  catalog: string | null,
  defaultDatabase: string | null,
  agent: string,
  openedAt: number,
  lastUsed: number,
};

export type AgentApplySafety = { kind: "transaction" } | { kind: "schema", atomic: boolean };

export type PreviewCell = { column: string, before: string | null, after: string | null };

export type PreviewRow = {
  action: "insert" | "update" | "delete",
  key: { column: string, value: string | null }[],
  cells: PreviewCell[],
  // Whether a row has this key right now. Null when it wasn't looked up.
  found: boolean | null,
};

export type RowPreview = { table: string, rows: PreviewRow[], more: number };

export type AgentApproval = {
  id: string,
  sessionId: string,
  agent: string,
  connectionId: string,
  connectionName: string,
  kind: DatabaseKind,
  database: string | null,
  tool: string,
  arguments: unknown,
  statements: string[],
  safety: AgentApplySafety,
  preview: RowPreview | null,
  requestedAt: number,
};

export type HistoryOutcome = "ok" | "error" | "refused" | "cancelled" | "timedOut";

export type ApprovalAnswer = "approved" | "rejected" | "timedOut" | "cancelled";

export type AgentHistoryEntry = {
  id: string,
  at: number,
  event: "call" | "sessionClosed",
  agent: string | null,
  sessionId: string | null,
  connectionId: string | null,
  connectionName: string | null,
  // Null on entries written before the kind was kept.
  kind: DatabaseKind | null,
  database: string | null,
  tool: string | null,
  arguments: unknown,
  statements: string[],
  approval: { answer: ApprovalAnswer, requestedAt: number, answeredAt: number } | null,
  outcome: HistoryOutcome,
  message: string | null,
  durationMs: number,
  reply?: unknown,
};
