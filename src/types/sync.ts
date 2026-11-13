export type CloudKind = "franServer" | "doppler";

export type SyncCategory =
  | "connections"
  | "sshHosts"
  | "identities"
  | "proxies"
  | "vpnProfiles"
  | "savedQueries"
  | "snippets"
  | "forwards"
  | "knownHosts"
  | "settings"
  | "secrets"
  | "passwords"
  | "privateKeys";

// "local" is "Don't sync" on a category and "Keep on this computer" on an item or group.
export type SyncTarget =
  | { kind: "local" }
  | { kind: "cloud", cloud: string }
  | { kind: "withItem" };

export type SyncRoutes = {
  categories: Partial<Record<SyncCategory, SyncTarget>>,
  // Keyed by `<item kind>:<group name>`.
  groups: Record<string, SyncTarget>,
  // Keyed by `<item kind>:<id>`.
  items: Record<string, SyncTarget>,
};

export type SyncPhase = "waiting" | "syncing" | "upToDate" | "error";

// "missing" and "computed" are about a secret linked to a name in the cloud: the name is gone there, or the value is built from other ones.
export type SyncProblemReason = "tooLarge" | "quotaExceeded" | "readOnly" | "missing" | "computed" | "refused";

export type SyncProblem = { key: string, label: string, reason: SyncProblemReason };

export type SyncStep =
  | { kind: "checking" }
  | { kind: "receiving", count: number }
  | { kind: "sending", count: number };

export type PassSummary = { received: number, sent: number };

export type CloudStatus = {
  phase: SyncPhase,
  step: SyncStep | null,
  lastPass: PassSummary | null,
  message: string | null,
  signedOut: boolean,
  problems: SyncProblem[],
};

export type Cloud = {
  id: string,
  kind: CloudKind,
  name: string,
  identity: string,
  // Owned by the cloud's module. Never holds a secret.
  config: unknown,
  lastSync: number | null,
  items: number,
  status: CloudStatus,
};

export type ReplacedReason = "replaced" | "deleted" | "overwritten";

export type ReplacedItem = { id: string, key: string, label: string, cloud: string, at: number, reason: ReplacedReason };

export type MissingRef = { item: string, label: string, target: string, cloud: string | null };

export type SyncView = {
  clouds: Cloud[],
  routes: SyncRoutes,
  // Item key to the id of the cloud it syncs to.
  homes: Record<string, string>,
  replaced: ReplacedItem[],
  // Items another computer moved to a cloud this one isn't signed into.
  moved: Record<string, string>,
  missing: MissingRef[],
  // Categories another computer sends to a cloud this one isn't signed into, with that cloud's identity.
  waitingRoutes: Partial<Record<SyncCategory, string>>,
  duplicates: SyncDuplicate[],
};

// Something only on this computer that looks the same as an item in a cloud. The local one isn't sent until it's settled.
export type SyncDuplicate = { id: string, cloud: string, local: string, remote: string, label: string };

export type MoveCandidate = { key: string, label: string, home: string | null };

export type DopplerConfig = { project: string, config: string };

export type DopplerProject = { slug: string, name: string };

// `project` and `config` are set when the token is tied to one config. Otherwise they're picked from `projects`, or typed when that's empty.
export type DopplerTokenInfo = { project: string | null, config: string | null, projects: DopplerProject[] };

export type FranServerConfig = { url: string, email: string, accountId: string, instanceId: string };

export type SignupMode = "open" | "invite" | "closed";

export type FranServerInfo = {
  version: string,
  protocolVersion: number,
  signup: SignupMode,
  instanceId: string,
  limits: { recordBytes: number, accountBytes: number, batchRecords: number },
  // Only sent, as false, while nobody has claimed the server.
  owned?: boolean,
};

export type FranServerLogin = { url: string, email: string, password: string, name: string, deviceName: string };

export type ServerRole = "user" | "admin" | "owner";

export type FranServerAccount = {
  id: string,
  email: string,
  totpEnabled: boolean,
  usedBytes: number,
  createdAt: number,
  role: ServerRole,
  quotaBytes: number,
};

export type AdminOverview = { version: string, startedAt: number, accounts: number, usedBytes: number, serverBytes: number, signup: SignupMode };

export type AdminUser = {
  id: string,
  email: string,
  role: ServerRole,
  usedBytes: number,
  // 0 when the account follows the server's default.
  ownQuotaBytes: number,
  quotaBytes: number,
  createdAt: number,
  totpEnabled: boolean,
  devices: number,
  lastSeenAt: number,
};

export type AdminUsersPage = { users: AdminUser[], total: number };

export type AdminUserDetail = { user: AdminUser, sessions: FranServerDevice[] };

export type AdminInvite = { id: string, email: string, createdAt: number, expiresAt: number, usedAt: number, usedBy: string };

export type CreatedInvite = { code: string, invite: AdminInvite };

export type ServerSettings = {
  signup: SignupMode,
  accountBytes: number,
  recordBytes: number,
  batchRecords: number,
  // 0 for no total limit.
  serverBytes: number,
};

export type UpdateServerSettings = Partial<{ signup: SignupMode, accountBytes: number, recordBytes: number, batchRecords: number, serverBytes: number }>;

export type AdminLogEntry = { id: string, at: number, actor: string, action: string, target: string, detail: string };

export type FranServerDevice = {
  id: string,
  device: { name: string, os: string },
  createdAt: number,
  lastSeenAt: number,
  expiresAt: number,
  current: boolean,
};

export type FranServerTotp = { enabled: boolean, secret?: string, uri?: string };

export type FranServerTotpAction =
  | { action: "begin" }
  | { action: "confirm", code: string }
  | { action: "disable", password: string };
