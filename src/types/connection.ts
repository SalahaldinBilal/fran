import type { AgentAccess } from "./agent";
import type { SecretOwner } from "./ssh";

export type DatabaseKind = "mysql" | "postgres" | "sqlite" | "d1";

// Without `store` the slot belongs to the connection being opened.
export type SecretSlot = {
  id: string,
  label: string,
  store?: { owner: SecretOwner, slot: string },
  // A one-time code, never offered for saving.
  oneTime?: boolean,
};

export type HostKeyInfo = {
  host: string,
  port: number,
  algorithm: string,
  fingerprint: string,
  // When it was trusted, Unix milliseconds.
  added?: number | null,
};

export type HopPosition = {
  index: number,
  total: number,
  label: string,
  target: string,
};

export type SshAuthMethod = "password" | "publicKey" | "agent";

export type SshOptions = {
  // A saved SSH host. When set, the fields below are ignored.
  hostId: string | null,
  host: string,
  port: number,
  user: string,
  auth: SshAuthMethod,
  keyFile: string,
  agentSocket: string,
};

export type KubeOptions = {
  context: string,
  namespace: string,
  resource: string,
  kubectlPath: string,
};

export type KubeContexts = {
  contexts: string[],
  current: string | null,
};

export type MysqlConnectMethod = "tcp" | "socket" | "sshTunnel" | "kubernetes";

export type SslMode = "disabled" | "preferred" | "required" | "verifyCa" | "verifyIdentity";

export type MysqlSslOptions = SslFiles & {
  mode: SslMode,
};

export type MysqlOptions = {
  method: MysqlConnectMethod,
  host: string,
  port: number,
  socketPath: string,
  user: string,
  defaultSchema: string,
  ssh: SshOptions,
  kube: KubeOptions,
  ssl: MysqlSslOptions,
  compression: boolean,
  cleartextAuth: boolean,
  connectTimeoutSecs: number,
  initSql: string,
};

export type PostgresConnectMethod = "tcp" | "socket" | "sshTunnel" | "kubernetes";

export type PostgresSslMode = "disable" | "prefer" | "require" | "verifyCa" | "verifyFull";

export type SslFiles = {
  caFile: string,
  certFile: string,
  keyFile: string,
};

export type PostgresSslOptions = SslFiles & {
  mode: PostgresSslMode,
};

export type PostgresOptions = {
  method: PostgresConnectMethod,
  host: string,
  port: number,
  socketPath: string,
  user: string,
  database: string,
  defaultSchema: string,
  ssh: SshOptions,
  kube: KubeOptions,
  ssl: PostgresSslOptions,
  connectTimeoutSecs: number,
  initSql: string,
};

export type SqliteOptions = {
  path: string,
  readOnly: boolean,
  createIfMissing: boolean,
  foreignKeys: boolean,
  busyTimeoutSecs: number,
  initSql: string,
};

export type D1Options = {
  accountId: string,
  // A database name or its UUID.
  database: string,
  timeoutSecs: number,
};

export type OptionsByKind = {
  mysql: MysqlOptions,
  postgres: PostgresOptions,
  sqlite: SqliteOptions,
  d1: D1Options,
};

export type DriverOptions = {
  [K in DatabaseKind]: { kind: K, options: OptionsByKind[K] }
}[DatabaseKind];

export type ConnectionProfile = {
  id: string,
  name: string,
  color: string | null,
  group: string | null,
  forwardPort: number | null,
  forwardAllNetworks: boolean,
  agentAccess: AgentAccess,
  // Reaches the database server, or the SSH server with inline SSH. Saved hosts bring their own.
  vpnId: string | null,
} & DriverOptions;

export type VaultStatus = {
  available: boolean,
  message: string | null,
  // The vault key is wrapped with the app lock password instead of kept in the OS keychain.
  lockEnabled: boolean,
  locked: boolean,
};
