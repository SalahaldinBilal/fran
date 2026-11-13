import type { HostKeyInfo } from "./connection";

export type SecretOwner =
  | { kind: "connection", id: string }
  | { kind: "identity", id: string }
  | { kind: "key", id: string }
  | { kind: "proxy", id: string }
  | { kind: "vpn", id: string }
  | { kind: "secret", id: string };

// A field path, or `slot:<name>` for a password slot, to the id of the named secret that fills it.
export type SecretRefs = Record<string, string>;

// A named value any field can use. The value itself stays in the vault.
export type NamedSecret = {
  id: string,
  name: string,
  note: string,
  // Set when the value lives in a cloud under its own name there. `cloud` is the cloud's identity, not its id.
  link?: SecretLink | null,
};

export type SecretLink = { cloud: string, name: string };

export type SecretUserKind = "connection" | "sshHost" | "identity" | "proxy" | "key" | "vpn";

export type SecretUse = {
  kind: SecretUserKind,
  id: string,
  label: string,
  // The field path, or the slot name when `slot` is set.
  field: string,
  slot: boolean,
};

export type SecretInfo = NamedSecret & {
  hasValue: boolean,
  usedBy: SecretUse[],
};

export type SshHost = {
  id: string,
  label: string,
  group: string | null,
  color: string | null,
  host: string,
  port: number,
  identityId: string | null,
  // Saved hosts this one is reached through, outermost first.
  jumps: string[],
  proxyId: string | null,
  // Carries the first hop. A host without one takes its first jump's.
  vpnId: string | null,
  // 0 turns keepalives off.
  keepaliveSecs: number,
  agentForwarding: boolean,
  // OSC 52 writes only. Servers can never read the clipboard.
  clipboardWrite: boolean,
  // Typed at the prompt after login, without pressing Enter.
  startupSnippetId: string | null,
  secretRefs?: SecretRefs,
};

export type ForwardKind = "local" | "remote" | "dynamic";

export type ForwardRule = {
  id: string,
  label: string,
  kind: ForwardKind,
  hostId: string,
  // Local and dynamic: the port on this computer. Remote: the port the server listens on.
  listenPort: number,
  allNetworks: boolean,
  // Remote only: the address the server listens on.
  remoteBind: string,
  // Local: as the server sees it. Remote: as this computer sees it. Unused for dynamic.
  targetHost: string,
  targetPort: number,
};

export type RuleForwardInfo = {
  ruleId: string,
  listen: string,
  started: number,
};

export type RuleStopped = {
  ruleId: string,
  reason: string | null,
};

export type Snippet = {
  id: string,
  label: string,
  command: string,
  confirm: boolean,
};

export type TerminalInfo = {
  id: string,
  connectionId: string,
  hostId: string,
  hostKey: HostKeyInfo | null,
  agentForwarding: boolean,
};

export type TerminalEvent = { kind: "closed", reason: string | null, connectionLost: boolean };

export type TerminalLogSession = {
  terminalId: string,
  hostId: string,
  hostLabel: string,
  startedAt: number,
  endedAt: number,
  bytes: number,
};

export type SftpInfo = {
  id: string,
  hostId: string,
  home: string,
  hostKey: HostKeyInfo | null,
  // Runs on a terminal's connection instead of its own login.
  shared: boolean,
};

export type SftpEvent = { kind: "closed", reason: string | null };

export type EntryKind ="file" | "dir" | "symlink" | "other";

export type FileEntry = {
  name: string,
  path: string,
  kind: EntryKind,
  size: number | null,
  // Unix milliseconds.
  modified: number | null,
  mode: number | null,
  hidden: boolean,
  // A link whose target is a folder, so it opens like one.
  linkDir: boolean,
};

export type Crumb = { label: string, path: string };

export type Listing = {
  path: string,
  crumbs: Crumb[],
  parent: string | null,
  entries: FileEntry[],
};

export type TreeCount = { files: number, folders: number, bytes: number };

export type TransferDirection = "upload" | "download";

export type ConflictChoice = "overwrite" | "skip" | "keepBoth";

export type TransferEvent =
  | { kind: "waiting" }
  | { kind: "scanning", files: number, bytes: number }
  | { kind: "started", totalBytes: number, totalFiles: number }
  | { kind: "progress", bytes: number, files: number, current: string }
  | { kind: "conflict", path: string, isDir: boolean }
  | { kind: "skipped", path: string, reason: string }
  | { kind: "finished", bytes: number, files: number, skipped: number }
  | { kind: "failed", message: string }
  | { kind: "cancelled" };

export type IdentityAuth =
  | { kind: "password" }
  | { kind: "key", keyId: string }
  | { kind: "agent", socket: string };

export type Identity = {
  id: string,
  label: string,
  user: string,
  auth: IdentityAuth,
  secretRefs?: SecretRefs,
};

export type KeyStorage = { kind: "vault" } | { kind: "file", path: string };

export type KeyMeta = {
  id: string,
  label: string,
  algorithm: string,
  publicKey: string,
  fingerprint: string,
  storage: KeyStorage,
  created: number,
  // Only `slot:passphrase`, for a key kept as a file.
  secretRefs?: SecretRefs,
};

export type KeyAlgorithm = "ed25519" | "ecdsaP256" | "rsa4096";

export type ProxyKind = "socks5" | "httpConnect";

export type Proxy = {
  id: string,
  label: string,
  kind: ProxyKind,
  host: string,
  port: number,
  // Empty means the proxy takes no login.
  user: string,
  secretRefs?: SecretRefs,
};

export type SshFile = {
  version: number,
  hosts: SshHost[],
  identities: Identity[],
  keys: KeyMeta[],
  proxies: Proxy[],
  forwards: ForwardRule[],
  // Host groups in Home's order. Groups missing here come after, by name.
  groupOrder: string[],
};

export type ImportCandidate = {
  alias: string,
  host: string,
  port: number,
  user: string,
  identityFile: string | null,
  jumps: string[],
  skipReason: string | null,
};

export type ImportPreview = {
  path: string,
  found: boolean,
  candidates: ImportCandidate[],
  skippedPatterns: string[],
};

export type ImportOutcome = {
  imported: string[],
  skipped: string[],
};
