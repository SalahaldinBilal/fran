import { HopPosition, HostKeyInfo, SecretSlot } from "./connection";

export type ErrorDetail =
  | { kind: "general" }
  | { kind: "notFound" }
  | { kind: "vault" }
  | { kind: "appLocked" }
  | { kind: "osAuthCancelled" }
  | { kind: "lockPasswordRequired" }
  // Linux: polkit doesn't know Fran yet. canInstall says whether pkexec can register it.
  | { kind: "osAuthSetup", canInstall: boolean }
  | { kind: "ssh" }
  | { kind: "database", code: number | null, sqlState: string | null }
  | { kind: "secretsRequired", slots: SecretSlot[] }
  | { kind: "unknownHostKey", key: HostKeyInfo, hop: HopPosition | null, opensshTrusted: boolean }
  | {
    kind: "hostKeyChanged",
    key: HostKeyInfo,
    knownFingerprint: string,
    knownAlgorithm: string,
    knownAdded: number | null,
    hop: HopPosition | null,
  };

export type AppError = {
  message: string,
  detail: ErrorDetail,
};
