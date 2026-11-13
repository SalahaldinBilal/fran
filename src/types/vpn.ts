import type { SecretOwner, SecretRefs } from "./ssh";
import type { SecretSlot } from "./connection";

export type VpnProto = "udp" | "tcp";

export type VpnRemote = { host: string, port: number, proto: VpnProto };

export type VpnAuth = "cert" | "userPass" | "certAndUserPass";

export type VpnChallenge = { kind: "none" } | { kind: "static", echo: boolean, text: string };

export type TlsWrap =
  | { kind: "none" }
  | { kind: "auth", direction: number | null }
  | { kind: "crypt" }
  | { kind: "cryptV2" };

export type RouteAll = "followServer" | "vpnNetworksOnly";

export type Compress = "off" | "lzoNo" | "stub" | "stubV2";

export type VerifyNameKind = "subject" | "name" | "namePrefix";

export type ImportNote = { option: string, reason: string };

export type ImportInfo = {
  fileName: string,
  used: string[],
  ignored: ImportNote[],
  dropped: ImportNote[],
  systemOnly: ImportNote[],
  importedAt: number,
};

export type VpnKind = "openVpn" | "wireGuard";

// Addresses keep their prefix, like "10.64.0.2/32". The private and preshared keys are in the vault.
export type WireGuardSettings = {
  // Worked out from the saved private key. Null while none is saved.
  publicKey: string | null,
  peerPublicKey: string,
  allowedIps: string[],
  addresses: string[],
  dns: string[],
  searchDomains: string[],
  mtu: number | null,
  keepaliveSecs: number | null,
};

export type VpnProfile = {
  id: string,
  label: string,
  group: string | null,
  color: string | null,
  kind: VpnKind,
  // For WireGuard, the one endpoint.
  remotes: VpnRemote[],
  remoteRandom: boolean,
  auth: VpnAuth,
  user: string,
  challenge: VpnChallenge,
  // Public PEM. The client key is in the vault.
  ca: string,
  cert: string,
  // What the saved client key is, like "EC P-256". Null means none is saved.
  keyKind: string | null,
  verifyName: { name: string, kind: VerifyNameKind } | null,
  peerFingerprints: string[],
  requireServerCert: boolean,
  tlsWrap: TlsWrap,
  ciphers: string[],
  fallbackCipher: string | null,
  authDigest: string | null,
  tlsVersionMin: string | null,
  renegSec: number | null,
  compress: Compress,
  routeAll: RouteAll,
  useVpnDns: boolean,
  // Why only the installed OpenVPN can run it. Empty means an own tunnel and Fran's service can.
  needsSystem: string[],
  // Options from the import only the installed OpenVPN gets. Set by import, never by the editor.
  systemOptions: string[][],
  // The smartcard library, only ever picked in the editor since it runs inside OpenVPN as admin.
  pkcs11Provider: string | null,
  imported: ImportInfo | null,
  wireGuard: WireGuardSettings,
  secretRefs?: SecretRefs,
};

export type VpnFile = {
  version: number,
  profiles: VpnProfile[],
  groupOrder: string[],
};

export type VpnPhase = "connecting" | "up" | "reconnecting" | "down";

// What runs a VPN that's on for the whole computer: Fran's own service or the installed OpenVPN.
export type SystemBackend = "fran" | "openvpn";

export type VpnStatus = {
  profileId: string,
  phase: VpnPhase,
  // On for the whole computer. False means Fran's own tunnel.
  system: boolean,
  with: SystemBackend | null,
  users: number,
  address: string | null,
  bytesIn: number,
  bytesOut: number,
  lastError: string | null,
  // Something to type in while it's on for the computer, like a new one-time code.
  prompt: VpnPrompt | null,
};

export type VpnPrompt = { title: string, slots: SecretSlot[] };

export type SecretGroup = "connection" | "identity" | "key" | "proxy" | "vpn" | "secret" | "internal" | "unknown";

// One entry in the vault, without its value.
export type SavedSecret = {
  id: string,
  owner: SecretOwner | null,
  slot: string,
  group: SecretGroup,
  // Null when what it belonged to was deleted.
  ownerLabel: string | null,
  label: string,
  revealable: boolean,
};

export type RevealOptions = {
  lockPassword: string | null,
  passwordDialog: boolean,
};

export type CertSummary = { subject: string, notAfter: string };

export type OpenVpnProgram = { path: string, version: string };

// From this sign-in's groups. Someone added since signing in is still let in by the service.
export type OpenVpnServiceCheck = { exePath: string | null, adminGroup: string, allowed: boolean };

export type OpenVpnCheck = { program: OpenVpnProgram | null, problem: string | null, service: OpenVpnServiceCheck | null };

// Who may turn VPNs on with Fran's service: any account signed in at this computer, or administrators and its group.
export type VpnServiceAccess = "everyone" | "group";

export type VpnServiceStatus =
  | { state: "notSetUp", nixos: boolean }
  | { state: "notRunning", reason: string }
  | { state: "needsUpdate", reason: string }
  // `outdated`: not the fran-vpn version this app ships. It still works, Update installs the one that comes with the app.
  | { state: "running", build: string, access: VpnServiceAccess, allowed: boolean, refused: string | null, outdated: boolean };

export type OpenVpnInstallHelp = { kind: "run", with: string } | { kind: "command", command: string } | { kind: "none" };

export type TrayItem = { id: string, label: string, checked?: boolean, enabled?: boolean, separatorBefore?: boolean };

export type VpnCertificates = { ca: CertSummary[], cert: CertSummary[] };
