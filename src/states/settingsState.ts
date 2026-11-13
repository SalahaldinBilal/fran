import { createRoot, createSignal } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { safeInvoke } from "@core/helpers/safeInvoke";
import useToastState from "./toastState";
import { TileNode, readTree } from "@core/helpers/tiling";
import { defaultHomeLayout, isHomePanel, isOldDefaultLayout } from "@core/helpers/homeLayout";
import type { SystemBackend } from "@core/types";

export type CellEditMode = "viewer" | "inline";

export type LetterCase = "upper" | "lower" | "preserve";
export type FormatIndent = "spaces2" | "spaces4" | "tabs";
export type OperatorPlacement = "before" | "after";

export type FormatSettings = {
  keywordCase: LetterCase,
  functionCase: LetterCase,
  dataTypeCase: LetterCase,
  indent: FormatIndent,
  logicalOperatorNewline: OperatorPlacement,
  expressionWidth: number,
  linesBetweenQueries: number,
};

export type Features = {
  database: boolean,
  ssh: boolean,
  vpn: boolean,
};

export type TerminalCursor = "block" | "bar" | "underline";

export type TerminalSettings = {
  // Empty means the app's monospace font.
  fontFamily: string,
  fontSize: number,
  cursorStyle: TerminalCursor,
  // Lines kept per pane, in memory only.
  scrollback: number,
  copyOnSelect: boolean,
  // What terminals print, encrypted on disk. Never what's typed.
  logOutput: boolean,
  logDays: number,
};

export const TERMINAL_FONTS: readonly string[] = ["", "Cascadia Code", "JetBrains Mono", "Fira Code", "Consolas", "Menlo", "SF Mono"];
export const TERMINAL_FONT_SIZES: readonly number[] = [11, 12, 13, 14, 15, 16, 18];
export const TERMINAL_CURSORS: readonly TerminalCursor[] = ["block", "bar", "underline"];
export const TERMINAL_SCROLLBACK: readonly number[] = [1000, 5000, 10000, 50000];
export const TERMINAL_LOG_DAYS: readonly number[] = [7, 30, 90, 365];

const DEFAULT_TERMINAL: TerminalSettings = {
  fontFamily: "",
  fontSize: 13,
  cursorStyle: "block",
  scrollback: 10000,
  copyOnSelect: false,
  logOutput: false,
  logDays: 30,
};

export type VpnSettings = {
  // Empty means the usual install folders and PATH.
  program: string,
  // How long an own tunnel stays open after the last connection using it closes.
  idleCloseSecs: number,
  connectTimeoutSecs: number,
  // How VPNs turn on for this computer. Fran's service is only used once it's set up.
  systemWith: SystemBackend,
};

export const VPN_IDLE_CLOSE: readonly number[] = [30, 120, 600];
export const VPN_CONNECT_TIMEOUTS: readonly number[] = [15, 30, 60];
const SYSTEM_BACKENDS: readonly SystemBackend[] = ["fran", "openvpn"];

const DEFAULT_VPN: VpnSettings = { program: "", idleCloseSecs: 30, connectTimeoutSecs: 30, systemWith: "fran" };

// 0 locks only when Fran starts.
export const LOCK_AFTER_MINUTES: readonly number[] = [5, 15, 60, 0];

export type AppSettings = {
  cellEditMode: CellEditMode,
  runTableQueryOnOpen: boolean,
  defaultRowLimit: number,
  colorFill: boolean,
  format: FormatSettings,
  terminal: TerminalSettings,
  vpn: VpnSettings,
  features: Features,
  onboardingVersion: number,
  homeLayout: TileNode | null,
  recentConnections: RecentConnection[],
  lockAfterMinutes: number,
  // SSH hosts on Home as one-line rows instead of cards.
  compactHosts: boolean,
  // VPNs on Home as one-line rows instead of cards.
  compactVpns: boolean,
  // Closing the window leaves Fran running in the tray, so VPNs, forwards and terminals keep going.
  keepInTray: boolean,
  // The one-time notice that Fran is still running after the window closed.
  trayNoticeShown: boolean,
  // The identity of the cloud new secrets start in. Empty is this computer.
  newSecretsStoredIn: string,
};

// Database connections and SSH hosts, newest first.
export type RecentConnection = { id: string, openedAt: number, kind: "database" | "ssh" };

export const RECENT_LIMIT = 8;

export const ONBOARDING_VERSION = 1;

const DEFAULT_FEATURES: Features = { database: true, ssh: false, vpn: false };

const CELL_EDIT_MODES: readonly CellEditMode[] = ["viewer", "inline"];
const LETTER_CASES: readonly LetterCase[] = ["upper", "lower", "preserve"];
const FORMAT_INDENTS: readonly FormatIndent[] = ["spaces2", "spaces4", "tabs"];
const OPERATOR_PLACEMENTS: readonly OperatorPlacement[] = ["before", "after"];
export const EXPRESSION_WIDTHS: readonly number[] = [40, 50, 60, 80, 100, 120];
export const LINES_BETWEEN_QUERIES: readonly number[] = [0, 1, 2];

const DEFAULT_FORMAT: FormatSettings = {
  keywordCase: "upper",
  functionCase: "preserve",
  dataTypeCase: "preserve",
  indent: "spaces2",
  logicalOperatorNewline: "after",
  expressionWidth: 50,
  linesBetweenQueries: 1,
};

export const ROW_LIMITS: readonly { value: number, label: string }[] = [
  { value: 100, label: "Limit 100" },
  { value: 500, label: "Limit 500" },
  { value: 1000, label: "Limit 1,000" },
  { value: 5000, label: "Limit 5,000" },
  { value: 10000, label: "Limit 10,000" },
  { value: 0, label: "No limit" },
];

export function isRowLimit(value: unknown): value is number {
  return ROW_LIMITS.some(limit => limit.value === value);
}

export const DEFAULT_SETTINGS: AppSettings = {
  cellEditMode: "viewer",
  runTableQueryOnOpen: true,
  defaultRowLimit: 1000,
  colorFill: true,
  format: DEFAULT_FORMAT,
  terminal: DEFAULT_TERMINAL,
  vpn: DEFAULT_VPN,
  features: DEFAULT_FEATURES,
  onboardingVersion: 0,
  homeLayout: defaultHomeLayout(),
  recentConnections: [],
  lockAfterMinutes: 15,
  compactHosts: false,
  compactVpns: false,
  keepInTray: true,
  trayNoticeShown: false,
  newSecretsStoredIn: "",
};

function oneOf<T>(value: unknown, allowed: readonly T[], fallback: T): T {
  return allowed.includes(value as T) ? value as T : fallback;
}

function formatFromStored(stored: unknown): FormatSettings {
  const values = (stored && typeof stored === "object" ? stored : {}) as Partial<Record<keyof FormatSettings, unknown>>;
  return {
    keywordCase: oneOf(values.keywordCase, LETTER_CASES, DEFAULT_FORMAT.keywordCase),
    functionCase: oneOf(values.functionCase, LETTER_CASES, DEFAULT_FORMAT.functionCase),
    dataTypeCase: oneOf(values.dataTypeCase, LETTER_CASES, DEFAULT_FORMAT.dataTypeCase),
    indent: oneOf(values.indent, FORMAT_INDENTS, DEFAULT_FORMAT.indent),
    logicalOperatorNewline: oneOf(values.logicalOperatorNewline, OPERATOR_PLACEMENTS, DEFAULT_FORMAT.logicalOperatorNewline),
    expressionWidth: oneOf(values.expressionWidth, EXPRESSION_WIDTHS, DEFAULT_FORMAT.expressionWidth),
    linesBetweenQueries: oneOf(values.linesBetweenQueries, LINES_BETWEEN_QUERIES, DEFAULT_FORMAT.linesBetweenQueries),
  };
}

function terminalFromStored(stored: unknown): TerminalSettings {
  const values = (stored && typeof stored === "object" ? stored : {}) as Partial<Record<keyof TerminalSettings, unknown>>;
  return {
    fontFamily: oneOf(values.fontFamily, TERMINAL_FONTS, DEFAULT_TERMINAL.fontFamily),
    fontSize: oneOf(values.fontSize, TERMINAL_FONT_SIZES, DEFAULT_TERMINAL.fontSize),
    cursorStyle: oneOf(values.cursorStyle, TERMINAL_CURSORS, DEFAULT_TERMINAL.cursorStyle),
    scrollback: oneOf(values.scrollback, TERMINAL_SCROLLBACK, DEFAULT_TERMINAL.scrollback),
    copyOnSelect: typeof values.copyOnSelect === "boolean" ? values.copyOnSelect : DEFAULT_TERMINAL.copyOnSelect,
    logOutput: typeof values.logOutput === "boolean" ? values.logOutput : DEFAULT_TERMINAL.logOutput,
    logDays: oneOf(values.logDays, TERMINAL_LOG_DAYS, DEFAULT_TERMINAL.logDays),
  };
}

function vpnFromStored(stored: unknown): VpnSettings {
  const values = (stored && typeof stored === "object" ? stored : {}) as Partial<Record<keyof VpnSettings, unknown>>;
  return {
    program: typeof values.program === "string" ? values.program : DEFAULT_VPN.program,
    idleCloseSecs: oneOf(values.idleCloseSecs, VPN_IDLE_CLOSE, DEFAULT_VPN.idleCloseSecs),
    connectTimeoutSecs: oneOf(values.connectTimeoutSecs, VPN_CONNECT_TIMEOUTS, DEFAULT_VPN.connectTimeoutSecs),
    systemWith: oneOf(values.systemWith, SYSTEM_BACKENDS, DEFAULT_VPN.systemWith),
  };
}

function featuresFromStored(stored: unknown): Features {
  const values = (stored && typeof stored === "object" ? stored : {}) as Partial<Record<keyof Features, unknown>>;
  const features = {
    database: typeof values.database === "boolean" ? values.database : DEFAULT_FEATURES.database,
    ssh: typeof values.ssh === "boolean" ? values.ssh : DEFAULT_FEATURES.ssh,
    vpn: typeof values.vpn === "boolean" ? values.vpn : DEFAULT_FEATURES.vpn,
  };
  return features.database || features.ssh || features.vpn ? features : { ...DEFAULT_FEATURES };
}

function recentFromStored(stored: unknown): RecentConnection[] {
  if (!Array.isArray(stored)) return [];
  return stored
    .filter((item): item is RecentConnection => typeof item?.id === "string" && typeof item?.openedAt === "number")
    .slice(0, RECENT_LIMIT)
    .map(item => ({ id: item.id, openedAt: item.openedAt, kind: item.kind === "ssh" ? "ssh" : "database" }));
}

function homeLayoutFromStored(stored: unknown): TileNode | null {
  if (stored === null) return null;
  const tree = readTree(stored, isHomePanel);
  return tree && !isOldDefaultLayout(tree) ? tree : defaultHomeLayout();
}

// Keys missing from an older file, or holding values this version doesn't know, take the default.
function fromStored(stored: unknown): AppSettings {
  const values = (stored && typeof stored === "object" ? stored : {}) as Partial<Record<keyof AppSettings, unknown>>;
  return {
    cellEditMode: CELL_EDIT_MODES.includes(values.cellEditMode as CellEditMode)
      ? values.cellEditMode as CellEditMode
      : DEFAULT_SETTINGS.cellEditMode,
    runTableQueryOnOpen: typeof values.runTableQueryOnOpen === "boolean"
      ? values.runTableQueryOnOpen
      : DEFAULT_SETTINGS.runTableQueryOnOpen,
    defaultRowLimit: isRowLimit(values.defaultRowLimit) ? values.defaultRowLimit : DEFAULT_SETTINGS.defaultRowLimit,
    colorFill: typeof values.colorFill === "boolean" ? values.colorFill : DEFAULT_SETTINGS.colorFill,
    format: formatFromStored(values.format),
    terminal: terminalFromStored(values.terminal),
    vpn: vpnFromStored(values.vpn),
    features: featuresFromStored(values.features),
    onboardingVersion: Number.isInteger(values.onboardingVersion) && (values.onboardingVersion as number) >= 0
      ? values.onboardingVersion as number
      : 0,
    homeLayout: homeLayoutFromStored(values.homeLayout),
    recentConnections: recentFromStored(values.recentConnections),
    lockAfterMinutes: oneOf(values.lockAfterMinutes, LOCK_AFTER_MINUTES, DEFAULT_SETTINGS.lockAfterMinutes),
    compactHosts: typeof values.compactHosts === "boolean" ? values.compactHosts : DEFAULT_SETTINGS.compactHosts,
    compactVpns: typeof values.compactVpns === "boolean" ? values.compactVpns : DEFAULT_SETTINGS.compactVpns,
    keepInTray: typeof values.keepInTray === "boolean" ? values.keepInTray : DEFAULT_SETTINGS.keepInTray,
    trayNoticeShown: typeof values.trayNoticeShown === "boolean" ? values.trayNoticeShown : DEFAULT_SETTINGS.trayNoticeShown,
    newSecretsStoredIn: typeof values.newSecretsStoredIn === "string" ? values.newSecretsStoredIn : DEFAULT_SETTINGS.newSecretsStoredIn,
  };
}

function useSettingsStateInner() {
  const { pushError } = useToastState;
  const [settings, setSettings] = createStore<AppSettings>({ ...DEFAULT_SETTINGS });
  const [loadError, setLoadError] = createSignal<unknown>(null);
  const [loaded, setLoaded] = createSignal(false);

  async function load() {
    try {
      setSettings(reconcile(fromStored(await safeInvoke("get_settings"))));
      setLoadError(null);
      void applyVpnOptions().catch(() => undefined);
      void applyTrayOptions().catch(() => undefined);
    } catch (error) {
      setLoadError(error);
    } finally {
      setLoaded(true);
    }
  }

  async function update(patch: Partial<AppSettings>) {
    const previous: AppSettings = {
      ...settings,
      format: { ...settings.format },
      terminal: { ...settings.terminal },
      vpn: { ...settings.vpn },
      features: { ...settings.features },
    };
    const next = { ...previous, ...patch };
    setSettings(reconcile(next));
    try {
      await safeInvoke("set_settings", { settings: next });
    } catch (error) {
      setSettings(reconcile(previous));
      pushError(error);
      return;
    }
    if (patch.vpn) void applyVpnOptions().catch(pushError);
    if (patch.keepInTray !== undefined || patch.trayNoticeShown !== undefined) void applyTrayOptions().catch(pushError);
  }

  async function applyTrayOptions() {
    await safeInvoke("set_tray_options", { keepInTray: settings.keepInTray, noticeShown: settings.trayNoticeShown });
  }

  // Rust keeps no settings of its own, so the VPN timeouts are handed over after load and on change.
  async function applyVpnOptions() {
    await safeInvoke("set_vpn_options", { idleCloseSecs: settings.vpn.idleCloseSecs, connectTimeoutSecs: settings.vpn.connectTimeoutSecs });
  }

  function updateVpn(patch: Partial<VpnSettings>) {
    return update({ vpn: { ...settings.vpn, ...patch } });
  }

  function updateFormat(patch: Partial<FormatSettings>) {
    return update({ format: { ...settings.format, ...patch } });
  }

  function updateTerminal(patch: Partial<TerminalSettings>) {
    return update({ terminal: { ...settings.terminal, ...patch } });
  }

  return { settings, loaded, loadError, load, update, updateFormat, updateTerminal, updateVpn };
}

const useSettingsState = createRoot(useSettingsStateInner);
export default useSettingsState;
