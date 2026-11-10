import styles from "@core/pages/Settings/Settings.module.scss";
import { Show, createEffect, createMemo, createSignal, on, onMount } from "solid-js";
import { Copy } from "lucide-solid";
import useSettingsState from "@core/states/settingsState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import useVpnState from "@core/states/vpnState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage } from "@core/helpers/errors";
import { copyText } from "@core/helpers/clipboard";
import { plural } from "@core/helpers";
import { IS_MAC, IS_WINDOWS } from "@core/helpers/platform";
import { OpenVpnCheck, OpenVpnInstallHelp, SystemBackend, VpnServiceAccess, VpnServiceStatus } from "@core/types";
import Select, { SelectItem } from "@core/components/Select/Select";
import Button from "@core/components/Button/Button";
import { SettingGroup, SettingRow } from "@core/pages/Settings/SettingsLayout";

const GROUP_HINT = IS_MAC
  ? "Adds you to a list only administrators can change. Others need an administrator to set it up for them."
  : `Adds you to a "${IS_WINDOWS ? "Fran VPN Users" : "fran-vpn"}" group. Others need an administrator to add them.`;

const ACCESS_ITEMS: SelectItem<VpnServiceAccess>[] = [
  { value: "everyone", label: "Everyone on this computer" },
  { value: "group", label: "Only me and administrators" },
];

// Shown under the setting instead of in the menu, which they'd make far too wide.
const ACCESS_HINTS: Record<VpnServiceAccess, string> = {
  everyone: "Any account signed in here. Not service accounts or network sign-ins.",
  group: GROUP_HINT,
};

const BACKEND_ITEMS: SelectItem<SystemBackend>[] = [
  { value: "fran", label: "Fran's VPN service" },
  { value: "openvpn", label: "Installed OpenVPN" },
];

function serviceText(status: VpnServiceStatus | null, failed: string | null): { text: string, error: boolean } {
  if (failed) return { text: failed, error: true };
  if (!status) return { text: "Checking Fran's VPN service", error: false };
  switch (status.state) {
    case "notSetUp":
      return status.nixos
        ? { text: "Not set up. On NixOS, turn it on with programs.fran.vpnService in your configuration.", error: false }
        : { text: "Not set up. Setting it up asks for admin rights once. After that, turning a VPN on asks for nothing.", error: false };
    case "notRunning":
      return { text: `Set up, but not running. ${status.reason}`, error: true };
    case "needsUpdate":
      return { text: "Installed by a different version of Fran. Click Update to fix it.", error: true };
    case "running": {
      if (!status.allowed) return { text: status.refused ?? "Running, but it doesn't take your account.", error: true };
      const who = status.access === "everyone" ? "everyone on this computer" : "you and administrators";
      const outdated = status.outdated ? ` This Fran comes with a different version. Click Update to install it.` : "";
      return { text: `Running, for ${who}.${outdated}`, error: status.outdated };
    }
  }
}

function openVpnText(check: OpenVpnCheck | null, failed: string | null): { text: string, error: boolean } {
  if (failed) return { text: failed, error: true };
  if (!check) return { text: "Looking for OpenVPN", error: false };
  if (check.program) return { text: `OpenVPN ${check.program.version} at ${check.program.path}`, error: false };
  return { text: check.problem ?? "OpenVPN wasn't found", error: true };
}

// The same block in Settings > VPN and in onboarding's VPN step, so the two can't drift apart.
function VpnSystemSetup() {
  const { settings, updateVpn } = useSettingsState;
  const [status, setStatus] = createSignal<VpnServiceStatus | null>(null);
  const [statusError, setStatusError] = createSignal<string | null>(null);
  const [access, setAccess] = createSignal<VpnServiceAccess>("everyone");
  const [check, setCheck] = createSignal<OpenVpnCheck | null>(null);
  const [checkError, setCheckError] = createSignal<string | null>(null);
  const [help, setHelp] = createSignal<OpenVpnInstallHelp>({ kind: "none" });
  const [busy, setBusy] = createSignal(false);

  async function loadStatus() {
    try {
      const next = await safeInvoke("vpn_service_status");
      setStatus(next);
      setStatusError(null);
      if (next.state === "running") setAccess(next.access);
    } catch (error) {
      setStatusError(errorMessage(error));
    }
  }

  async function loadOpenVpn() {
    try {
      setCheck(await safeInvoke("check_openvpn", { program: settings.vpn.program.trim() || null }));
      setCheckError(null);
    } catch (error) {
      setCheckError(errorMessage(error));
    }
  }

  onMount(() => {
    void loadStatus();
    void safeInvoke("openvpn_install_help").then(setHelp).catch(() => undefined);
  });
  createEffect(on(() => settings.vpn.program, () => void loadOpenVpn()));

  // VPNs that are on with the service stop while it's set up again or removed.
  async function confirmStopping(action: string): Promise<boolean> {
    const running = useVpnState.file.profiles.filter(profile => useVpnState.status(profile.id)?.with === "fran" && useVpnState.onComputer(profile.id));
    if (running.length === 0) return true;
    return usePromptState.confirm({
      title: `${action} Fran's VPN service?`,
      message: `${plural(running.length, "VPN")} on with it turn${running.length === 1 ? "s" : ""} off: ${running.map(profile => profile.label).join(", ")}.`,
      confirmLabel: action,
      danger: true,
    });
  }

  async function run(action: () => Promise<VpnServiceStatus>) {
    setBusy(true);
    try {
      const next = await action();
      setStatus(next);
      setStatusError(null);
    } catch (error) {
      useToastState.pushError(error);
      await loadStatus();
    } finally {
      setBusy(false);
    }
  }

  async function setUp() {
    if (!(await confirmStopping(status()?.state === "notSetUp" ? "Set up" : "Update"))) return;
    await run(() => safeInvoke("set_up_vpn_service", { access: access() }));
  }

  async function changeAccess(next: VpnServiceAccess) {
    setAccess(next);
    if (status()?.state !== "running") return;
    await run(() => safeInvoke("set_vpn_service_access", { access: next }));
  }

  async function remove() {
    if (!(await confirmStopping("Remove"))) return;
    await run(() => safeInvoke("remove_vpn_service"));
  }

  async function installOpenVpn() {
    setBusy(true);
    try {
      await safeInvoke("install_openvpn");
      await loadOpenVpn();
    } catch (error) {
      useToastState.pushError(error);
    } finally {
      setBusy(false);
    }
  }

  const service = createMemo(() => serviceText(status(), statusError()));
  const openVpn = createMemo(() => openVpnText(check(), checkError()));
  const state = createMemo(() => status()?.state ?? null);
  const canSetUp = createMemo(() => {
    const current = status();
    return current?.state === "notSetUp" && !current.nixos;
  });
  const canUpdate = createMemo(() => {
    const current = status();
    return current?.state === "needsUpdate" || (current?.state === "running" && current.outdated);
  });
  const canRemove = createMemo(() => state() === "running" || state() === "notRunning" || state() === "needsUpdate");
  const showAccess = createMemo(() => canSetUp() || state() === "running");
  const installCommand = createMemo(() => {
    const current = help();
    return current.kind === "command" ? current.command : null;
  });
  const installWith = createMemo(() => {
    const current = help();
    return current.kind === "run" ? current.with : null;
  });
  const profilesNeedOpenVpn = createMemo(() => useVpnState.file.profiles.some(profile => profile.needsSystem.length > 0));
  const showOpenVpn = createMemo(() => settings.vpn.systemWith === "openvpn" || profilesNeedOpenVpn());
  const openVpnMissing = createMemo(() => check() !== null && check()?.program === null);
  const openVpnError = createMemo(() => openVpn().error && !installCommand());
  const accessHint = createMemo(() => (state() === "running" ? `${ACCESS_HINTS[access()]} Changing this asks for admin rights once.` : ACCESS_HINTS[access()]));

  return (
    <SettingGroup title="Turning VPNs on for this computer">
      <SettingRow
        name="Fran's VPN service"
        hint={<>Turns VPNs on for this computer. It runs OpenVPN and WireGuard as a small system service. <span classList={{ [styles.HintError]: service().error }}>{service().text}</span></>}
      >
        <div class={styles.FormActions}>
          <Show when={canSetUp()}>
            <Button variant="primary" size="sm" disabled={busy()} onClick={() => void setUp()}>Set up</Button>
          </Show>
          <Show when={canUpdate()}>
            <Button variant="primary" size="sm" disabled={busy()} onClick={() => void setUp()}>Update</Button>
          </Show>
          <Show when={canRemove()}>
            <Button variant="subtle" size="sm" disabled={busy()} onClick={() => void remove()}>Remove</Button>
          </Show>
        </div>
      </SettingRow>

      <Show when={showAccess()}>
        <SettingRow name="Who may use it" hint={accessHint()}>
          <Select value={access()} items={ACCESS_ITEMS} disabled={busy()} onChange={next => void changeAccess(next)} />
        </SettingRow>
      </Show>

      <Show when={showOpenVpn()}>
        <SettingRow
          name="Installed OpenVPN"
          hint={<>For the profiles Fran's engine can't run, like TAP, legacy ciphers and proxies. <span classList={{ [styles.HintError]: openVpnError() }}>{openVpn().text}</span></>}
          below={
            <Show when={openVpnMissing() && installCommand()}>
              {command => (
                <div class={styles.PathField}>
                  <code>{command()}</code>
                  <Button icon size="sm" tooltip="Copy" onClick={() => void copyText(command(), "Command")}>
                    <Copy size={14} />
                  </Button>
                </div>
              )}
            </Show>
          }
        >
          <Show when={openVpnMissing() && installWith()}>
            {tool => (
              <Button variant="subtle" size="sm" disabled={busy()} tooltip={`Runs ${tool()}, which asks for admin rights itself`} onClick={() => void installOpenVpn()}>
                Install OpenVPN
              </Button>
            )}
          </Show>
        </SettingRow>
      </Show>

      <SettingRow
        name="OpenVPN profiles use"
        hint="WireGuard profiles always use Fran's VPN service. Fran's own tunnels need neither of these. They carry only Fran's connections and never need admin rights."
      >
        <Select value={settings.vpn.systemWith} items={BACKEND_ITEMS} onChange={systemWith => void updateVpn({ systemWith })} />
      </SettingRow>
    </SettingGroup>
  );
}

export default VpnSystemSetup;
