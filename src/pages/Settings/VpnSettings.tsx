import styles from "./Settings.module.scss";
import { Show, createEffect, createMemo, createSignal, on, onCleanup } from "solid-js";
import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen } from "@core/icons";
import useSettingsState, { VPN_CONNECT_TIMEOUTS, VPN_IDLE_CLOSE } from "@core/states/settingsState";
import useToastState from "@core/states/toastState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage } from "@core/helpers/errors";
import { IS_WINDOWS } from "@core/helpers/platform";
import { OpenVpnCheck } from "@core/types";
import Select, { SelectItem } from "@core/components/Select/Select";
import Input from "@core/components/Input/Input";
import Button from "@core/components/Button/Button";
import VpnSystemSetup from "@core/components/VpnSystemSetup/VpnSystemSetup";
import { SettingGroup, SettingRow, SettingsPage } from "./SettingsLayout";

function secondsLabel(seconds: number): string {
  return seconds < 60 ? `${seconds} seconds` : `${seconds / 60} minutes`;
}

const IDLE_ITEMS: SelectItem<number>[] = VPN_IDLE_CLOSE.map(seconds => ({ value: seconds, label: secondsLabel(seconds) }));
const TIMEOUT_ITEMS: SelectItem<number>[] = VPN_CONNECT_TIMEOUTS.map(seconds => ({ value: seconds, label: secondsLabel(seconds) }));

const ADMIN_HINT = "Asks for your admin password every time it turns a VPN on. Fran's VPN service doesn't.";

function VpnSettings() {
  const { settings, updateVpn } = useSettingsState;
  const [check, setCheck] = createSignal<OpenVpnCheck | null>(null);
  const [failed, setFailed] = createSignal<string | null>(null);
  // Typed paths are saved when the field is left, not on every key.
  const [draft, setDraft] = createSignal(settings.vpn.program);

  createEffect(on(() => settings.vpn.program, program => {
    setDraft(program);
    setCheck(null);
    setFailed(null);
    let current = true;
    safeInvoke("check_openvpn", { program: program.trim() || null })
      .then(result => current && setCheck(result))
      .catch(error => current && setFailed(errorMessage(error)));
    onCleanup(() => {
      current = false;
    });
  }));

  function commit() {
    if (draft() !== settings.vpn.program) void updateVpn({ program: draft() });
  }

  async function browse() {
    try {
      const picked = await open({ multiple: false, directory: false, title: "Choose the OpenVPN program" });
      if (typeof picked === "string") void updateVpn({ program: picked });
    } catch (error) {
      useToastState.pushError(error);
    }
  }

  const service = createMemo(() => check()?.service ?? null);
  const serviceHint = createMemo(() => {
    const current = service();
    if (failed()) return failed();
    if (!current) return "Checking the OpenVPN Interactive Service";
    return current.allowed
      ? "Your account can use it."
      : `Add your account to "${current.adminGroup}", then sign out and back in.`;
  });
  const serviceMissing = createMemo(() => failed() !== null || service()?.allowed === false);

  return (
    <SettingsPage title="VPN" description="VPNs for the whole computer and Fran's own tunnels.">
      <VpnSystemSetup />

      <SettingGroup title="Installed OpenVPN">
        <Show
          when={IS_WINDOWS}
          fallback={
            <>
              <SettingRow name="OpenVPN program" hint="Leave empty to find it automatically.">
                <div class={styles.PathField}>
                  <Input
                    value={draft()}
                    onValue={setDraft}
                    onBlur={commit}
                    onKeyDown={event => {
                      if (event.key === "Enter") commit();
                    }}
                    placeholder="Found automatically"
                    mono
                    after={
                      <Button icon size="sm" tooltip="Browse" onClick={() => void browse()}>
                        <FolderOpen size={14} />
                      </Button>
                    }
                  />
                </div>
              </SettingRow>
              <SettingRow name="Admin rights" hint={ADMIN_HINT} />
            </>
          }
        >
          <SettingRow name="Interactive Service" hint={serviceHint()} hintError={serviceMissing()} />
        </Show>
      </SettingGroup>

      <SettingGroup title="Own tunnels">
        <SettingRow name="Close after" hint="Once nothing is using the tunnel.">
          <Select value={settings.vpn.idleCloseSecs} items={IDLE_ITEMS} onChange={idleCloseSecs => updateVpn({ idleCloseSecs })} />
        </SettingRow>
        <SettingRow name="Connect timeout" hint="How long to wait for a VPN to connect.">
          <Select value={settings.vpn.connectTimeoutSecs} items={TIMEOUT_ITEMS} onChange={connectTimeoutSecs => updateVpn({ connectTimeoutSecs })} />
        </SettingRow>
      </SettingGroup>
    </SettingsPage>
  );
}

export default VpnSettings;
