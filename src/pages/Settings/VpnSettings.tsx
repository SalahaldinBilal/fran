import styles from "./Settings.module.scss";
import { Show, createEffect, createMemo, createSignal, on, onCleanup } from "solid-js";
import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen } from "lucide-solid";
import useSettingsState, { VPN_CONNECT_TIMEOUTS, VPN_IDLE_CLOSE } from "@core/states/settingsState";
import useToastState from "@core/states/toastState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage } from "@core/helpers/errors";
import { IS_MAC, IS_WINDOWS } from "@core/helpers/platform";
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

const ADMIN_HINT = IS_MAC
  ? "macOS asks for your admin password each time a VPN is turned on through the installed OpenVPN. Fran's VPN service doesn't ask."
  : "Your desktop asks for the admin password each time a VPN is turned on through the installed OpenVPN. Fran's VPN service doesn't ask. Fran looks up names through the VPN's own DNS servers either way. With OpenVPN 2.6 the rest of the computer keeps its DNS, 2.7 changes it too.";

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
      ? `Your sign-in is allowed to start OpenVPN with Fran's settings, as an administrator or a member of "${current.adminGroup}".`
      : `The service only takes Fran's settings from an administrator or a member of "${current.adminGroup}". Add your account to that group. If you just did, it may already work, otherwise sign out and back in.`;
  });
  const serviceMissing = createMemo(() => failed() !== null || service()?.allowed === false);

  return (
    <SettingsPage title="VPN" description="How VPNs turn on for the whole computer, and how long Fran's own tunnels stay open.">
      <VpnSystemSetup />

      <SettingGroup title="Installed OpenVPN">
        <Show
          when={IS_WINDOWS}
          fallback={
            <>
              <SettingRow name="OpenVPN program" hint="Empty looks in the usual install folders and PATH.">
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
                    style={{ "padding-right": "3px" }}
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
        <SettingRow name="Close after" hint="How long an own tunnel stays open after the last connection using it closes.">
          <Select value={settings.vpn.idleCloseSecs} items={IDLE_ITEMS} onChange={idleCloseSecs => updateVpn({ idleCloseSecs })} />
        </SettingRow>
        <SettingRow name="Connect timeout" hint="How long a connect waits for a VPN to come up, own tunnel or for this computer.">
          <Select value={settings.vpn.connectTimeoutSecs} items={TIMEOUT_ITEMS} onChange={connectTimeoutSecs => updateVpn({ connectTimeoutSecs })} />
        </SettingRow>
      </SettingGroup>
    </SettingsPage>
  );
}

export default VpnSettings;
