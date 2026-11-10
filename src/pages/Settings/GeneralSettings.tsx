import { createMemo, createSignal, onMount } from "solid-js";
import { Database, Shield, SquareTerminal } from "lucide-solid";
import { safeInvoke } from "@core/helpers/safeInvoke";
import useSettingsState, { Features } from "@core/states/settingsState";
import useOnboardingState from "@core/states/onboardingState";
import { setFeatures } from "@core/helpers/features";
import Button from "@core/components/Button/Button";
import Toggle from "@core/components/Switch/Switch";
import { SettingGroup, SettingRow, SettingsPage } from "./SettingsLayout";
import styles from "./Settings.module.scss";

function GeneralSettings() {
  const { settings } = useSettingsState;
  const [trayAvailable, setTrayAvailable] = createSignal(true);

  onMount(() => {
    safeInvoke("tray_available").then(setTrayAvailable).catch(() => setTrayAvailable(false));
  });

  const trayMissing = createMemo(() => !trayAvailable());
  const trayHint = createMemo(() => (trayAvailable()
    ? "VPNs, port forwards, terminals and the MCP server keep running. Quit from the tray icon."
    : "This desktop has no tray, so closing the window quits Fran."));

  function toggle(feature: keyof Features, on: boolean) {
    void setFeatures({ ...settings.features, [feature]: on });
  }

  return (
    <SettingsPage title="General" description="Turning a part off hides it everywhere. Nothing you've saved is removed.">
      <SettingGroup title="What Fran is for">
        <SettingRow
          name={<span class={styles.IconName}><Database size={14} />Database client</span>}
          hint="Connections, query tabs, the table designer and the Agents tab."
        >
          <Toggle checked={settings.features.database} onChange={on => toggle("database", on)} />
        </SettingRow>
        <SettingRow
          name={<span class={styles.IconName}><SquareTerminal size={14} />SSH client</span>}
          hint="Terminals, saved hosts, keys, snippets and port forwards."
        >
          <Toggle checked={settings.features.ssh} onChange={on => toggle("ssh", on)} />
        </SettingRow>
        <SettingRow
          name={<span class={styles.IconName}><Shield size={14} />VPN client</span>}
          hint="OpenVPN and WireGuard profiles on Home. Connections and hosts that use a VPN keep working with this off."
        >
          <Toggle checked={settings.features.vpn} onChange={on => toggle("vpn", on)} />
        </SettingRow>
      </SettingGroup>
      <SettingGroup>
        <SettingRow name="Keep running in the tray when the window is closed" hint={trayHint()} hintError={trayMissing()}>
          <Toggle
            checked={settings.keepInTray}
            disabled={trayMissing()}
            onChange={keepInTray => void useSettingsState.update({ keepInTray })}
          />
        </SettingRow>
        <SettingRow name="Welcome screen" hint="Pick what you use Fran for again.">
          <Button size="sm" variant="subtle" onClick={useOnboardingState.showAgain}>Show again</Button>
        </SettingRow>
      </SettingGroup>
    </SettingsPage>
  );
}

export default GeneralSettings;
