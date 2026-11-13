import styles from "./Settings.module.scss";
import { createMemo, createSignal, For, JSX, Show } from "solid-js";
import {
  Bot, CircleAlert, Download, LucideIcon, Palette, Shield, ShieldCheck, SlidersHorizontal, SquareTerminal, Table2, Terminal as TerminalIcon, WandSparkles,
} from "@core/icons";
import VpnSettings from "./VpnSettings";
import SecuritySettings from "./SecuritySettings";
import useSettingsState from "@core/states/settingsState";
import useUpdaterState from "@core/states/updaterState";
import { errorMessage } from "@core/helpers/errors";
import { Feature, featureOn } from "@core/helpers/features";
import GeneralSettings from "./GeneralSettings";
import AppearanceSettings from "./AppearanceSettings";
import QuerySettings from "./QuerySettings";
import FormattingSettings from "./FormattingSettings";
import ResultSettings from "./ResultSettings";
import AgentSettings from "./AgentSettings";
import UpdateSettings from "./UpdateSettings";
import TerminalSettings from "./TerminalSettings";

export type SettingsProps = {
  onOpenAgents: () => void,
};

type SettingsSection = {
  id: string,
  label: string,
  icon: LucideIcon,
  feature: Feature,
  marked?: () => boolean,
  view: () => JSX.Element,
};

function Settings(props: SettingsProps) {
  const { loadError } = useSettingsState;
  const updater = useUpdaterState;

  const updatePending = createMemo(() => ["available", "downloading", "ready"].includes(updater.phase()));

  const sections: SettingsSection[] = [
    { id: "general", label: "General", icon: SlidersHorizontal, feature: "any", view: () => <GeneralSettings /> },
    { id: "appearance", label: "Appearance", icon: Palette, feature: "any", view: () => <AppearanceSettings /> },
    { id: "queries", label: "Queries", icon: SquareTerminal, feature: "database", view: () => <QuerySettings /> },
    { id: "formatting", label: "Formatting", icon: WandSparkles, feature: "database", view: () => <FormattingSettings /> },
    { id: "results", label: "Results", icon: Table2, feature: "database", view: () => <ResultSettings /> },
    { id: "agents", label: "Agents", icon: Bot, feature: "database", view: () => <AgentSettings onOpenAgents={props.onOpenAgents} /> },
    { id: "terminal", label: "Terminal", icon: TerminalIcon, feature: "ssh", view: () => <TerminalSettings /> },
    { id: "vpn", label: "VPN", icon: Shield, feature: "vpn", view: () => <VpnSettings /> },
    { id: "security", label: "Security", icon: ShieldCheck, feature: "any", view: () => <SecuritySettings /> },
    { id: "updates", label: "Updates", icon: Download, feature: "any", marked: updatePending, view: () => <UpdateSettings /> },
  ];

  const visibleSections = createMemo(() => sections.filter(section => featureOn(section.feature)));
  const [chosenId, setChosenId] = createSignal(sections[0].id);
  const activeId = createMemo(() => (visibleSections().some(section => section.id === chosenId()) ? chosenId() : visibleSections()[0].id));

  return (
    <div class={styles.Settings}>
      <nav class={styles.Nav}>
        <For each={visibleSections()}>
          {section => (
            <button
              type="button"
              class={styles.NavItem}
              classList={{ [styles.Active]: activeId() === section.id }}
              onClick={() => setChosenId(section.id)}
            >
              <section.icon size={18} />
              {section.label}
              <Show when={section.marked?.()}>
                <span class={styles.Mark} />
              </Show>
            </button>
          )}
        </For>
        <div class={styles.NavNote}>Saved on this machine and applied right away.</div>
      </nav>

      <div class={styles.Content}>
        <div class={styles.Wrap}>
          <Show when={loadError()}>
            <div class={styles.Error}>
              <CircleAlert size={14} />
              <span>Settings couldn't be loaded, so defaults are in use. {errorMessage(loadError())}</span>
            </div>
          </Show>
          <For each={visibleSections()}>
            {section => <Show when={activeId() === section.id}>{section.view()}</Show>}
          </For>
        </div>
      </div>
    </div>
  );
}

export default Settings;
