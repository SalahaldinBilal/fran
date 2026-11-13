import settingsStyles from "../Settings/Settings.module.scss";
import { For, JSX, Show, createEffect, createMemo, createSignal, onMount } from "solid-js";
import { Cog, Globe, KeyRound, Lock, LucideIcon, Shield, ShieldCheck, User } from "@core/icons";
import useSshState from "@core/states/sshState";
import useSavedSecretsState from "@core/states/savedSecretsState";
import useWorkspaceState, { SECRETS_TAB_ID } from "@core/states/workspaceState";
import PasswordsView from "./PasswordsView";
import KeysView from "./KeysView";
import VpnKeysView from "./VpnKeysView";
import InternalKeysView from "./InternalKeysView";
import IdentitiesView from "./IdentitiesView";
import ProxiesView from "./ProxiesView";
import KnownHostsView from "./KnownHostsView";

type Section = {
  id: string,
  label: string,
  icon: LucideIcon,
  count: () => number,
  view: () => JSX.Element,
};

function Secrets() {
  const ssh = useSshState;
  const saved = useSavedSecretsState;
  const [active, setActive] = createSignal("passwords");

  onMount(() => {
    ssh.loadKnownHosts().catch(() => undefined);
  });

  // Reloaded each time the tab is shown, so passwords saved elsewhere since are listed.
  // Values leave the page while it's hidden and come back without asking if it's still unlocked.
  createEffect(() => {
    if (useWorkspaceState.store.activeGlobalTabId === SECRETS_TAB_ID) {
      void saved.load();
      void saved.resume();
    } else {
      saved.hideValues();
    }
  });

  const vpnKeyOwners = createMemo(() => new Set(saved.secrets.filter(secret => secret.group === "vpn" && !secret.revealable).map(secret => secret.owner?.id)).size);
  const sections: Section[] = [
    { id: "passwords", label: "Passwords", icon: Lock, count: () => saved.secrets.filter(secret => secret.revealable).length, view: () => <PasswordsView /> },
    { id: "keys", label: "SSH keys", icon: KeyRound, count: () => ssh.file.keys.length, view: () => <KeysView /> },
    { id: "vpnKeys", label: "VPN keys", icon: Shield, count: vpnKeyOwners, view: () => <VpnKeysView /> },
    { id: "identities", label: "Identities", icon: User, count: () => ssh.file.identities.length, view: () => <IdentitiesView /> },
    { id: "proxies", label: "Proxies", icon: Globe, count: () => ssh.file.proxies.length, view: () => <ProxiesView /> },
    { id: "known", label: "Known hosts", icon: ShieldCheck, count: () => ssh.knownHosts.length, view: () => <KnownHostsView /> },
    {
      id: "internal",
      label: "Fran's keys",
      icon: Cog,
      count: () => saved.secrets.filter(secret => secret.group === "internal" || secret.group === "unknown").length,
      view: () => <InternalKeysView />,
    },
  ];
  const current = createMemo(() => sections.find(section => section.id === active()) ?? sections[0]);

  return (
    <div class={settingsStyles.Settings}>
      <nav class={settingsStyles.Nav}>
        <For each={sections}>
          {section => (
            <button
              type="button"
              class={settingsStyles.NavItem}
              classList={{ [settingsStyles.Active]: active() === section.id }}
              onClick={() => setActive(section.id)}
            >
              <section.icon size={18} />
              {section.label}
              <span class={settingsStyles.NavCount}>{section.count()}</span>
            </button>
          )}
        </For>
        <div class={settingsStyles.NavNote}>
          Everything here is in the encrypted vault on this computer. Showing or exporting a secret asks your system to confirm it's you.
        </div>
      </nav>
      <div class={settingsStyles.Content}>
        <div class={settingsStyles.Wrap} style={{ "max-width": "880px" }}>
          <Show when={current()} keyed>
            {section => section.view()}
          </Show>
        </div>
      </div>
    </div>
  );
}

export default Secrets;
