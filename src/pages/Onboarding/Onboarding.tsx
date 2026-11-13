import styles from "./Onboarding.module.scss";
import { For, Match, Show, Switch, createMemo, createSignal, onCleanup, onMount } from "solid-js";
import { createStore } from "solid-js/store";
import { ArrowLeft, ArrowRight, Check, CircleAlert, Cloud, CloudCheck, Database, FileX, LucideIcon, Shield, ShieldCheck, SquareTerminal } from "@core/icons";
import useSettingsState, { Features } from "@core/states/settingsState";
import useToastState from "@core/states/toastState";
import { createSshImport } from "@core/helpers/sshImport";
import { errorMessage } from "@core/helpers/errors";
import { plural } from "@core/helpers";
import SshImportList from "@core/components/SshImport/SshImportList";
import useConnectionsState from "@core/states/connectionsState";
import useOnboardingState from "@core/states/onboardingState";
import useVaultState from "@core/states/vaultState";
import useModalState from "@core/states/modalState";
import useSyncState from "@core/states/syncState";
import { IS_MAC, IS_WINDOWS } from "@core/helpers/platform";
import Button from "@core/components/Button/Button";
import Spinner from "@core/components/Spinner/Spinner";
import VpnSystemSetup from "@core/components/VpnSystemSetup/VpnSystemSetup";

type Step = "pick" | "vpn" | "import" | "sync" | "secrets";

type Choice = {
  feature: keyof Features,
  icon: LucideIcon,
  title: string,
  text: string,
  points: string[],
};

const CHOICES: Choice[] = [
  {
    feature: "database",
    icon: Database,
    title: "Database client",
    text: "MySQL, PostgreSQL, SQLite and Cloudflare D1.",
    points: ["Query tabs with editable results", "Table designer", "MCP server for coding agents"],
  },
  {
    feature: "ssh",
    icon: SquareTerminal,
    title: "SSH client",
    text: "Terminals for the servers you manage.",
    points: ["Split terminals and snippets", "Jump hosts, proxies and port forwards", "Keys kept in the vault"],
  },
  {
    feature: "vpn",
    icon: Shield,
    title: "VPN client",
    text: "OpenVPN and WireGuard, only for the connections that need it.",
    points: ["Import .ovpn and WireGuard .conf files", "Several VPNs at once", "No admin rights needed"],
  },
];

const KEY_STORE = IS_WINDOWS ? "Windows Credential Manager" : IS_MAC ? "the macOS Keychain" : "your system's keyring";

function Onboarding() {
  const onboarding = useOnboardingState;
  const vault = useVaultState;

  const returning = onboarding.replaying() || useConnectionsState.connections.length > 0;
  const [picks, setPicks] = createStore<Features>(returning ? { ...useSettingsState.settings.features } : { database: false, ssh: false, vpn: false });
  const [step, setStep] = createSignal<Step>("pick");
  const [finishing, setFinishing] = createSignal(false);
  const [importing, setImporting] = createSignal(false);
  const importer = createSshImport();

  const steps = createMemo<Step[]>(() => [
    "pick",
    ...(picks.vpn ? ["vpn" as const] : []),
    ...(picks.ssh ? ["import" as const] : []),
    "sync",
    "secrets",
  ]);
  const stepIndex = createMemo(() => steps().indexOf(step()));
  const importLabel = createMemo(() => `Import ${plural(importer.picked().size, "host")}`);
  const picked = createMemo(() => picks.database || picks.ssh || picks.vpn);
  const leftOut = createMemo(() => {
    const names = CHOICES.filter(choice => !picks[choice.feature]).map(choice => choice.title);
    if (names.length === 0) return null;
    return names.length === 1 ? `${names[0]} is` : `${names.join(" and ")} are`;
  });

  const clouds = createMemo(() => useSyncState.view.clouds.map(cloud => cloud.name).join(", "));

  onMount(() => onCleanup(useModalState.track()));

  function next() {
    const following = steps()[stepIndex() + 1];
    if (following === "import") void importer.load();
    if (following) setStep(following);
  }

  function back() {
    const previous = steps()[stepIndex() - 1];
    if (previous) setStep(previous);
  }

  async function runImport() {
    setImporting(true);
    try {
      await importer.run();
      next();
    } catch (error) {
      useToastState.pushError(error);
    } finally {
      setImporting(false);
    }
  }

  async function finish() {
    setFinishing(true);
    try {
      await onboarding.finish({ ...picks });
    } finally {
      setFinishing(false);
    }
  }

  return (
    <div class={styles.Onboarding}>
      <div class={styles.Card}>
        <div class={styles.Steps}>
          <For each={steps()}>
            {(_, index) => <span class={styles.Bar} classList={{ [styles.Done]: index() <= stepIndex() }} />}
          </For>
          <span class={styles.StepLabel}>Step {stepIndex() + 1} of {steps().length}</span>
        </div>

        <Switch>
          <Match when={step() === "pick"}>
            <div>
              <h1 class={styles.Title}>What will you use Fran for?</h1>
              <p class={styles.Lead}>Pick any of them. The rest stays out of your way, and you can change this in Settings.</p>
            </div>

            <div class={styles.Choices}>
              <For each={CHOICES}>
                {choice => {
                  const selected = createMemo(() => picks[choice.feature]);
                  return (
                    <button
                      type="button"
                      class={styles.Choice}
                      classList={{ [styles.Selected]: selected() }}
                      aria-pressed={selected()}
                      onClick={() => setPicks(choice.feature, !selected())}
                    >
                      <span class={styles.Check}><Check size={13} /></span>
                      <span class={styles.ChoiceIcon}><choice.icon size={20} /></span>
                      <span class={styles.ChoiceTitle}>{choice.title}</span>
                      <span class={styles.ChoiceText}>{choice.text}</span>
                      <ul class={styles.Points}>
                        <For each={choice.points}>
                          {point => <li><Check size={13} />{point}</li>}
                        </For>
                      </ul>
                    </button>
                  );
                }}
              </For>
            </div>

            <div class={styles.Footer}>
              <Show when={!picked()}>
                <span class={styles.Hint}>Pick at least one to continue</span>
              </Show>
              <div class={styles.Spacer} />
              <Show when={onboarding.replaying()}>
                <Button variant="ghost" onClick={onboarding.cancel}>Cancel</Button>
              </Show>
              <Button variant="primary" disabled={!picked()} onClick={next}>
                Continue
                <ArrowRight size={14} />
              </Button>
            </div>
          </Match>

          <Match when={step() === "vpn"}>
            <div>
              <h1 class={styles.Title}>VPNs for the whole computer</h1>
              <p class={styles.Lead}>
                Fran's own tunnels need none of this. They carry only Fran's connections and never ask for admin rights. To turn a VPN on
                for the whole computer, set up Fran's VPN service. The installed OpenVPN is only for OpenVPN profiles Fran's engine
                can't run, or if you'd rather use it.
              </p>
            </div>

            <VpnSystemSetup />

            <p class={styles.Hint}>Skipping installs nothing. You can set this up later in Settings, VPN.</p>

            <div class={styles.Footer}>
              <Button variant="ghost" onClick={back}>
                <ArrowLeft size={14} />
                Back
              </Button>
              <div class={styles.Spacer} />
              <Button variant="ghost" onClick={next}>Skip</Button>
              <Button variant="primary" onClick={next}>
                Continue
                <ArrowRight size={14} />
              </Button>
            </div>
          </Match>

          <Match when={step() === "import"}>
            <div>
              <h1 class={styles.Title}>Bring your SSH hosts</h1>
              <p class={styles.Lead}>From your OpenSSH config. Key files stay where they are and are read when you connect.</p>
            </div>

            <Switch>
              <Match when={importer.loading()}>
                <div class={styles.Note}>
                  <Spinner size={14} />
                  <span>Reading ~/.ssh/config</span>
                </div>
              </Match>
              <Match when={importer.error()}>
                <div class={`${styles.Note} ${styles.Problem}`}>
                  <CircleAlert size={15} />
                  <span>The config couldn't be read. {errorMessage(importer.error())}</span>
                </div>
              </Match>
              <Match when={importer.preview() && importer.preview()!.candidates.length === 0}>
                <div class={styles.Note}>
                  <FileX size={15} />
                  <span>No hosts found in {importer.preview()!.path}. You can add hosts on Home later.</span>
                </div>
              </Match>
              <Match when={importer.preview()}>
                {preview => (
                  <SshImportList
                    candidates={preview().candidates}
                    skippedPatterns={preview().skippedPatterns}
                    picked={importer.picked()}
                    onToggle={importer.toggle}
                  />
                )}
              </Match>
            </Switch>

            <div class={styles.Footer}>
              <Button variant="ghost" onClick={back}>
                <ArrowLeft size={14} />
                Back
              </Button>
              <div class={styles.Spacer} />
              <Button variant="ghost" onClick={next}>Skip</Button>
              <Button variant="primary" disabled={importing() || importer.picked().size === 0} onClick={runImport}>
                {importLabel()}
                <ArrowRight size={14} />
              </Button>
            </div>
          </Match>

          <Match when={step() === "sync"}>
            <div>
              <h1 class={styles.Title}>The same setup on every computer</h1>
              <p class={styles.Lead}>
                Sync keeps your connections, SSH hosts, VPNs, snippets and settings in a cloud you choose, and brings them to your other
                computers. Everything is encrypted here first, so the server can't read it. Passwords and keys only sync if you turn them on.
              </p>
            </div>

            <Show
              when={clouds()}
              fallback={
                <div class={styles.Note}>
                  <Cloud size={15} />
                  <span class={styles.NoteText}>Already syncing on another computer? Sign in to bring everything here.</span>
                  <Button variant="subtle" size="sm" onClick={() => useSyncState.openAdd()}>Add a cloud</Button>
                </div>
              }
            >
              {names => (
                <div class={`${styles.Note} ${styles.Ok}`}>
                  <CloudCheck size={15} />
                  <span>Syncing with {names()}. Pick what goes where on the Sync page.</span>
                </div>
              )}
            </Show>

            <p class={styles.Hint}>Skipping changes nothing. You can add a cloud later from the cloud button in the title bar.</p>

            <div class={styles.Footer}>
              <Button variant="ghost" onClick={back}>
                <ArrowLeft size={14} />
                Back
              </Button>
              <div class={styles.Spacer} />
              <Show when={!clouds()}>
                <Button variant="ghost" onClick={next}>Skip</Button>
              </Show>
              <Button variant="primary" onClick={next}>
                Continue
                <ArrowRight size={14} />
              </Button>
            </div>
          </Match>

          <Match when={step() === "secrets"}>
            <div>
              <h1 class={styles.Title}>Where your passwords go</h1>
              <p class={styles.Lead}>
                Passwords, passphrases and keys you save are encrypted in a vault file on this computer. Its key is kept in {KEY_STORE}.
              </p>
            </div>

            <Switch>
              <Match when={vault.status() === null}>
                <div class={styles.Note}>
                  <Spinner size={14} />
                  <span>Checking the vault</span>
                </div>
              </Match>
              <Match when={vault.status()?.available}>
                <div class={`${styles.Note} ${styles.Ok}`}>
                  <ShieldCheck size={15} />
                  <span>The vault is ready. Saved secrets are only shown again after your system confirms it's you.</span>
                </div>
              </Match>
              <Match when={true}>
                <div class={`${styles.Note} ${styles.Problem}`}>
                  <CircleAlert size={15} />
                  <span>
                    The vault can't be used right now. {vault.status()?.message} You can still connect, and Fran asks for passwords each time.
                  </span>
                </div>
              </Match>
            </Switch>

            <Show when={vault.status()?.available && !vault.status()?.lockEnabled}>
              <p class={styles.Hint}>
                Want a password of its own on top? Turn on the app lock in Settings, Security. Without it, anyone signed in to this computer can open Fran.
              </p>
            </Show>

            <Show when={leftOut()}>
              {names => <p class={styles.Hint}>{names()} hidden. Turn them on any time in Settings, General.</p>}
            </Show>

            <div class={styles.Footer}>
              <Button variant="ghost" onClick={back}>
                <ArrowLeft size={14} />
                Back
              </Button>
              <div class={styles.Spacer} />
              <Button variant="primary" disabled={finishing()} onClick={finish}>
                Start using Fran
                <ArrowRight size={14} />
              </Button>
            </div>
          </Match>
        </Switch>
      </div>
    </div>
  );
}

export default Onboarding;
