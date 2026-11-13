import styles from "./Routes.module.scss";
import { For, Show, createMemo, createSignal } from "solid-js";
import { Dynamic } from "solid-js/web";
import { Check, ChevronDown, Database, Lock, LucideIcon, Shield, SlidersHorizontal, SquareTerminal } from "@core/icons";
import { cloudModule, withCloudModule } from "@core/clouds";
import useSyncState from "@core/states/syncState";
import useSettingsState from "@core/states/settingsState";
import usePromptState from "@core/states/promptState";
import useContextMenuState, { MenuItem } from "@core/states/contextMenuState";
import { Feature, featureOn } from "@core/helpers/features";
import { SyncChoice, isSecretCategory, syncChoices, targetId } from "@core/helpers/syncTargets";
import { SyncCategory, SyncTarget } from "@core/types";
import Button from "@core/components/Button/Button";
import { tooltip } from "@core/components/Tooltip/Tooltip";

type Line = { id: SyncCategory, label: string, hint?: string };

type Area = { id: string, title: string, icon: LucideIcon, feature: Feature, lines: Line[], sensitive?: boolean };

// Ordered so each row of two pairs cards of about the same height: Databases with VPN, SSH with General.
const AREAS: Area[] = [
  {
    id: "databases",
    title: "Databases",
    icon: Database,
    feature: "database",
    lines: [
      { id: "connections", label: "Connections" },
      { id: "savedQueries", label: "Saved queries" },
    ],
  },
  {
    id: "vpn",
    title: "VPN",
    icon: Shield,
    feature: "vpn",
    lines: [{ id: "vpnProfiles", label: "Profiles", hint: "Servers, certificates and options, never the client key" }],
  },
  {
    id: "ssh",
    title: "SSH",
    icon: SquareTerminal,
    feature: "ssh",
    lines: [
      { id: "sshHosts", label: "Hosts" },
      { id: "identities", label: "Identities and keys", hint: "Logins and public keys" },
      { id: "proxies", label: "Proxies" },
      { id: "forwards", label: "Port forward rules" },
      { id: "knownHosts", label: "Known hosts" },
    ],
  },
  {
    id: "general",
    title: "General",
    icon: SlidersHorizontal,
    feature: "any",
    lines: [
      { id: "snippets", label: "Snippets" },
      { id: "settings", label: "Settings", hint: "With the choices on this page, except this one" },
      { id: "secrets", label: "Secrets", hint: "Names and notes, the values are below" },
    ],
  },
  {
    id: "sensitive",
    title: "Passwords and keys",
    icon: Lock,
    feature: "any",
    sensitive: true,
    lines: [
      { id: "passwords", label: "Passwords and secret values", hint: "Readable on every computer signed into that cloud" },
      { id: "privateKeys", label: "Private keys", hint: "SSH keys in the vault, VPN client, TLS and preshared keys" },
    ],
  },
];

const OFF_LABEL = "Off";

function choiceLabel(choice: SyncChoice | undefined): string {
  if (!choice || choice.target === null) return OFF_LABEL;
  return choice.target.kind === "withItem" ? "With its item" : choice.label;
}

async function confirmSensitive(what: string): Promise<boolean> {
  return usePromptState.confirm({
    title: `Sync ${what}?`,
    message: "They leave this computer encrypted, and any computer signed into that cloud with your password can read them. "
      + "Use a long password you don't use anywhere else.",
    confirmLabel: "Sync them",
  });
}

function openChoices(event: MouseEvent & { currentTarget: HTMLElement }, choices: SyncChoice[], current: string | null, pick: (choice: SyncChoice) => void) {
  const rect = event.currentTarget.getBoundingClientRect();
  const items: MenuItem[] = choices.map(choice => ({
    label: choice.target === null ? "Don't sync" : choice.label,
    hint: choice.hint,
    icon: choice.id === current ? Check : undefined,
    onSelect: () => pick(choice),
  }));
  useContextMenuState.openMenuAt({ x: rect.right - 220, y: rect.bottom + 4 }, items);
}

function Chip(props: { label: string, on: boolean, mixed?: boolean, onClick: (event: MouseEvent & { currentTarget: HTMLElement }) => void }) {
  return (
    <button type="button" class={styles.Chip} classList={{ [styles.ChipOn]: props.on, [styles.ChipMixed]: props.mixed ?? false }} onClick={event => props.onClick(event)}>
      <span class={styles.ChipDot} />
      <span class={styles.ChipLabel}>{props.label}</span>
      <ChevronDown size={12} class={styles.ChipArrow} />
    </button>
  );
}

// Shows the whole text in a tooltip, but only when the card is too narrow for it.
function Hint(props: { text: string }) {
  const [cut, setCut] = createSignal(false);
  const shown = createMemo(() => (cut() ? props.text : null));

  return (
    <span
      class={styles.LineHint}
      ref={element => tooltip(element, shown)}
      onMouseEnter={event => setCut(event.currentTarget.scrollWidth > event.currentTarget.clientWidth)}
    >
      {props.text}
    </span>
  );
}

function LineRow(props: { line: Line }) {
  const sync = useSyncState;
  const choices = createMemo(() => syncChoices(props.line.id, "category"));
  const current = createMemo(() => targetId(sync.categoryRoute(props.line.id)));
  const label = createMemo(() => choiceLabel(choices().find(choice => choice.id === current())));
  const on = createMemo(() => current() !== "");
  const hint = createMemo(() => (sync.view.waitingRoutes[props.line.id] ? "Your other computers send these to a cloud this one isn't signed into" : props.line.hint));

  async function pick(choice: SyncChoice) {
    if (isSecretCategory(props.line.id) && choice.target !== null && !on() && !await confirmSensitive(props.line.label.toLowerCase())) return;
    await sync.setCategoryRoute(props.line.id, choice.target);
  }

  return (
    <div class={styles.Line}>
      <div class={styles.LineText}>
        <span class={styles.LineLabel}>{props.line.label}</span>
        <Show when={hint()}>{text => <Hint text={text()} />}</Show>
      </div>
      <Chip label={label()} on={on()} onClick={event => openChoices(event, choices(), current(), choice => void pick(choice))} />
    </div>
  );
}

function NewSecretsLine() {
  const sync = useSyncState;
  const stores = createMemo(() => sync.view.clouds.filter(cloud => cloudModule(cloud.kind).secretStore));
  const chosen = createMemo(() => useSettingsState.settings.newSecretsStoredIn);
  // A cloud chosen on another computer that this one doesn't have counts as this computer here.
  const store = createMemo(() => stores().find(cloud => cloud.identity === chosen()) ?? null);
  const label = createMemo(() => store()?.name ?? "This computer");

  function open(event: MouseEvent & { currentTarget: HTMLElement }) {
    const rect = event.currentTarget.getBoundingClientRect();
    const current = store()?.identity ?? "";
    const pick = (identity: string) => void useSettingsState.update({ newSecretsStoredIn: identity });
    useContextMenuState.openMenuAt({ x: rect.right - 220, y: rect.bottom + 4 }, [
      { label: "This computer", icon: current === "" ? Check : undefined, onSelect: () => pick("") },
      ...stores().map(cloud => ({
        label: cloud.name,
        hint: cloudModule(cloud.kind).detail(cloud),
        icon: current === cloud.identity ? Check : undefined,
        onSelect: () => pick(cloud.identity),
      })),
    ]);
  }

  return (
    <Show when={stores().length > 0}>
      <div class={styles.Line}>
        <div class={styles.LineText}>
          <span class={styles.LineLabel}>New secrets are stored in</span>
          <Hint text="Unless you pick another place in the secret" />
        </div>
        <Chip label={label()} on={store() !== null} onClick={open} />
      </div>
    </Show>
  );
}

function AreaCard(props: { area: Area }) {
  const sync = useSyncState;
  const targets = createMemo(() => props.area.lines.map(line => targetId(sync.categoryRoute(line.id))));
  const syncing = createMemo(() => targets().filter(id => id !== "").length);
  const same = createMemo(() => targets().every(id => id === targets()[0]));
  const choices = createMemo(() => syncChoices(props.area.lines[0].id, "category"));
  const allLabel = createMemo(() => {
    if (!same()) return `${syncing()} of ${props.area.lines.length}`;
    return choiceLabel(choices().find(choice => choice.id === targets()[0]));
  });
  const countText = createMemo(() => (syncing() === 0 ? "Nothing syncs" : syncing() === props.area.lines.length ? "All sync" : `${syncing()} of ${props.area.lines.length} sync`));

  async function pickAll(choice: SyncChoice) {
    const turningOn = props.area.lines.some((line, index) => isSecretCategory(line.id) && choice.target !== null && targets()[index] === "");
    if (turningOn && !await confirmSensitive(props.area.title.toLowerCase())) return;
    for (const line of props.area.lines) {
      await sync.setCategoryRoute(line.id, choice.target as SyncTarget | null);
    }
  }

  return (
    <section class={styles.Card} classList={{ [styles.Wide]: props.area.sensitive ?? false, [styles.Sensitive]: props.area.sensitive ?? false }}>
      <header class={styles.CardHead}>
        <span class={styles.CardIcon}><Dynamic component={props.area.icon} size={15} /></span>
        <div class={styles.CardTitles}>
          <span class={styles.CardTitle}>{props.area.title}</span>
          <span class={styles.CardCount}>{countText()}</span>
        </div>
        <Chip
          label={allLabel()}
          on={syncing() > 0}
          mixed={!same()}
          onClick={event => openChoices(event, choices(), same() ? targets()[0] : null, choice => void pickAll(choice))}
        />
      </header>
      <div class={styles.Lines}>
        <For each={props.area.lines}>{line => <LineRow line={line} />}</For>
        <Show when={props.area.id === "general"}><NewSecretsLine /></Show>
      </div>
      <Show when={props.area.sensitive}>
        <p class={styles.Note}>Off unless you turn them on. Each can follow the item it belongs to, so a connection's password goes where the connection goes.</p>
      </Show>
    </section>
  );
}

function Routes() {
  const sync = useSyncState;
  const areas = createMemo(() => AREAS.filter(area => featureOn(area.feature)));
  const lines = createMemo(() => areas().flatMap(area => area.lines));
  const syncing = createMemo(() => lines().filter(line => sync.categoryRoute(line.id) !== null).length);
  // Only clouds that take whole categories can be used for everything. Doppler takes none.
  const everywhere = createMemo(() => sync.view.clouds.filter(cloud => withCloudModule(cloud, module => module.accepts("connections"))));
  const summary = createMemo(() => (syncing() === 0 ? "Nothing syncs yet. Pick a cloud for each kind of item, or sync everything at once." : `${syncing()} of ${lines().length} kinds of items sync.`));

  function syncEverything(event: MouseEvent & { currentTarget: HTMLElement }) {
    const clouds = everywhere();
    if (clouds.length === 1) {
      void sync.useForEverything(clouds[0].id);
      return;
    }
    const rect = event.currentTarget.getBoundingClientRect();
    useContextMenuState.openMenuAt({ x: rect.left, y: rect.bottom + 4 }, clouds.map(cloud => ({ label: cloud.name, onSelect: () => void sync.useForEverything(cloud.id) })));
  }

  return (
    <section class={styles.Routes}>
      <div class={styles.Head}>
        <div class={styles.HeadText}>
          <h3>What syncs where</h3>
          <p>{summary()}</p>
        </div>
        <Show when={everywhere().length > 0}>
          <Button variant="subtle" size="sm" onClick={syncEverything}>Sync everything</Button>
        </Show>
      </div>
      <div class={styles.Grid}>
        <For each={areas()}>{area => <AreaCard area={area} />}</For>
      </div>
    </section>
  );
}

export default Routes;
