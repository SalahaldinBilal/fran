import styles from "./Agents.module.scss";
import { For, Show, createMemo, createSignal, onSettled } from "solid-js";
import { ChevronDown, Database, Info, Plus, RefreshCw, Search, ShieldAlert, TriangleAlert } from "@core/icons";
import { AgentAccess, AgentMode, ConnectionProfile, DatabaseRule } from "@core/types";
import { describeConnection, withDatabaseModule } from "@core/databases";
import { plural } from "@core/helpers";
import { formatClock } from "./agentText";
import useAgentState from "@core/states/agentState";
import useConnectionsState from "@core/states/connectionsState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import SegmentedControl, { SegmentedOption } from "@core/components/SegmentedControl/SegmentedControl";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Button from "@core/components/Button/Button";
import Spinner from "@core/components/Spinner/Spinner";
import Input from "@core/components/Input/Input";
import { tooltip } from "@core/components/Tooltip/Tooltip";

const MODES: SegmentedOption<AgentMode>[] = [
  { value: "off", label: "Nothing" },
  { value: "readOnly", label: "Read" },
  { value: "ask", label: "Read + ask" },
  { value: "write", label: "Read + write" },
];

const SHORT_LABELS: Record<AgentMode, string> = {
  off: "Hidden",
  readOnly: "Read",
  ask: "Ask",
  write: "Write",
};

type Choice = AgentMode | "default";

type DatabaseEntry = { name: string, system: boolean, onServer: boolean };

function describeScope(access: AgentAccess): string {
  const hidden = access.exceptions.filter(rule => rule.mode === "off").length;
  const own = access.exceptions.length - hidden;
  if (!access.allDatabases) return own === 0 ? "No databases" : `${plural(own, "database")} shared`;
  const parts = ["All databases"];
  if (hidden > 0) parts.push(`${hidden} hidden`);
  if (own > 0) parts.push(`${own} with their own level`);
  return parts.join(", ");
}

type DatabaseRowProps = {
  entry: DatabaseEntry,
  access: AgentAccess,
  onChoose: (name: string, choice: Choice) => void,
};

function DatabaseRow(props: DatabaseRowProps) {
  const rule = createMemo(() => props.access.exceptions.find(existing => existing.name === props.entry.name));
  const choice = createMemo<Choice>(() => rule()?.mode ?? "default");
  const options = createMemo(() => {
    const fallback = props.access.allDatabases ? SHORT_LABELS[props.access.mode] : SHORT_LABELS.off;
    const levels: SegmentedOption<Choice>[] = [{ value: "default", label: `Default (${fallback})` }];
    for (const mode of ["off", "readOnly", "ask", "write"] as const) {
      if (mode !== "off" || props.access.allDatabases) levels.push({ value: mode, label: SHORT_LABELS[mode] });
    }
    return levels;
  });
  const writes = createMemo(() => choice() === "write" || (choice() === "default" && props.access.allDatabases && props.access.mode === "write"));

  return (
    <div class={[styles.DbRow, { [styles.DbWrite]: writes() }]}>
      <div class={styles.DbName}>
        <Show when={writes()}>
          <TriangleAlert size={13} />
        </Show>
        <span>{props.entry.name}</span>
        <Show when={props.entry.system}>
          <span class={styles.DbTag}>system</span>
        </Show>
        <Show when={!props.entry.onServer}>
          <span class={styles.DbTag}>not on the server</span>
        </Show>
      </div>
      <SegmentedControl<Choice> value={choice()} options={options()} onChange={next => props.onChoose(props.entry.name, next)} />
    </div>
  );
}

type DatabasePanelProps = {
  profile: ConnectionProfile,
  onChange: (access: AgentAccess) => void,
};

function DatabasePanel(props: DatabasePanelProps) {
  const agent = useAgentState;
  const prompts = usePromptState;
  const [search, setSearch] = createSignal("");
  const [extra, setExtra] = createSignal<string[]>([]);

  const access = createMemo(() => props.profile.agentAccess);
  const state = createMemo(() => agent.databaseLists[props.profile.id]);
  const listed = createMemo(() => state()?.list ?? null);
  const loading = createMemo(() => state()?.loading ?? false);
  const error = createMemo(() => state()?.error ?? null);

  const entries = createMemo<DatabaseEntry[]>(() => {
    const fromServer = listed()?.databases ?? [];
    const known = new Set(fromServer.map(database => database.name));
    const ordered = [...fromServer.filter(database => !database.system), ...fromServer.filter(database => database.system)];
    const unlisted = [...access().exceptions.map(rule => rule.name), ...extra()].filter(name => {
      if (known.has(name)) return false;
      known.add(name);
      return true;
    });
    return [
      ...ordered.map(database => ({ name: database.name, system: database.system, onServer: true })),
      ...unlisted.map(name => ({ name, system: false, onServer: listed() === null })),
    ];
  });

  const needle = createMemo(() => search().trim().toLowerCase());
  const shown = createMemo(() => entries().filter(entry => entry.name.toLowerCase().includes(needle())));
  const addable = createMemo(() => {
    const name = search().trim();
    return name !== "" && !entries().some(entry => entry.name === name) ? name : null;
  });
  const sharedSession = createMemo(() => listed()?.bound === false);
  const showList = createMemo(() => !loading() || listed() !== null);
  const listedNote = createMemo(() => {
    const current = state();
    if (!current?.list || current.listedAt === null) return null;
    const count = needle() ? `${shown().length} of ${plural(entries().length, "database")}` : plural(entries().length, "database");
    return `${count}, listed at ${formatClock(current.listedAt, false)}`;
  });
  const emptyText = createMemo(() => (needle() ? `No database matches "${search().trim()}"` : "No databases to show"));

  const scopeOptions = createMemo<SegmentedOption<boolean>[]>(() => [
    { value: true, label: `Default to ${SHORT_LABELS[access().mode]}` },
    { value: false, label: "Hidden" },
  ]);

  function load(refresh = false) {
    void agent.listDatabases(props.profile, refresh);
  }

  onSettled(() => queueMicrotask(load));

  function addByName(name: string) {
    setExtra(names => [...names, name]);
  }

  async function choose(name: string, choice: Choice) {
    const current = access().exceptions.find(rule => rule.name === name)?.mode ?? "default";
    if (choice === current) return;
    const others = access().exceptions.filter(rule => rule.name !== name);
    if (choice === "default") {
      props.onChange({ ...access(), exceptions: others });
      return;
    }
    if (choice === "write" && !await prompts.askToAllowUnattendedWrites({ connectionName: props.profile.name, database: name })) return;
    const rules: DatabaseRule[] = access().exceptions.some(rule => rule.name === name)
      ? access().exceptions.map(rule => (rule.name === name ? { name, mode: choice } : rule))
      : [...others, { name, mode: choice }];
    props.onChange({ ...access(), exceptions: rules });
  }

  return (
    <div class={styles.DbPanel}>
      <div class={styles.DbPanelHead}>
        <Input
          class={styles.DbSearch}
          value={search()}
          onValue={setSearch}
          placeholder="Find or add a database"
          before={<Search size={14} />}
          clearable
          onKeyDown={event => {
            const name = addable();
            if (event.key === "Enter" && name) addByName(name);
          }}
        />
        <div class={styles.DbScope}>
          <span class={styles.DbPanelLabel}>Databases you don't set</span>
          <SegmentedControl<boolean>
            value={access().allDatabases}
            options={scopeOptions()}
            onChange={allDatabases => props.onChange({ ...access(), allDatabases })}
          />
        </div>
      </div>

      <div class={styles.DbMeta}>
        <span>{listedNote() ?? ""}</span>
        <Button size="sm" variant="subtle" disabled={loading()} onClick={() => load(true)}>
          <Show when={loading()} fallback={<RefreshCw size={13} />}>
            <Spinner size={13} />
          </Show>
          Refresh
        </Button>
      </div>

      <Show when={sharedSession()}>
        <div class={styles.DbNote}>
          <Info size={13} />
          <span>
            One session reaches every database on this server, so raw SQL that changes data still asks first unless every
            database is Write. The other change tools follow each database's level.
          </span>
        </div>
      </Show>

      <Show when={error()}>
        {message => (
          <div class={`${styles.DbNote} ${styles.DbError}`}>
            <ShieldAlert size={13} />
            <span>{message()}</span>
            <Button size="sm" variant="subtle" onClick={() => load(true)}>Try again</Button>
          </div>
        )}
      </Show>

      <Show
        when={showList()}
        fallback={
          <div class={styles.DbLoading}>
            <Spinner size={14} />
            Listing databases
          </div>
        }
      >
        <div class={styles.DbList}>
          <For each={shown()} fallback={<Show when={!addable()}><div class={styles.DbEmpty}>{emptyText()}</div></Show>}>
            {entry => <DatabaseRow entry={entry} access={access()} onChoose={(name, choice) => void choose(name, choice)} />}
          </For>
          <Show when={addable()}>
            {name => (
              <button type="button" class={styles.DbAddRow} onClick={() => addByName(name())}>
                <Plus size={13} />
                <span>Add <b>{name()}</b>, a database that isn't listed</span>
              </button>
            )}
          </Show>
        </div>
      </Show>
    </div>
  );
}

function AccessRow(props: { profile: ConnectionProfile }) {
  const connections = useConnectionsState;
  const prompts = usePromptState;
  const { pushError } = useToastState;
  const [open, setOpen] = createSignal(false);

  const details = createMemo(() =>
    withDatabaseModule(props.profile, module => ({ kind: module.label, target: describeConnection(props.profile) })),
  );
  const initial = createMemo(() => props.profile.name.trim().charAt(0).toUpperCase() || "?");
  const shared = createMemo(() => props.profile.agentAccess.mode !== "off");
  const expanded = createMemo(() => open() && shared());
  const scope = createMemo(() => describeScope(props.profile.agentAccess));
  const anyWrite = createMemo(() => {
    const access = props.profile.agentAccess;
    return (access.allDatabases && access.mode === "write") || access.exceptions.some(rule => rule.mode === "write");
  });

  async function save(access: AgentAccess) {
    try {
      await connections.save({ ...props.profile, agentAccess: access });
    } catch (error) {
      pushError(error);
    }
  }

  async function setMode(mode: AgentMode) {
    if (mode === props.profile.agentAccess.mode) return;
    if (mode === "write" && !await prompts.askToAllowUnattendedWrites({ connectionName: props.profile.name, database: null })) return;
    await save({ ...props.profile.agentAccess, mode });
  }

  return (
    <>
      <div class={styles.TableRow}>
        <div class={styles.Connection}>
          <span class={styles.Badge} style={{ "--badge": props.profile.color ?? undefined }}>{initial()}</span>
          <div class={styles.ConnectionText}>
            <div class={styles.ConnectionName}>{props.profile.name}</div>
            <div class={styles.ConnectionHost} ref={tooltip(() => details().target)}>{details().target}</div>
          </div>
        </div>
        <span class={styles.Kind}>{details().kind}</span>
        <SegmentedControl<AgentMode>
          value={props.profile.agentAccess.mode}
          options={MODES}
          onChange={mode => void setMode(mode)}
        />
        <Show when={shared()} fallback={<span class={styles.Off}>Not shared</span>}>
          <button
            type="button"
            class={[styles.DbToggle, { [styles.Open]: open() }]}
            aria-expanded={open() ? "true" : "false"}
            onClick={() => setOpen(!open())}
          >
            <Database size={14} />
            <span class={styles.DbToggleText}>{scope()}</span>
            <Show when={anyWrite()}>
              <TriangleAlert size={13} class={styles.WriteIcon} />
            </Show>
            <ChevronDown size={14} class={styles.DbChevron} />
          </button>
        </Show>
      </div>
      <Show when={expanded()}>
        <DatabasePanel profile={props.profile} onChange={access => void save(access)} />
      </Show>
    </>
  );
}

function AccessView() {
  const agent = useAgentState;
  const connections = useConnectionsState;

  return (
    <div class={styles.Scroll}>
      <div class={styles.Wrap}>
        <div class={styles.PageHead}>
          <h2>Access</h2>
          <p>What agents can do with each connection, and with each of its databases. New connections start at Nothing.</p>
        </div>

        <Show when={!agent.config.allowChanges}>
          <div class={styles.Notice}>
            <ShieldAlert size={14} />
            <span>Changes are turned off for every agent in Server, so Read + ask and Read + write work like Read for now.</span>
          </div>
        </Show>

        <Show
          when={connections.connections.length > 0}
          fallback={<EmptyState title="No connections yet" description="Add a connection on the Connections tab, then choose what agents can do with it here." />}
        >
          <div class={styles.Table}>
            <div class={`${styles.TableRow} ${styles.TableHead}`}>
              <span>Connection</span>
              <span>Type</span>
              <span>Agents can</span>
              <span>Databases</span>
            </div>
            <For each={connections.connections}>
              {profile => <AccessRow profile={profile} />}
            </For>
            <div class={styles.TableFoot}>
              <Info size={14} />
              <span>
                Read keeps agents to reads, but a database login that can only read is the only full guarantee. Changing a
                connection here closes its open agent sessions.
              </span>
            </div>
          </div>
        </Show>
      </div>
    </div>
  );
}

export default AccessView;
