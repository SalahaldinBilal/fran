import page from "./Sync.module.scss";
import { For, Show, createEffect, createMemo, createSignal, on, onCleanup } from "solid-js";
import { Dynamic } from "solid-js/web";
import { ChevronDown, ChevronRight, CloudSync, Ellipsis, Pencil, Plus, RefreshCw } from "@core/icons";
import { cloudModules, withCloudModule } from "@core/clouds";
import useSyncState from "@core/states/syncState";
import useSecretsState from "@core/states/secretsState";
import usePromptState from "@core/states/promptState";
import useContextMenuState from "@core/states/contextMenuState";
import useToastState from "@core/states/toastState";
import { formatAgo, plural } from "@core/helpers";
import { SYNC_CATEGORIES, kindLabel } from "@core/helpers/syncTargets";
import { Cloud, CloudKind, ReplacedItem, SyncStep, SyncProblem, SyncProblemReason } from "@core/types";
import Button from "@core/components/Button/Button";
import { tooltip } from "@core/components/Tooltip/Tooltip";
import { SettingGroup } from "../Settings/SettingsLayout";
import Routes from "./Routes";

const REPLACED_TEXT: Record<ReplacedItem["reason"], string> = {
  replaced: "Your version, replaced by a newer edit from another computer",
  deleted: "Deleted on another computer",
  overwritten: "Another computer's version, replaced by your newer edit",
};

const PROBLEM_ORDER: readonly SyncProblemReason[] = ["tooLarge", "quotaExceeded", "readOnly", "refused", "missing", "computed"];

const PROBLEM_TEXT: Record<SyncProblemReason, string> = {
  tooLarge: "Too large for this cloud, kept on this computer",
  quotaExceeded: "This cloud is full, kept on this computer",
  readOnly: "Not written, this cloud's token can only read",
  refused: "Not taken by this cloud, often a name it doesn't allow, kept on this computer",
  missing: "No longer in this cloud, the last value is kept here",
  computed: "Built from other secrets there, can only be changed there",
};

// A linked secret's value is known by the secret's name, anything else by its own label or kind.
function problemName(problem: SyncProblem): string {
  const secretId = /^vault:secret:(.+):value$/.exec(problem.key)?.[1];
  return useSecretsState.find(secretId)?.name ?? (problem.label || kindLabel(problem.key));
}

// Passes are usually over in a blink. Only one that takes longer than this shows as busy, so the pill doesn't flicker.
const BUSY_AFTER_MS = 600;

type PillTone = "good" | "busy" | "bad" | "idle";

function stepText(step: SyncStep | null): string {
  switch (step?.kind) {
    case "receiving": return `Receiving ${step.count}`;
    case "sending": return `Sending ${step.count}`;
    default: return "Checking";
  }
}

function lastPassText(cloud: Cloud): string {
  const pass = cloud.status.lastPass;
  if (!pass || (pass.received === 0 && pass.sent === 0)) return "Nothing changed last time.";
  const parts = [pass.received > 0 ? `${plural(pass.received, "item")} came in` : "", pass.sent > 0 ? `${plural(pass.sent, "item")} went up` : ""];
  return `Last time ${parts.filter(Boolean).join(" and ")}.`;
}

function CloudRow(props: { cloud: Cloud }) {
  const sync = useSyncState;
  const { pushError } = useToastState;
  const [managing, setManaging] = createSignal(false);
  const [naming, setNaming] = createSignal(false);

  const module = createMemo(() => withCloudModule(props.cloud, found => found));
  const detail = createMemo(() => module().detail(props.cloud));
  const failed = createMemo(() => props.cloud.status.phase === "error");
  const syncing = createMemo(() => props.cloud.status.phase === "syncing");
  const itemsText = createMemo(() => plural(props.cloud.items, "item"));

  const [busy, setBusy] = createSignal(false);
  let busyTimer: ReturnType<typeof setTimeout> | undefined;
  createEffect(on(syncing, now => {
    clearTimeout(busyTimer);
    if (now) busyTimer = setTimeout(() => setBusy(true), BUSY_AFTER_MS);
    else setBusy(false);
  }));
  onCleanup(() => clearTimeout(busyTimer));

  const tone = createMemo<PillTone>(() => {
    if (failed()) return "bad";
    if (busy()) return "busy";
    return props.cloud.lastSync === null ? "idle" : "good";
  });
  const pillText = createMemo(() => {
    if (props.cloud.status.signedOut) return "Signed out";
    if (failed()) return "Failed";
    if (busy()) return stepText(props.cloud.status.step);
    return props.cloud.lastSync === null ? "Starting" : "Up to date";
  });
  const pillTooltip = createMemo(() => {
    const synced = props.cloud.lastSync === null ? "Not synced yet." : `Synced ${formatAgo(props.cloud.lastSync)}.`;
    const doing = busy() ? `${stepText(props.cloud.status.step)} now. ` : "";
    return `${doing}${synced} ${lastPassText(props.cloud)} Click to sync now.`;
  });
  const open = createMemo(() => managing() || props.cloud.status.signedOut);
  // Mounted on first open and kept, so closing can slide instead of vanishing.
  const [mounted, setMounted] = createSignal(false);
  createEffect(() => {
    if (open()) setMounted(true);
  });
  const drawerLabel = createMemo(() => (open() ? "Hide" : module().accountLabel));

  function toggleManaging() {
    setManaging(shown => !shown);
  }
  const takesCategories = createMemo(() => SYNC_CATEGORIES.some(category => module().accepts(category.id)));
  const problems = createMemo(() => PROBLEM_ORDER.flatMap(reason => {
    const found = props.cloud.status.problems.filter(problem => problem.reason === reason);
    return found.length > 0 ? [{ reason, names: found.map(problemName).join(", ") }] : [];
  }));

  async function saveName(next: string) {
    if (!naming()) return;
    setNaming(false);
    if (next.trim() !== "" && next.trim() !== props.cloud.name) await sync.rename(props.cloud.id, next);
  }

  async function remove() {
    const confirmed = await usePromptState.confirm({
      title: `Remove ${props.cloud.name} from this computer?`,
      message: module().removeNote,
      confirmLabel: "Remove",
      danger: true,
    });
    if (!confirmed) return;
    try {
      await module().remove(props.cloud);
      await sync.load();
    } catch (error) {
      pushError(error);
    }
  }

  function openMenu(event: MouseEvent & { currentTarget: HTMLButtonElement }) {
    const rect = event.currentTarget.getBoundingClientRect();
    const everything = { label: "Use for everything", onSelect: () => void sync.useForEverything(props.cloud.id) };
    useContextMenuState.openMenuAt({ x: rect.left, y: rect.bottom + 2 }, [
      { label: "Rename", onSelect: () => setNaming(true) },
      ...(takesCategories() ? [everything] : []),
      { separator: true },
      { label: "Remove from this computer", danger: true, onSelect: () => void remove() },
    ]);
  }

  return (
    <div class={page.Cloud} classList={{ [page.CloudFailed]: failed() }}>
      <div class={page.CloudHead}>
        <span class={page.CloudIcon}>
          <Dynamic component={module().icon} size={18} />
        </span>
        <div class={page.CloudText}>
          <Show
            when={naming()}
            fallback={
              <div class={page.CloudNameRow}>
                <span class={page.CloudName}>{props.cloud.name}</span>
                <button type="button" class={page.Rename} ref={element => tooltip(element, () => "Rename")} onClick={() => setNaming(true)}>
                  <Pencil size={12} />
                </button>
              </div>
            }
          >
            <input
              class={page.NameInput}
              value={props.cloud.name}
              ref={element => queueMicrotask(() => element.select())}
              onKeyDown={event => {
                if (event.key === "Enter") void saveName(event.currentTarget.value);
                if (event.key === "Escape") {
                  event.stopPropagation();
                  setNaming(false);
                }
              }}
              onBlur={event => void saveName(event.currentTarget.value)}
            />
          </Show>
          <div class={page.CloudDetail}>{detail()}, {itemsText()}</div>
        </div>
        <div class={page.Tools}>
          <button
            type="button"
            class={page.Pill}
            classList={{ [page.PillGood]: tone() === "good", [page.PillBusy]: tone() === "busy", [page.PillBad]: tone() === "bad" }}
            ref={element => tooltip(element, pillTooltip)}
            onClick={() => void sync.syncNow(props.cloud.id)}
          >
            <span class={page.PillMark}>
              <Show when={tone() === "busy"} fallback={<span class={page.PillDot} />}>
                <RefreshCw size={12} class={page.Spin} />
              </Show>
              <RefreshCw size={12} class={page.PillHover} />
            </span>
            {pillText()}
          </button>
          <Button icon size="sm" tooltip="More" onClick={openMenu}>
            <Ellipsis size={16} />
          </Button>
        </div>
      </div>
      <Show when={failed() && props.cloud.status.message}>
        {text => <div class={`${page.Status} ${page.Failed}`}>{text()}</div>}
      </Show>
      <For each={problems()}>
        {group => <div class={`${page.Status} ${page.Failed}`}>{PROBLEM_TEXT[group.reason]}: {group.names}</div>}
      </For>
      <div class={page.Drawer} classList={{ [page.DrawerOpen]: open() }}>
        <div class={page.DrawerInner}>
          <Show when={mounted()}>
            <div class={page.Manage}>
              <Dynamic component={module().Account} cloud={props.cloud} />
            </div>
          </Show>
        </div>
      </div>
      <Show when={!props.cloud.status.signedOut}>
        <button type="button" class={page.DrawerBar} classList={{ [page.DrawerOpen]: open() }} aria-expanded={open()} onClick={toggleManaging}>
          {drawerLabel()}
          <ChevronDown size={14} class={page.DrawerChevron} />
        </button>
      </Show>
    </div>
  );
}

function Welcome() {
  const sync = useSyncState;

  return (
    <div class={page.Welcome}>
      <span class={page.WelcomeIcon}><CloudSync size={26} /></span>
      <h1>The same Fran on every computer</h1>
      <p>
        Connect a cloud and your connections, SSH hosts, VPNs, snippets and settings follow you. Passwords and keys only sync if you say so,
        and everything is encrypted here before it leaves.
      </p>
      <div class={page.Choices}>
        <For each={cloudModules}>
          {option => (
            <button type="button" class={page.Choice} onClick={() => sync.openAdd(option.kind as CloudKind)}>
              <span class={page.ChoiceIcon}><Dynamic component={option.icon} size={18} /></span>
              <span class={page.ChoiceText}>
                <strong>{option.label}</strong>
                <span>{option.description}</span>
              </span>
              <ChevronRight size={16} class={page.ChoiceArrow} />
            </button>
          )}
        </For>
      </div>
      <p class={page.WelcomeNote}>Already using Fran on another computer? Connect to the same cloud and sign in. Everything comes over on its own.</p>
    </div>
  );
}

const OVERALL_TEXT = { off: "", waiting: "Starting", syncing: "Syncing", upToDate: "Up to date", error: "Something needs a look" } as const;

function Sync() {
  const sync = useSyncState;

  const hasClouds = createMemo(() => sync.view.clouds.length > 0);
  const moved = createMemo(() => Object.entries(sync.view.moved));
  const overallText = createMemo(() => OVERALL_TEXT[sync.overall()]);
  const cloudsText = createMemo(() => plural(sync.view.clouds.length, "cloud"));

  function cloudName(id: string): string {
    return sync.cloud(id)?.name ?? "a cloud that was removed";
  }

  async function clearReplaced() {
    const confirmed = await usePromptState.confirm({
      title: "Clear the list?",
      message: "The replaced versions are deleted for good.",
      confirmLabel: "Clear",
      danger: true,
    });
    if (confirmed) await sync.discard(null);
  }

  return (
    <div class={page.Page}>
      <div class={page.Wrap}>
        <Show when={hasClouds()} fallback={<Welcome />}>
          <header class={page.Head}>
            <div class={page.HeadText}>
              <h1>Sync</h1>
              <div class={page.Status} classList={{ [page.Failed]: sync.overall() === "error" }}>
                <span class={page.Dot} classList={{ [page.Good]: sync.overall() === "upToDate", [page.Bad]: sync.overall() === "error" }} />
                {overallText()}, {cloudsText()}
              </div>
            </div>
            <Button variant="subtle" onClick={() => void sync.syncNow(null)}>
              <RefreshCw size={14} />
              Sync now
            </Button>
            <Button variant="primary" onClick={() => sync.openAdd()}>
              <Plus size={14} />
              Add cloud
            </Button>
          </header>

          <section class={page.Section}>
            <h3>Clouds</h3>
            <div class={page.Clouds}>
              <For each={sync.view.clouds}>{cloud => <CloudRow cloud={cloud} />}</For>
            </div>
          </section>

          <Routes />

          <Show when={sync.view.duplicates.length > 0}>
            <SettingGroup
              title="Looks like the same thing"
              after={
                <div class={page.After}>
                  <Button variant="subtle" onClick={() => void sync.settleDuplicates(null, true)}>Merge all</Button>
                </div>
              }
            >
              <div class={page.List}>
                <For each={sync.view.duplicates}>
                  {duplicate => (
                    <div class={page.Entry}>
                      <div class={page.EntryText}>
                        <strong>{duplicate.label}</strong>
                        <span>
                          {kindLabel(duplicate.local)} made on this computer, with the same name and target as one in {cloudName(duplicate.cloud)}.
                          It isn't sent until you choose.
                        </span>
                      </div>
                      <Button variant="subtle" size="sm" onClick={() => void sync.settleDuplicates([duplicate.id], true)}>Merge</Button>
                      <Button variant="ghost" size="sm" onClick={() => void sync.settleDuplicates([duplicate.id], false)}>Keep both</Button>
                    </div>
                  )}
                </For>
              </div>
            </SettingGroup>
          </Show>

          <Show when={sync.view.missing.length > 0}>
            <SettingGroup title="Waiting for something from another cloud">
              <div class={page.List}>
                <For each={sync.view.missing}>
                  {missing => (
                    <div class={page.Entry}>
                      <div class={page.EntryText}>
                        <strong>{missing.label}</strong>
                        <span>
                          Uses {kindLabel(missing.target).toLowerCase()} that{" "}
                          {missing.cloud ? `hasn't arrived from ${cloudName(missing.cloud)} yet` : "is on a cloud this computer isn't signed into"}
                        </span>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </SettingGroup>
          </Show>

          <Show when={moved().length > 0}>
            <SettingGroup title="Moved to a cloud this computer isn't signed into">
              <div class={page.List}>
                <For each={moved()}>
                  {([key]) => (
                    <div class={page.Entry}>
                      <div class={page.EntryText}>
                        <strong>{kindLabel(key)}</strong>
                        <span>Another computer moved it. The copy here is local only until this computer signs into that cloud.</span>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </SettingGroup>
          </Show>

          <Show when={sync.view.replaced.length > 0}>
            <SettingGroup
              title="Replaced by sync"
              after={
                <div class={page.After}>
                  <Button variant="ghost" onClick={() => void clearReplaced()}>Clear all</Button>
                </div>
              }
            >
              <div class={page.List}>
                <For each={sync.view.replaced}>
                  {entry => (
                    <div class={page.Entry}>
                      <div class={page.EntryText}>
                        <strong>{entry.label || kindLabel(entry.key)}</strong>
                        <span>{kindLabel(entry.key)}. {REPLACED_TEXT[entry.reason]}, {formatAgo(entry.at)}. Kept for 30 days.</span>
                      </div>
                      <Button variant="subtle" size="sm" onClick={() => void sync.restore(entry.id)}>Restore</Button>
                      <Button variant="ghost" size="sm" onClick={() => void sync.discard(entry.id)}>Discard</Button>
                    </div>
                  )}
                </For>
              </div>
            </SettingGroup>
          </Show>
        </Show>
      </div>
    </div>
  );
}

export default Sync;
