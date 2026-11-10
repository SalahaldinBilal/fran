import shared from "./Panels.module.scss";
import groups from "./DatabasesPanel.module.scss";
import styles from "./SshHostsPanel.module.scss";
import { For, Match, Show, Switch, createMemo, createSignal } from "solid-js";
import {
  Check, CircleAlert, Download, Globe, GripVertical, LayoutGrid, Link, Pencil, Plus, Rows3, Server, SquareTerminal, X,
} from "lucide-solid";
import useSshState from "@core/states/sshState";
import useHostEditorState from "@core/states/hostEditorState";
import useSshImportState from "@core/states/sshImportState";
import useContextMenuState from "@core/states/contextMenuState";
import HostCard, { activateHost, hostMenuItems } from "../HostCard/HostCard";
import useSettingsState from "@core/states/settingsState";
import useToastState from "@core/states/toastState";
import { startReorder } from "@core/helpers/dragReorder";
import { errorMessage } from "@core/helpers/errors";
import { featureOn } from "@core/helpers/features";
import { SshHost } from "@core/types";
import Button from "@core/components/Button/Button";
import Input from "@core/components/Input/Input";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Spinner from "@core/components/Spinner/Spinner";
import { ItemBadge, ItemIcon } from "@core/components/ItemParts/ItemParts";
import PanelFrame from "./PanelFrame";
import { PanelProps } from "./types";

type Preview = { groups: string[] } | { id: string, group: string, ids: string[] };

// The compact view: one line per host.
function HostRow(props: { host: SshHost, onGrab?: (event: PointerEvent) => void }) {
  const ssh = useSshState;
  const editor = useHostEditorState;
  const { openContextMenu } = useContextMenuState;

  const address = createMemo(() => ssh.address(props.host));
  const jumps = createMemo(() => props.host.jumps.flatMap(id => ssh.host(id)?.label ?? []));
  const proxy = createMemo(() => ssh.proxy(props.host.proxyId));
  const terminalsOn = createMemo(() => featureOn("ssh"));
  const filled = createMemo(() => useSettingsState.settings.colorFill && props.host.color !== null);

  return (
    <div
      class={`${shared.Row} ${styles.HostRow}`}
      classList={{ [shared.Filled]: filled() }}
      role="button"
      tabIndex={0}
      style={{ "--row-color": props.host.color ?? "var(--accent)" }}
      onClick={() => activateHost(props.host)}
      onKeyDown={event => {
        if (event.key === "Enter") activateHost(props.host);
      }}
      onContextMenu={event => openContextMenu(event, hostMenuItems(props.host))}
    >
      <Show when={props.onGrab}>
        {grab => (
          <span class={groups.Grip} onClick={event => event.stopPropagation()} onPointerDown={event => grab()(event)}>
            <GripVertical size={14} />
          </span>
        )}
      </Show>
      <ItemIcon><Server size={15} /></ItemIcon>
      <span class={shared.RowText}>
        <span class={shared.RowName}>{props.host.label}</span>
        <span class={shared.RowSub}>{address()}</span>
      </span>
      <span class={styles.Badges}>
        <Show when={jumps().length > 0}>
          <ItemBadge><Link size={11} />via {jumps().join(", ")}</ItemBadge>
        </Show>
        <Show when={proxy()}>
          {item => <ItemBadge><Globe size={11} />{item().label}</ItemBadge>}
        </Show>
        <Show when={props.host.agentForwarding}>
          <ItemBadge tone="warning">Agent forwarding</ItemBadge>
        </Show>
      </span>
      <span class={styles.Tools}>
        <Button
          icon
          size="sm"
          tooltip="Edit"
          onClick={event => {
            event.stopPropagation();
            editor.open(props.host);
          }}
        >
          <Pencil size={13} />
        </Button>
      </span>
      <Show when={terminalsOn()}>
        <span class={shared.RowEnd}><SquareTerminal size={13} /></span>
      </Show>
    </div>
  );
}

function SshHostsPanel(props: PanelProps) {
  const ssh = useSshState;
  const editor = useHostEditorState;
  const importer = useSshImportState;
  const { pushError } = useToastState;
  const [editing, setEditing] = createSignal(false);
  const [newGroup, setNewGroup] = createSignal("");
  const [renaming, setRenaming] = createSignal<string | null>(null);
  const [preview, setPreview] = createSignal<Preview | null>(null);
  let sectionList!: HTMLDivElement;

  const filtered = createMemo(() => {
    const needle = editing() ? "" : props.search.trim().toLowerCase();
    if (!needle) return ssh.file.hosts;
    return ssh.file.hosts.filter(host => [host.label, host.host, host.group ?? ""].some(text => text.toLowerCase().includes(needle)));
  });

  // While dragging, the preview decides where the moved host or group shows.
  const sectionMap = createMemo(() => {
    const current = preview();
    const moving = current && "ids" in current ? current : null;
    const byGroup = new Map<string, SshHost[]>();
    if (editing()) {
      for (const key of ["", ...ssh.file.groupOrder]) byGroup.set(key, []);
    }
    let dragged: SshHost | undefined;
    for (const host of filtered()) {
      const key = host.group ?? "";
      if (!byGroup.has(key)) byGroup.set(key, []);
      if (host.id === moving?.id) dragged = host;
      else byGroup.get(key)!.push(host);
    }
    if (moving && dragged) {
      const members = [...(byGroup.get(moving.group) ?? []), dragged];
      byGroup.set(moving.group, members.sort((a, b) => moving.ids.indexOf(a.id) - moving.ids.indexOf(b.id)));
    }
    return byGroup;
  });

  const sectionKeys = createMemo(() => {
    const current = preview();
    const order = current && "groups" in current ? current.groups : ssh.file.groupOrder;
    function rank(key: string) {
      const index = order.indexOf(key);
      return index >= 0 ? index : order.length + (key === "" ? 1 : 0);
    }
    return [...sectionMap().keys()].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
  });

  const count = createMemo(() => (ssh.file.hosts.length > 0 ? ssh.file.hosts.length : null));
  const canAddGroup = createMemo(() => newGroup().trim() !== "" && !sectionMap().has(newGroup().trim()));
  const emptyDescription = createMemo(() => (featureOn("ssh")
    ? "Add the servers you log in to, or import your ~/.ssh/config."
    : "Database connections can tunnel through a saved host. Add one, or import your ~/.ssh/config."));
  const editTooltip = createMemo(() => (editing() ? "Done editing groups" : "Edit groups"));
  const compact = createMemo(() => useSettingsState.settings.compactHosts);
  const viewTooltip = createMemo(() => (compact() ? "Show as cards" : "Compact view"));
  const listClass = createMemo(() => `${styles.HostList} ${compact() ? shared.Rows : groups.Grid}`);

  async function save(ids: string[], groupOrder: string[], moved?: { id: string, group: string | null }) {
    try {
      await ssh.reorderHosts(ids, groupOrder.filter(key => key !== ""), moved);
    } catch (error) {
      pushError(error);
    }
  }

  function currentIds(): string[] {
    return sectionKeys().flatMap(key => (sectionMap().get(key) ?? []).map(host => host.id));
  }

  function addGroup() {
    if (!canAddGroup()) return;
    const name = newGroup().trim();
    const keys = sectionKeys();
    const at = keys[keys.length - 1] === "" ? keys.length - 1 : keys.length;
    setNewGroup("");
    void save(ssh.file.hosts.map(host => host.id), [...keys.slice(0, at), name, ...keys.slice(at)]);
  }

  async function commitRename(key: string, value: string) {
    setRenaming(null);
    const name = value.trim();
    if (!name || name === key) return;
    try {
      await ssh.renameGroup(key, name);
    } catch (error) {
      pushError(error);
    }
  }

  function grabGroup(event: PointerEvent, key: string, header: HTMLElement) {
    startReorder(event, {
      id: key,
      items: () => [...sectionList.children] as HTMLElement[],
      axis: "y",
      ghost: header,
      onPlace: placement => {
        if ("zone" in placement) return;
        const order = sectionKeys().filter(other => other !== key);
        order.splice(order.indexOf(placement.target) + (placement.after ? 1 : 0), 0, key);
        setPreview({ groups: order });
      },
      onEnd: commitOrder,
    });
  }

  function grabHost(event: PointerEvent, id: string) {
    startReorder(event, {
      id,
      items: () => [...sectionList.querySelectorAll<HTMLElement>(`.${styles.HostList} > [data-id]`)],
      zones: () => [...sectionList.children] as HTMLElement[],
      axis: compact() ? "y" : "x",
      onPlace: placement => {
        const map = sectionMap();
        const group = "zone" in placement
          ? placement.zone
          : [...map.keys()].find(key => map.get(key)!.some(host => host.id === placement.target))!;
        const ids = (map.get(group) ?? []).map(host => host.id).filter(other => other !== id);
        const at = "zone" in placement ? ids.length : ids.indexOf(placement.target) + (placement.after ? 1 : 0);
        ids.splice(at, 0, id);
        setPreview({ id, group, ids });
      },
      onEnd: commitOrder,
    });
  }

  async function commitOrder() {
    const current = preview();
    if (!current) return;
    const order = sectionKeys();
    const ids = currentIds();
    let moved: { id: string, group: string | null } | undefined;
    if ("ids" in current) {
      const host = ssh.host(current.id);
      if (host && (host.group ?? "") !== current.group) moved = { id: current.id, group: current.group || null };
    }
    setPreview(null);
    await save(ids, order, moved);
  }

  return (
    <PanelFrame
      title="SSH hosts"
      icon={Server}
      count={count()}
      controls={props.controls}
      actions={
        <>
          <Show when={ssh.file.hosts.length > 0}>
            <Button icon size="sm" tooltip={viewTooltip()} onClick={() => void useSettingsState.update({ compactHosts: !compact() })}>
              <Show when={compact()} fallback={<Rows3 size={14} />}><LayoutGrid size={14} /></Show>
            </Button>
            <Button icon size="sm" active={editing()} tooltip={editTooltip()} onClick={() => setEditing(!editing())}>
              <Show when={editing()} fallback={<Pencil size={14} />}><Check size={14} /></Show>
            </Button>
          </Show>
          <Button icon size="sm" tooltip="Import from ~/.ssh/config" onClick={importer.open}>
            <Download size={14} />
          </Button>
          <Button icon size="sm" tooltip="New SSH host" onClick={() => editor.open(null)}>
            <Plus size={14} />
          </Button>
        </>
      }
    >
      <Switch>
        <Match when={!ssh.loaded()}>
          <div class={shared.Center}><Spinner size={18} /></div>
        </Match>
        <Match when={ssh.loadError()}>
          <div class={shared.Center}>
            <EmptyState
              tone="danger"
              icon={CircleAlert}
              title="SSH hosts couldn't be loaded"
              description={errorMessage(ssh.loadError())}
              actions={<Button variant="subtle" onClick={ssh.load}>Try again</Button>}
            />
          </div>
        </Match>
        <Match when={ssh.file.hosts.length === 0}>
          <div class={shared.Center}>
            <EmptyState
              icon={Server}
              title="No SSH hosts yet"
              description={emptyDescription()}
              actions={
                <>
                  <Button variant="subtle" onClick={importer.open}>
                    <Download size={14} />
                    Import
                  </Button>
                  <Button variant="primary" onClick={() => editor.open(null)}>
                    <Plus size={14} />
                    New host
                  </Button>
                </>
              }
            />
          </div>
        </Match>
        <Match when={filtered().length === 0}>
          <div class={shared.Center}>
            <EmptyState title="Nothing matches" description={`No host matches "${props.search.trim()}".`} />
          </div>
        </Match>
        <Match when={true}>
          <div ref={sectionList}>
            <For each={sectionKeys()}>
              {key => {
                const hosts = createMemo(() => sectionMap().get(key) ?? []);
                const renamable = createMemo(() => editing() && key !== "");
                let header!: HTMLElement;
                return (
                  <section class={groups.Section} data-id={key}>
                    <Show when={key !== "" || sectionKeys().length > 1}>
                      <header ref={header} class={groups.SectionHeader}>
                        <Show when={editing()}>
                          <span class={groups.Grip} onPointerDown={event => grabGroup(event, key, header)}>
                            <GripVertical size={14} />
                          </span>
                        </Show>
                        <Show
                          when={renaming() === key}
                          fallback={
                            <h3
                              class={groups.SectionTitle}
                              classList={{ [groups.Renamable]: renamable() }}
                              onClick={() => {
                                if (renamable()) setRenaming(key);
                              }}
                            >
                              {key || "Ungrouped"}
                            </h3>
                          }
                        >
                          <input
                            class={groups.RenameInput}
                            value={key}
                            size={Math.max(8, key.length + 2)}
                            ref={input => queueMicrotask(() => {
                              input.focus();
                              input.select();
                            })}
                            onKeyDown={event => {
                              if (event.key === "Enter") void commitRename(key, event.currentTarget.value);
                              if (event.key === "Escape") setRenaming(null);
                            }}
                            onBlur={event => {
                              if (renaming() === key) void commitRename(key, event.currentTarget.value);
                            }}
                          />
                        </Show>
                        <Show when={renamable() && hosts().length === 0}>
                          <Button
                            icon
                            size="sm"
                            class={groups.RemoveGroup}
                            tooltip="Remove group"
                            onClick={() => void save(currentIds(), sectionKeys().filter(other => other !== key))}
                          >
                            <X size={14} />
                          </Button>
                        </Show>
                      </header>
                    </Show>
                    <div class={listClass()} classList={{ [styles.EmptyGroup]: hosts().length === 0 }}>
                      <Show when={hosts().length === 0}>
                        <span>Drop hosts here</span>
                      </Show>
                      <For each={hosts()}>
                        {host => {
                          const onGrab = createMemo(() => (editing() ? (event: PointerEvent) => grabHost(event, host.id) : undefined));
                          return (
                            <div data-id={host.id}>
                              <Show when={compact()} fallback={<HostCard host={host} onGrab={onGrab()} />}>
                                <HostRow host={host} onGrab={onGrab()} />
                              </Show>
                            </div>
                          );
                        }}
                      </For>
                    </div>
                  </section>
                );
              }}
            </For>
          </div>
          <Show when={editing()}>
            <div class={groups.AddGroup}>
              <Input
                class={groups.GroupInput}
                value={newGroup()}
                onValue={setNewGroup}
                placeholder="New group"
                onKeyDown={event => {
                  if (event.key === "Enter") addGroup();
                }}
              />
              <Button variant="subtle" disabled={!canAddGroup()} onClick={addGroup}>
                <Plus size={14} />
                Add group
              </Button>
            </div>
          </Show>
        </Match>
      </Switch>
    </PanelFrame>
  );
}

export default SshHostsPanel;
