import styles from "./DatabasesPanel.module.scss";
import shared from "./Panels.module.scss";
import { For, Match, Show, Switch, createMemo, createSignal } from "solid-js";
import { unwrap } from "solid-js/store";
import { Check, CircleAlert, Database, GripVertical, Pencil, Plus, X } from "@core/icons";
import useConnectionsState from "@core/states/connectionsState";
import useToastState from "@core/states/toastState";
import { startReorder } from "@core/helpers/dragReorder";
import { describeConnection } from "@core/databases";
import { errorMessage } from "@core/helpers/errors";
import { ConnectionProfile } from "@core/types";
import Button from "@core/components/Button/Button";
import Input from "@core/components/Input/Input";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Spinner from "@core/components/Spinner/Spinner";
import ConnectionCard from "../ConnectionCard/ConnectionCard";
import PanelFrame from "./PanelFrame";
import { PanelProps } from "./types";

type Preview = { groups: string[] } | { id: string, group: string, ids: string[] };

function DatabasesPanel(props: PanelProps) {
  const connections = useConnectionsState;
  const { pushError } = useToastState;
  const [editing, setEditing] = createSignal(false);
  const [newGroup, setNewGroup] = createSignal("");
  const [renaming, setRenaming] = createSignal<string | null>(null);
  const [preview, setPreview] = createSignal<Preview | null>(null);
  let sectionList!: HTMLDivElement;

  const needle = createMemo(() => (editing() ? "" : props.search.trim().toLowerCase()));

  const filtered = createMemo(() => {
    const query = needle();
    if (!query) return connections.connections;

    return connections.connections.filter(profile => {
      const target = describeConnection(profile);
      return [profile.name, profile.group ?? "", target].some(text => text.toLowerCase().includes(query));
    });
  });

  const sectionMap = createMemo(() => {
    const current = preview();
    const moving = current && "ids" in current ? current : null;
    const byGroup = new Map<string, ConnectionProfile[]>();
    if (editing()) {
      for (const key of ["", ...connections.groupOrder()]) byGroup.set(key, []);
    }
    let dragged: ConnectionProfile | undefined;
    for (const profile of filtered()) {
      const key = profile.group ?? "";
      if (!byGroup.has(key)) byGroup.set(key, []);
      if (profile.id === moving?.id) dragged = profile;
      else byGroup.get(key)!.push(profile);
    }
    if (moving && dragged) {
      const members = [...(byGroup.get(moving.group) ?? []), dragged];
      byGroup.set(moving.group, members.sort((a, b) => moving.ids.indexOf(a.id) - moving.ids.indexOf(b.id)));
    }
    return byGroup;
  });

  const sectionKeys = createMemo(() => {
    const current = preview();
    const order = current && "groups" in current ? current.groups : connections.groupOrder();
    function rank(key: string) {
      const index = order.indexOf(key);
      return index >= 0 ? index : order.length + (key === "" ? 1 : 0);
    }
    return [...sectionMap().keys()].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
  });

  const canAddGroup = createMemo(() => {
    const name = newGroup().trim();
    return name !== "" && !sectionMap().has(name);
  });

  const hasConnections = createMemo(() => connections.connections.length > 0);

  async function saveGroups(groups: string[]) {
    try {
      await connections.reorder(connections.connections.map(profile => profile.id), groups);
    } catch (error) {
      pushError(error);
    }
  }

  function addGroup() {
    if (!canAddGroup()) return;
    const name = newGroup().trim();
    const keys = sectionKeys();
    const at = keys[keys.length - 1] === "" ? keys.length - 1 : keys.length;
    setNewGroup("");
    return saveGroups([...keys.slice(0, at), name, ...keys.slice(at)]);
  }

  async function commitRename(key: string, value: string) {
    setRenaming(null);
    const name = value.trim();
    if (!name || name === key) return;
    try {
      await connections.renameGroup(key, name);
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
        const groups = sectionKeys().filter(other => other !== key);
        groups.splice(groups.indexOf(placement.target) + (placement.after ? 1 : 0), 0, key);
        setPreview({ groups });
      },
      onEnd: commitOrder,
    });
  }

  function grabCard(event: PointerEvent, id: string) {
    startReorder(event, {
      id,
      items: () => [...sectionList.querySelectorAll<HTMLElement>(`.${styles.Grid} > [data-id]`)],
      zones: () => [...sectionList.children] as HTMLElement[],
      axis: "x",
      onPlace: placement => {
        const map = sectionMap();
        const group = "zone" in placement
          ? placement.zone
          : [...map.keys()].find(key => map.get(key)!.some(profile => profile.id === placement.target))!;
        const ids = (map.get(group) ?? []).map(profile => profile.id).filter(other => other !== id);
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
    try {
      if ("ids" in current) {
        const profile = connections.find(current.id);
        if (profile && (profile.group ?? "") !== current.group) {
          await connections.save({ ...unwrap(profile), group: current.group || null });
        }
      }
      const groups = sectionKeys();
      const ids = groups.flatMap(key => (sectionMap().get(key) ?? []).map(profile => profile.id));
      const saving = connections.reorder(ids, groups);
      setPreview(null);
      await saving;
    } catch (error) {
      setPreview(null);
      pushError(error);
    }
  }

  return (
    <PanelFrame
      title="Databases"
      icon={Database}
      count={hasConnections() ? connections.connections.length : null}
      controls={props.controls}
      actions={
        <>
          <Show when={hasConnections()}>
            <Button icon size="sm" active={editing()} tooltip={editing() ? "Done editing groups" : "Edit groups"} onClick={() => setEditing(!editing())}>
              <Show when={editing()} fallback={<Pencil size={14} />}><Check size={14} /></Show>
            </Button>
          </Show>
          <Button icon size="sm" tooltip="New connection" onClick={() => props.onEditConnection(null)}>
            <Plus size={14} />
          </Button>
        </>
      }
    >
      <Switch>
        <Match when={!connections.loaded()}>
          <div class={shared.Center}><Spinner size={18} /></div>
        </Match>
        <Match when={connections.loadError()}>
          <div class={shared.Center}>
            <EmptyState
              tone="danger"
              icon={CircleAlert}
              title="Connections couldn't be loaded"
              description={errorMessage(connections.loadError())}
              actions={<Button variant="subtle" onClick={connections.load}>Try again</Button>}
            />
          </div>
        </Match>
        <Match when={!hasConnections()}>
          <div class={shared.Center}>
            <EmptyState
              title="No connections yet"
              description="Passwords you save are kept in an encrypted vault on this machine."
              actions={
                <Button variant="primary" onClick={() => props.onEditConnection(null)}>
                  <Plus size={14} />
                  New connection
                </Button>
              }
            />
          </div>
        </Match>
        <Match when={filtered().length === 0}>
          <div class={shared.Center}>
            <EmptyState title="Nothing matches" description={`No connection matches "${props.search.trim()}".`} />
          </div>
        </Match>
        <Match when={true}>
          <div ref={sectionList}>
            <For each={sectionKeys()}>
              {key => {
                const profiles = createMemo(() => sectionMap().get(key) ?? []);
                let header!: HTMLElement;
                return (
                  <section class={styles.Section} data-id={key}>
                    <Show when={key !== "" || sectionKeys().length > 1}>
                      <header ref={header} class={styles.SectionHeader}>
                        <Show when={editing()}>
                          <span class={styles.Grip} onPointerDown={event => grabGroup(event, key, header)}>
                            <GripVertical size={14} />
                          </span>
                        </Show>
                        <Show
                          when={renaming() === key}
                          fallback={
                            <h3
                              class={styles.SectionTitle}
                              classList={{ [styles.Renamable]: editing() && key !== "" }}
                              onClick={() => {
                                if (editing() && key !== "") setRenaming(key);
                              }}
                            >
                              {key || "Ungrouped"}
                            </h3>
                          }
                        >
                          <input
                            class={styles.RenameInput}
                            value={key}
                            size={Math.max(8, key.length + 2)}
                            ref={input => queueMicrotask(() => {
                              input.focus();
                              input.select();
                            })}
                            onKeyDown={event => {
                              if (event.key === "Enter") commitRename(key, event.currentTarget.value);
                              if (event.key === "Escape") setRenaming(null);
                            }}
                            onBlur={event => {
                              if (renaming() === key) commitRename(key, event.currentTarget.value);
                            }}
                          />
                        </Show>
                        <Show when={editing() && key !== "" && profiles().length === 0}>
                          <Button
                            icon
                            size="sm"
                            class={styles.RemoveGroup}
                            tooltip="Remove group"
                            onClick={() => saveGroups(sectionKeys().filter(other => other !== key))}
                          >
                            <X size={14} />
                          </Button>
                        </Show>
                      </header>
                    </Show>
                    <div class={styles.Grid} classList={{ [styles.Empty]: profiles().length === 0 }}>
                      <Show when={profiles().length === 0}>
                        <span>Drop connections here</span>
                      </Show>
                      <For each={profiles()}>
                        {profile => {
                          const onGrab = createMemo(() => (editing() ? (event: PointerEvent) => grabCard(event, profile.id) : undefined));
                          return (
                            <div data-id={profile.id}>
                              <ConnectionCard profile={profile} onEdit={() => props.onEditConnection(profile)} onGrab={onGrab()} />
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
            <div class={styles.AddGroup}>
              <Input
                class={styles.GroupInput}
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

export default DatabasesPanel;
