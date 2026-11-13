import shared from "./Panels.module.scss";
import groups from "./DatabasesPanel.module.scss";
import hostStyles from "./SshHostsPanel.module.scss";
import { For, Match, Show, Switch, createMemo, createSignal } from "solid-js";
import { Check, CircleAlert, Download, GripVertical, LayoutGrid, Pencil, Plus, Rows3, Shield, Unplug, X } from "@core/icons";
import useVpnState from "@core/states/vpnState";
import useVpnEditorState from "@core/states/vpnEditorState";
import useContextMenuState from "@core/states/contextMenuState";
import useSettingsState from "@core/states/settingsState";
import useToastState from "@core/states/toastState";
import { startReorder } from "@core/helpers/dragReorder";
import { errorMessage } from "@core/helpers/errors";
import { disconnectVpn } from "@core/helpers/vpnActions";
import { VpnProfile } from "@core/types";
import Button from "@core/components/Button/Button";
import Input from "@core/components/Input/Input";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Spinner from "@core/components/Spinner/Spinner";
import { ItemIcon } from "@core/components/ItemParts/ItemParts";
import VpnCard, { VpnComputerSwitch, VpnStateBadges, useVpnView, vpnMenuItems } from "../VpnCard/VpnCard";
import PanelFrame from "./PanelFrame";
import { PanelProps } from "./types";

type Preview = { groups: string[] } | { id: string, group: string, ids: string[] };

// The compact view: one line per VPN.
function VpnRow(props: { profile: VpnProfile, onGrab?: (event: PointerEvent) => void }) {
  const editor = useVpnEditorState;
  const { openContextMenu } = useContextMenuState;
  const view = useVpnView(() => props.profile);

  return (
    <div
      class={`${shared.Row} ${hostStyles.HostRow}`}
      classList={{ [shared.Filled]: view.filled() }}
      role="button"
      tabIndex={0}
      style={{ "--row-color": props.profile.color ?? "var(--accent)" }}
      onClick={() => editor.open(props.profile)}
      onKeyDown={event => {
        if (event.key === "Enter") editor.open(props.profile);
      }}
      onContextMenu={event => openContextMenu(event, vpnMenuItems(props.profile))}
    >
      <Show when={props.onGrab}>
        {grab => (
          <span class={groups.Grip} onClick={event => event.stopPropagation()} onPointerDown={event => grab()(event)}>
            <GripVertical size={14} />
          </span>
        )}
      </Show>
      <ItemIcon><Shield size={15} /></ItemIcon>
      <span class={shared.RowText}>
        <span class={shared.RowName}>{props.profile.label}</span>
        <span class={shared.RowSub}>{view.server()}</span>
      </span>
      <span class={hostStyles.Badges}>
        <VpnStateBadges view={view} profile={props.profile} />
      </span>
      <span class={hostStyles.Tools}>
        <VpnComputerSwitch view={view} profile={props.profile} />
        <Show when={view.ownRunning()}>
          <Button
            icon
            size="sm"
            tooltip="Disconnect"
            onClick={event => {
              event.stopPropagation();
              void disconnectVpn(props.profile);
            }}
          >
            <Unplug size={13} />
          </Button>
        </Show>
        <Button
          icon
          size="sm"
          tooltip="Edit"
          onClick={event => {
            event.stopPropagation();
            editor.open(props.profile);
          }}
        >
          <Pencil size={13} />
        </Button>
      </span>
    </div>
  );
}

function VpnPanel(props: PanelProps) {
  const vpn = useVpnState;
  const editor = useVpnEditorState;
  const { pushError } = useToastState;
  const [editing, setEditing] = createSignal(false);
  const [newGroup, setNewGroup] = createSignal("");
  const [renaming, setRenaming] = createSignal<string | null>(null);
  const [preview, setPreview] = createSignal<Preview | null>(null);
  let sectionList!: HTMLDivElement;

  const filtered = createMemo(() => {
    const needle = editing() ? "" : props.search.trim().toLowerCase();
    if (!needle) return vpn.file.profiles;
    return vpn.file.profiles.filter(profile => [profile.label, profile.group ?? "", ...profile.remotes.map(remote => remote.host)]
      .some(text => text.toLowerCase().includes(needle)));
  });

  // While dragging, the preview decides where the moved VPN or group shows.
  const sectionMap = createMemo(() => {
    const current = preview();
    const moving = current && "ids" in current ? current : null;
    const byGroup = new Map<string, VpnProfile[]>();
    if (editing()) {
      for (const key of ["", ...vpn.file.groupOrder]) byGroup.set(key, []);
    }
    let dragged: VpnProfile | undefined;
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
    const order = current && "groups" in current ? current.groups : vpn.file.groupOrder;
    function rank(key: string) {
      const index = order.indexOf(key);
      return index >= 0 ? index : order.length + (key === "" ? 1 : 0);
    }
    return [...sectionMap().keys()].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
  });

  const count = createMemo(() => (vpn.file.profiles.length > 0 ? vpn.file.profiles.length : null));
  const compact = createMemo(() => useSettingsState.settings.compactVpns);
  const viewTooltip = createMemo(() => (compact() ? "Show as cards" : "Compact view"));
  const editTooltip = createMemo(() => (editing() ? "Done editing groups" : "Edit groups"));
  const listClass = createMemo(() => `${hostStyles.HostList} ${compact() ? shared.Rows : groups.Grid}`);
  const canAddGroup = createMemo(() => newGroup().trim() !== "" && !sectionMap().has(newGroup().trim()));

  async function save(ids: string[], groupOrder: string[], moved?: { id: string, group: string | null }) {
    try {
      await vpn.reorder(ids, groupOrder.filter(key => key !== ""), moved);
    } catch (error) {
      pushError(error);
    }
  }

  function currentIds(): string[] {
    return sectionKeys().flatMap(key => (sectionMap().get(key) ?? []).map(profile => profile.id));
  }

  function addGroup() {
    if (!canAddGroup()) return;
    const name = newGroup().trim();
    const keys = sectionKeys();
    const at = keys[keys.length - 1] === "" ? keys.length - 1 : keys.length;
    setNewGroup("");
    void save(vpn.file.profiles.map(profile => profile.id), [...keys.slice(0, at), name, ...keys.slice(at)]);
  }

  async function commitRename(key: string, value: string) {
    setRenaming(null);
    const name = value.trim();
    if (!name || name === key) return;
    try {
      await vpn.renameGroup(key, name);
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

  function grabProfile(event: PointerEvent, id: string) {
    startReorder(event, {
      id,
      items: () => [...sectionList.querySelectorAll<HTMLElement>(`.${hostStyles.HostList} > [data-id]`)],
      zones: () => [...sectionList.children] as HTMLElement[],
      axis: compact() ? "y" : "x",
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
    const order = sectionKeys();
    const ids = currentIds();
    let moved: { id: string, group: string | null } | undefined;
    if ("ids" in current) {
      const profile = vpn.profile(current.id);
      if (profile && (profile.group ?? "") !== current.group) moved = { id: current.id, group: current.group || null };
    }
    setPreview(null);
    await save(ids, order, moved);
  }

  return (
    <PanelFrame
      title="VPN"
      icon={Shield}
      count={count()}
      controls={props.controls}
      actions={
        <>
          <Show when={vpn.file.profiles.length > 0}>
            <Button icon size="sm" tooltip={viewTooltip()} onClick={() => void useSettingsState.update({ compactVpns: !compact() })}>
              <Show when={compact()} fallback={<Rows3 size={14} />}><LayoutGrid size={14} /></Show>
            </Button>
            <Button icon size="sm" active={editing()} tooltip={editTooltip()} onClick={() => setEditing(!editing())}>
              <Show when={editing()} fallback={<Pencil size={14} />}><Check size={14} /></Show>
            </Button>
          </Show>
          <Button icon size="sm" tooltip="Import a profile" onClick={() => void editor.importFile()}>
            <Download size={14} />
          </Button>
          <Button icon size="sm" tooltip="New VPN" onClick={() => editor.open(null)}>
            <Plus size={14} />
          </Button>
        </>
      }
    >
      <Switch>
        <Match when={!vpn.loaded()}>
          <div class={shared.Center}><Spinner size={18} /></div>
        </Match>
        <Match when={vpn.loadError()}>
          <div class={shared.Center}>
            <EmptyState
              tone="danger"
              icon={CircleAlert}
              title="VPN profiles couldn't be loaded"
              description={errorMessage(vpn.loadError())}
              actions={<Button variant="subtle" onClick={vpn.load}>Try again</Button>}
            />
          </div>
        </Match>
        <Match when={vpn.file.profiles.length === 0}>
          <div class={shared.Center}>
            <EmptyState
              icon={Shield}
              title="No VPNs yet"
              description="Import an .ovpn or WireGuard .conf file. Connections and hosts that use it open their own tunnel, without admin rights."
              actions={
                <>
                  <Button variant="subtle" onClick={() => editor.open(null)}>
                    <Plus size={14} />
                    New VPN
                  </Button>
                  <Button variant="primary" onClick={() => void editor.importFile()}>
                    <Download size={14} />
                    Import profile
                  </Button>
                </>
              }
            />
          </div>
        </Match>
        <Match when={filtered().length === 0}>
          <div class={shared.Center}>
            <EmptyState title="Nothing matches" description={`No VPN matches "${props.search.trim()}".`} />
          </div>
        </Match>
        <Match when={true}>
          <div ref={sectionList}>
            <For each={sectionKeys()}>
              {key => {
                const profiles = createMemo(() => sectionMap().get(key) ?? []);
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
                        <Show when={renamable() && profiles().length === 0}>
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
                    <div class={listClass()} classList={{ [hostStyles.EmptyGroup]: profiles().length === 0 }}>
                      <Show when={profiles().length === 0}>
                        <span>Drop VPNs here</span>
                      </Show>
                      <For each={profiles()}>
                        {profile => {
                          const onGrab = createMemo(() => (editing() ? (event: PointerEvent) => grabProfile(event, profile.id) : undefined));
                          return (
                            <div data-id={profile.id}>
                              <Show when={compact()} fallback={<VpnCard profile={profile} onGrab={onGrab()} />}>
                                <VpnRow profile={profile} onGrab={onGrab()} />
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

export default VpnPanel;
