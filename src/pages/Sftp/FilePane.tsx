import styles from "./Sftp.module.scss";
import { For, JSX, Match, Show, Switch, createMemo, createSignal } from "solid-js";
import { Dynamic } from "solid-js/web";
import {
  ArrowDownToLine, ArrowUpFromLine, ChevronDown, ChevronRight, ChevronUp, CircleAlert, Copy, CornerLeftUp, Eye, File, FileQuestion,
  FileSymlink, Folder, FolderOpen, FolderPlus, FolderSymlink, HardDrive, Lock, LucideIcon, Pencil, RefreshCw, Trash2,
} from "lucide-solid";
import useSftpState, { Side, isFolder } from "@core/states/sftpState";
import useContextMenuState, { MenuItem } from "@core/states/contextMenuState";
import { formatBytes, plural } from "@core/helpers";
import { FileEntry } from "@core/types";
import Button from "@core/components/Button/Button";
import Input from "@core/components/Input/Input";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Spinner from "@core/components/Spinner/Spinner";
import { Sort, SortKey, formatModified, modeString, sortEntries } from "./format";

export type DropTarget = { side: Side, folder: string | null };

export type DragState = { from: Side, entries: FileEntry[], x: number, y: number, over: DropTarget | null };

export type FilePaneProps = {
  tabId: string,
  side: Side,
  title: string,
  subtitle: string,
  icon: LucideIcon,
  drag: DragState | null,
  onGrab: (event: PointerEvent, entry: FileEntry, order: string[]) => void,
  // While the server side isn't connected, `blockedView` is shown instead of the list.
  blocked?: boolean,
  blockedView?: JSX.Element,
};

function entryIcon(entry: FileEntry): LucideIcon {
  switch (entry.kind) {
    case "dir": return Folder;
    case "symlink": return entry.linkDir ? FolderSymlink : FileSymlink;
    case "file": return File;
    default: return FileQuestion;
  }
}

function FilePane(props: FilePaneProps) {
  const sftp = useSftpState;
  const { openContextMenu, openMenuAt } = useContextMenuState;
  let list!: HTMLDivElement;

  const [sort, setSort] = createSignal<Sort>({ key: "name", descending: false });
  const tab = createMemo(() => sftp.tab(props.tabId));
  const showRoots = createMemo(() => props.side === "local" && sftp.roots().length > 1);

  function sortBy(key: SortKey) {
    setSort(current => (current.key === key ? { key, descending: !current.descending } : { key, descending: key !== "name" }));
  }

  function openRoots(event: MouseEvent) {
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    openMenuAt({ x: rect.left, y: rect.bottom + 4 }, sftp.roots().map(root => ({
      label: root.label,
      icon: HardDrive,
      onSelect: () => void sftp.load(props.tabId, props.side, root.path),
    })));
  }
  const pane = createMemo(() => tab()?.[props.side]);
  const listing = createMemo(() => pane()?.listing ?? null);
  const remote = createMemo(() => props.side === "remote");
  const selected = createMemo(() => new Set(pane()?.selected ?? []));

  const visible = createMemo(() => {
    const current = listing();
    if (!current) return [];
    const needle = (pane()?.filter ?? "").trim().toLowerCase();
    const showHidden = tab()?.showHidden ?? false;
    const shown = current.entries.filter(entry => (showHidden || !entry.hidden) && (needle === "" || entry.name.toLowerCase().includes(needle)));
    return sortEntries(shown, sort());
  });
  const order = createMemo(() => visible().map(entry => entry.path));
  const hiddenCount = createMemo(() => (tab()?.showHidden ? 0 : listing()?.entries.filter(entry => entry.hidden).length ?? 0));
  const showMode = createMemo(() => listing()?.entries.some(entry => entry.mode !== null) ?? false);
  const selection = createMemo(() => sftp.selectedEntries(props.tabId, props.side));
  const sendLabel = createMemo(() => (remote() ? "Download" : "Upload"));
  const sendIcon = createMemo(() => (remote() ? ArrowDownToLine : ArrowUpFromLine));
  const emptyTitle = createMemo(() => ((pane()?.filter ?? "").trim() !== "" ? "Nothing matches" : "This folder is empty"));
  const emptyDescription = createMemo(() => (hiddenCount() > 0 ? `${plural(hiddenCount(), "hidden item")}. Turn on Hidden files to see them.` : undefined));
  const blocked = createMemo(() => props.blocked ?? false);
  const dropHere = createMemo(() => props.drag !== null && props.drag.from !== props.side && props.drag.over?.side === props.side);
  const dropFolder = createMemo(() => (dropHere() ? props.drag?.over?.folder ?? null : null));
  const dragged = createMemo(() => new Set(props.drag?.from === props.side ? props.drag.entries.map(entry => entry.path) : []));

  const footer = createMemo(() => {
    const parts = [plural(visible().length, "item")];
    if (selection().length > 0) parts.push(`${selection().length} selected`);
    if (hiddenCount() > 0) parts.push(`${hiddenCount()} hidden`);
    return parts.join(" · ");
  });

  function send(entries: FileEntry[]) {
    sftp.transfer(props.tabId, props.side, entries);
  }

  function onRowMouseDown(event: MouseEvent, entry: FileEntry) {
    // Row presses start a drag, so they shouldn't start a text selection.
    event.preventDefault();
    list.focus();
    if (event.button !== 0) return;
    if (event.shiftKey) sftp.select(props.tabId, props.side, entry.path, "range", order());
    else if (event.ctrlKey || event.metaKey) sftp.select(props.tabId, props.side, entry.path, "toggle", order());
    else if (!selected().has(entry.path)) sftp.select(props.tabId, props.side, entry.path, "single", order());
  }

  function onRowClick(event: MouseEvent, entry: FileEntry) {
    if (event.shiftKey || event.ctrlKey || event.metaKey) return;
    sftp.select(props.tabId, props.side, entry.path, "single", order());
  }

  function rowMenu(event: MouseEvent, entry: FileEntry) {
    if (!selected().has(entry.path)) sftp.select(props.tabId, props.side, entry.path, "single", order());
    const entries = sftp.selectedEntries(props.tabId, props.side);
    const single = entries.length === 1 ? entries[0] : null;
    const items: MenuItem[] = [];
    if (single && isFolder(single)) items.push({ label: "Open", icon: FolderOpen, onSelect: () => sftp.openEntry(props.tabId, props.side, single) });
    if (single && remote() && !isFolder(single)) items.push({ label: "Preview", icon: Eye, onSelect: () => void sftp.preview(props.tabId, single) });
    items.push({ label: sendLabel(), icon: remote() ? ArrowDownToLine : ArrowUpFromLine, onSelect: () => send(entries) });
    items.push({ separator: true });
    if (single) {
      items.push({ label: "Rename", icon: Pencil, hint: "F2", onSelect: () => void sftp.rename(props.tabId, props.side, single) });
      if (remote() && single.mode !== null) items.push({ label: "Permissions", icon: Lock, onSelect: () => sftp.editPermissions(props.tabId, single) });
      items.push({ label: "Copy path", icon: Copy, onSelect: () => sftp.copyPath(single) });
    }
    items.push({ label: entries.length > 1 ? `Delete ${entries.length} items` : "Delete", icon: Trash2, danger: true, hint: "Del", onSelect: () => void sftp.remove(props.tabId, props.side, entries) });
    items.push({ separator: true });
    items.push({ label: "New folder", icon: FolderPlus, onSelect: () => void sftp.newFolder(props.tabId, props.side) });
    openContextMenu(event, items);
  }

  function backgroundMenu(event: MouseEvent) {
    if (!listing()) return;
    sftp.select(props.tabId, props.side, null, "single", order());
    openContextMenu(event, [
      { label: "New folder", icon: FolderPlus, onSelect: () => void sftp.newFolder(props.tabId, props.side) },
      { label: "Refresh", icon: RefreshCw, onSelect: () => sftp.refresh(props.tabId, props.side) },
    ]);
  }

  function onKeyDown(event: KeyboardEvent) {
    const entries = selection();
    const mod = event.ctrlKey || event.metaKey;
    if (mod && event.key.toLowerCase() === "a") {
      event.preventDefault();
      sftp.selectAll(props.tabId, props.side, order());
    } else if (event.key === "Delete" && entries.length > 0) {
      event.preventDefault();
      void sftp.remove(props.tabId, props.side, entries);
    } else if (event.key === "F2" && entries.length === 1) {
      event.preventDefault();
      void sftp.rename(props.tabId, props.side, entries[0]);
    } else if (event.key === "Enter" && entries.length === 1) {
      event.preventDefault();
      sftp.openEntry(props.tabId, props.side, entries[0]);
    } else if (event.key === "Backspace") {
      event.preventDefault();
      sftp.up(props.tabId, props.side);
    } else if (event.key === "Escape" && entries.length > 0) {
      event.preventDefault();
      sftp.select(props.tabId, props.side, null, "single", order());
    }
  }

  function PathBar() {
    return (
      <div class={styles.PathBar}>
        <Show when={showRoots()}>
          <Button icon size="sm" tooltip="Drives" onClick={openRoots}>
            <HardDrive size={14} />
          </Button>
        </Show>
        <Button icon size="sm" tooltip="Up one folder" disabled={!listing()?.parent} onClick={() => sftp.up(props.tabId, props.side)}>
          <CornerLeftUp size={14} />
        </Button>
        <Show
          when={!pane()?.editingPath}
          fallback={
            <PathInput
              initial={listing()?.path ?? ""}
              onSubmit={path => void sftp.load(props.tabId, props.side, path)}
              onCancel={() => sftp.setEditingPath(props.tabId, props.side, false)}
            />
          }
        >
          <div class={styles.Crumbs} onClick={event => {
            if (event.target === event.currentTarget) sftp.setEditingPath(props.tabId, props.side, true);
          }}>
            <For each={listing()?.crumbs ?? []}>
              {(crumb, index) => (
                <>
                  <Show when={index() > 0 && crumb.label !== "/"}>
                    <ChevronRight size={12} class={styles.CrumbSep} />
                  </Show>
                  <button type="button" class={styles.Crumb} onClick={() => void sftp.load(props.tabId, props.side, crumb.path)}>
                    {crumb.label}
                  </button>
                </>
              )}
            </For>
          </div>
          <Button icon size="sm" tooltip="Type a path" onClick={() => sftp.setEditingPath(props.tabId, props.side, true)}>
            <Pencil size={12} />
          </Button>
        </Show>
      </div>
    );
  }

  return (
    <section class={styles.Pane} classList={{ [styles.DropActive]: dropHere() && dropFolder() === null }}>
      <header class={styles.PaneHeader}>
        <span class={styles.PaneIcon}><Dynamic component={props.icon} size={15} /></span>
        <span class={styles.PaneTitles}>
          <span class={styles.PaneTitle}>{props.title}</span>
          <span class={styles.PaneSub}>{props.subtitle}</span>
        </span>
        <div class={styles.PaneActions}>
          <Button size="sm" variant="subtle" disabled={selection().length === 0 || blocked()} onClick={() => send(selection())}>
            <Dynamic component={sendIcon()} size={13} />
            {sendLabel()}
          </Button>
          <Button icon size="sm" tooltip="New folder" disabled={!listing() || blocked()} onClick={() => void sftp.newFolder(props.tabId, props.side)}>
            <FolderPlus size={14} />
          </Button>
          <Button icon size="sm" tooltip="Refresh" disabled={blocked()} onClick={() => sftp.refresh(props.tabId, props.side)}>
            <RefreshCw size={13} />
          </Button>
        </div>
      </header>

      <Show when={!blocked()} fallback={<div class={styles.Center}>{props.blockedView}</div>}>
        <PathBar />
        <div class={styles.FilterRow}>
          <Input
            type="search"
            value={pane()?.filter ?? ""}
            onValue={value => sftp.setFilter(props.tabId, props.side, value)}
            placeholder="Filter this folder"
            clearable
            class={styles.Filter}
          />
        </div>

        <div class={styles.ListHead} classList={{ [styles.NoMode]: !showMode() }}>
          <SortHeader label="Name" sortKey="name" sort={sort()} onSort={sortBy} />
          <SortHeader label="Size" sortKey="size" sort={sort()} onSort={sortBy} end />
          <SortHeader label="Modified" sortKey="modified" sort={sort()} onSort={sortBy} />
          <Show when={showMode()}><span>Permissions</span></Show>
        </div>
        <div
          ref={list}
          class={styles.List}
          tabIndex={0}
          data-drop-side={props.side}
          onKeyDown={onKeyDown}
          onContextMenu={backgroundMenu}
          onMouseDown={event => {
            if (event.target === event.currentTarget && event.button === 0) sftp.select(props.tabId, props.side, null, "single", order());
          }}
        >
          <Switch>
            <Match when={pane()?.status === "error" && !listing()}>
              <div class={styles.Center}>
                <EmptyState
                  tone="danger"
                  icon={CircleAlert}
                  title="This folder couldn't be opened"
                  description={pane()?.error}
                  actions={<Button variant="subtle" onClick={() => void sftp.load(props.tabId, props.side, null)}>Go to home folder</Button>}
                />
              </div>
            </Match>
            <Match when={!listing()}>
              <div class={styles.Center}><Spinner size={18} /></div>
            </Match>
            <Match when={true}>
              <Show when={pane()?.status === "error"}>
                <div class={styles.ListError}>
                  <CircleAlert size={13} />
                  <span>{pane()?.error}</span>
                </div>
              </Show>
              <Show
                when={visible().length > 0}
                fallback={
                  <div class={styles.Center} data-drop-side={props.side}>
                    <EmptyState icon={Folder} title={emptyTitle()} description={emptyDescription()} />
                  </div>
                }
              >
                <For each={visible()}>
                  {entry => {
                    const folder = isFolder(entry);
                    const isSelected = createMemo(() => selected().has(entry.path));
                    const isDropTarget = createMemo(() => dropFolder() === entry.path);
                    return (
                      <div
                        class={styles.Row}
                        classList={{
                          [styles.NoMode]: !showMode(),
                          [styles.Selected]: isSelected(),
                          [styles.DropOn]: isDropTarget(),
                          [styles.Dragged]: dragged().has(entry.path),
                          [styles.HiddenEntry]: entry.hidden,
                        }}
                        data-drop-side={props.side}
                        data-drop-folder={folder ? entry.path : undefined}
                        onMouseDown={event => onRowMouseDown(event, entry)}
                        onPointerDown={event => {
                          if (event.button === 0 && !event.shiftKey && !event.ctrlKey && !event.metaKey) props.onGrab(event, entry, order());
                        }}
                        onClick={event => onRowClick(event, entry)}
                        onDblClick={() => sftp.openEntry(props.tabId, props.side, entry)}
                        onContextMenu={event => rowMenu(event, entry)}
                      >
                        <span class={styles.Name}>
                          <span class={styles.EntryIcon} classList={{ [styles.FolderIcon]: folder }}>
                            <Dynamic component={entryIcon(entry)} size={14} />
                          </span>
                          <span class={styles.NameText}>{entry.name}</span>
                        </span>
                        <span class={`${styles.Num} ${styles.Faint}`}>{entry.size !== null ? formatBytes(entry.size) : ""}</span>
                        <span class={styles.Faint}>{formatModified(entry.modified)}</span>
                        <Show when={showMode()}>
                          <span class={styles.Mode}>{modeString(entry)}</span>
                        </Show>
                      </div>
                    );
                  }}
                </For>
              </Show>
            </Match>
          </Switch>
        </div>
        <footer class={styles.PaneFooter}>
          <span>{footer()}</span>
          <Show when={pane()?.status === "loading" && listing()}>
            <Spinner size={11} />
          </Show>
        </footer>
      </Show>
    </section>
  );
}

function SortHeader(props: { label: string, sortKey: SortKey, sort: Sort, onSort: (key: SortKey) => void, end?: boolean }) {
  const active = createMemo(() => props.sort.key === props.sortKey);
  return (
    <button
      type="button"
      class={styles.SortHead}
      classList={{ [styles.SortActive]: active(), [styles.SortEnd]: props.end ?? false }}
      onClick={() => props.onSort(props.sortKey)}
    >
      {props.label}
      <Show when={active()}>
        <Show when={props.sort.descending} fallback={<ChevronUp size={11} />}>
          <ChevronDown size={11} />
        </Show>
      </Show>
    </button>
  );
}

function PathInput(props:{ initial: string, onSubmit: (path: string) => void, onCancel: () => void }) {
  let value = props.initial;
  return (
    <Input
      value={props.initial}
      mono
      autofocus
      class={styles.PathInput}
      onValue={next => { value = next; }}
      onBlur={() => props.onCancel()}
      onKeyDown={event => {
        if (event.key === "Enter") {
          event.preventDefault();
          props.onSubmit(value.trim());
        } else if (event.key === "Escape") {
          event.preventDefault();
          props.onCancel();
        }
      }}
    />
  );
}

export default FilePane;
