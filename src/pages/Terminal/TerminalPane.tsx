import "@xterm/xterm/css/xterm.css";
import styles from "./Terminal.module.scss";
import { Show, createEffect, createMemo, createSignal, on, onCleanup, onMount } from "solid-js";
import { ArrowDown, ArrowUp, ClipboardPaste, Copy, Eraser, GripVertical, Search, SquareTerminal, TextSelect, TriangleAlert, X } from "lucide-solid";
import { ITheme, Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { WebglAddon } from "@xterm/addon-webgl";
import useTerminalState from "@core/states/terminalState";
import useSettingsState from "@core/states/settingsState";
import useSshState from "@core/states/sshState";
import usePromptState from "@core/states/promptState";
import useContextMenuState from "@core/states/contextMenuState";
import useToastState from "@core/states/toastState";
import useVpnState from "@core/states/vpnState";
import { vpnWaitLabel } from "@core/helpers/vpn";
import Spinner from "@core/components/Spinner/Spinner";
import { copyText, pasteText } from "@core/helpers/clipboard";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { IS_MAC } from "@core/helpers/platform";
import { plural } from "@core/helpers";
import { TileControls } from "@core/components/Tiling/TileLayout";
import Button from "@core/components/Button/Button";

export type TerminalPaneProps = {
  tabId: string,
  paneId: string,
  title: string,
  controls: TileControls,
  closable: boolean,
  visible: boolean,
  // The only pane in the tab: it fills the area with no frame or header, since the tab already names the host.
  solo: boolean,
};

const MAX_CLIPBOARD_WRITE = 1024 * 1024;
const RESIZE_DELAY_MS = 60;

function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function readTheme(): ITheme {
  return {
    background: token("--term-bg"),
    foreground: token("--term-fg"),
    cursor: token("--term-cursor"),
    cursorAccent: token("--term-bg"),
    selectionBackground: token("--term-selection"),
    black: token("--term-black"),
    red: token("--term-red"),
    green: token("--term-green"),
    yellow: token("--term-yellow"),
    blue: token("--term-blue"),
    magenta: token("--term-magenta"),
    cyan: token("--term-cyan"),
    white: token("--term-white"),
    brightBlack: token("--term-bright-black"),
    brightRed: token("--term-bright-red"),
    brightGreen: token("--term-bright-green"),
    brightYellow: token("--term-bright-yellow"),
    brightBlue: token("--term-bright-blue"),
    brightMagenta: token("--term-bright-magenta"),
    brightCyan: token("--term-bright-cyan"),
    brightWhite: token("--term-bright-white"),
  };
}

function fontFamily(choice: string): string {
  const mono = token("--font-mono");
  return choice ? `"${choice}", ${mono}` : mono;
}

// A crafted clipboard could end bracketed paste early and have the rest run as typed input.
export function stripPasteMarkers(text: string): string {
  return text.replace(/(?:\x1b\[|\x9b)20[01]~/g, "");
}

function decodeBase64(payload: string): string | null {
  try {
    const binary = atob(payload);
    if (binary.length > MAX_CLIPBOARD_WRITE) return null;
    return new TextDecoder().decode(Uint8Array.from(binary, character => character.charCodeAt(0)));
  } catch {
    return null;
  }
}

function TerminalPane(props: TerminalPaneProps) {
  const terminals = useTerminalState;
  const ssh = useSshState;
  const { settings } = useSettingsState;
  const { openContextMenu } = useContextMenuState;
  let host!: HTMLDivElement;
  let searchInput: HTMLInputElement | undefined;

  const [searching, setSearching] = createSignal(false);
  const [query, setQuery] = createSignal("");

  const tab = createMemo(() => terminals.tab(props.tabId));
  const pane = createMemo(() => tab()?.panes[props.paneId]);
  const focused = createMemo(() => tab()?.focus === props.paneId);
  const pendingPaste = createMemo(() => pane()?.pendingPaste ?? null);
  const pasteLines = createMemo(() => (pendingPaste() ?? "").split(/\r\n|\r|\n/).filter(line => line.length > 0));
  const pastePreview = createMemo(() => pasteLines().slice(0, 3).join("\n"));
  const pasteTitle = createMemo(() => `Paste ${plural(pasteLines().length, "line")}? Each line runs as soon as it lands.`);
  const connecting = createMemo(() => pane()?.status === "connecting");
  const hostLabel = createMemo(() => ssh.host(tab()?.hostId ?? "")?.label ?? "the server");
  const vpnWait = createMemo(() => {
    const profile = useVpnState.profile(ssh.routeVpnId(tab()?.hostId ?? ""));
    return vpnWaitLabel(profile, profile ? useVpnState.status(profile.id) : undefined);
  });

  const term = new Terminal({
    allowProposedApi: false,
    cursorBlink: true,
    cursorStyle: settings.terminal.cursorStyle,
    cursorInactiveStyle: "outline",
    drawBoldTextInBrightColors: false,
    fontSize: settings.terminal.fontSize,
    scrollback: settings.terminal.scrollback,
    theme: readTheme(),
    // Every report that would echo window titles or other server-set text back as input stays off.
    windowOptions: {},
    linkHandler: { activate: (_event, text) => void openLink(text) },
  });
  const fit = new FitAddon();
  const search = new SearchAddon();
  term.loadAddon(fit);
  term.loadAddon(search);
  term.loadAddon(new WebLinksAddon((_event, uri) => void openLink(uri)));

  async function openLink(url: string) {
    if (!/^https?:\/\//i.test(url)) return;
    const confirmed = await usePromptState.confirm({
      title: "Open this link?",
      message: `${url} came from the server. Check it before opening it in your browser.`,
      confirmLabel: "Open link",
    });
    if (!confirmed) return;
    try {
      await safeInvoke("open_link", { url });
    } catch (error) {
      useToastState.pushError(error);
    }
  }

  function handlePaste(text: string) {
    const cleaned = stripPasteMarkers(text);
    if (!cleaned) return;
    if (/[\r\n]/.test(cleaned)) terminals.askPaste(props.tabId, props.paneId, cleaned);
    else term.paste(cleaned);
  }

  async function pasteFromClipboard() {
    const text = await pasteText();
    if (text) handlePaste(text);
  }

  function copySelection() {
    if (term.hasSelection()) void copyText(term.getSelection());
  }

  function openSearch() {
    setSearching(true);
    queueMicrotask(() => {
      searchInput?.focus();
      searchInput?.select();
    });
  }

  function closeSearch() {
    setSearching(false);
    search.clearDecorations();
    term.focus();
  }

  function find(forward: boolean) {
    const text = query();
    if (!text) return;
    if (forward) search.findNext(text);
    else search.findPrevious(text);
  }

  function isCopy(event: KeyboardEvent): boolean {
    return IS_MAC ? event.metaKey && event.key === "c" : event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "c";
  }

  function isPaste(event: KeyboardEvent): boolean {
    return !IS_MAC && event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "v";
  }

  function isFind(event: KeyboardEvent): boolean {
    return IS_MAC ? event.metaKey && event.key === "f" : event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "f";
  }

  term.attachCustomKeyEventHandler(event => {
    if (event.type !== "keydown") return true;
    if (isCopy(event)) {
      if (!term.hasSelection()) return !IS_MAC;
      event.preventDefault();
      copySelection();
      return false;
    }
    if (isPaste(event)) {
      event.preventDefault();
      void pasteFromClipboard();
      return false;
    }
    if (isFind(event)) {
      event.preventDefault();
      openSearch();
      return false;
    }
    return true;
  });

  term.parser.registerOscHandler(52, data => {
    // Answering a read ("?") would hand the clipboard to the server, so reads are dropped always.
    const allowed = ssh.host(tab()?.hostId ?? "")?.clipboardWrite ?? false;
    const separator = data.indexOf(";");
    const payload = separator < 0 ? "" : data.slice(separator + 1);
    if (!allowed || payload === "" || payload === "?") return true;
    const text = decodeBase64(payload);
    if (text !== null) void copyText(text);
    return true;
  });

  term.onData(data => terminals.send(props.tabId, props.paneId, data));
  term.onBinary(data => terminals.send(props.tabId, props.paneId, Uint8Array.from(data, character => character.charCodeAt(0) & 0xff)));
  term.onResize(size => terminals.resize(props.tabId, props.paneId, size.cols, size.rows));
  term.onSelectionChange(() => {
    if (settings.terminal.copyOnSelect && term.hasSelection()) void copyText(term.getSelection());
  });

  function measure(): { cols: number, rows: number } | null {
    if (!host || host.clientWidth === 0 || host.clientHeight === 0) return null;
    const size = fit.proposeDimensions();
    return size && Number.isFinite(size.cols) && Number.isFinite(size.rows) ? { cols: size.cols, rows: size.rows } : null;
  }

  let resizeTimer: ReturnType<typeof setTimeout> | undefined;
  function refit() {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (measure()) fit.fit();
    }, RESIZE_DELAY_MS);
  }

  onMount(() => {
    term.open(host);
    try {
      const webgl = new WebglAddon();
      webgl.onContextLoss(() => webgl.dispose());
      term.loadAddon(webgl);
    } catch {
      // Falls back to the DOM renderer when WebGL isn't available.
    }
    term.options.fontFamily = fontFamily(settings.terminal.fontFamily);
    if (measure()) fit.fit();

    // Paste events reach xterm's hidden textarea, so they're caught on the way down.
    function onPaste(event: ClipboardEvent) {
      event.preventDefault();
      event.stopPropagation();
      handlePaste(event.clipboardData?.getData("text/plain") ?? "");
    }
    host.addEventListener("paste", onPaste, true);
    host.addEventListener("focusin", () => terminals.focus(props.tabId, props.paneId));

    const observer = new ResizeObserver(refit);
    observer.observe(host);

    terminals.attach(props.paneId, {
      write: data => term.write(data),
      size: () => measure(),
      paste: text => term.paste(stripPasteMarkers(text)),
      focus: () => term.focus(),
    });
    void terminals.connect(props.tabId, props.paneId);
    if (focused()) term.focus();

    onCleanup(() => {
      clearTimeout(resizeTimer);
      observer.disconnect();
      host.removeEventListener("paste", onPaste, true);
      terminals.detach(props.paneId);
      term.dispose();
    });
  });

  createEffect(on(() => ({ ...settings.terminal }), current => {
    term.options.fontFamily = fontFamily(current.fontFamily);
    term.options.fontSize = current.fontSize;
    term.options.cursorStyle = current.cursorStyle;
    term.options.scrollback = current.scrollback;
    refit();
  }, { defer: true }));

  createEffect(on(() => props.visible, visible => {
    if (!visible) return;
    refit();
    if (focused()) requestAnimationFrame(() => term.focus());
  }, { defer: true }));

  createEffect(on(focused, isFocused => {
    if (isFocused && props.visible) term.focus();
  }, { defer: true }));

  function onContextMenu(event: MouseEvent) {
    openContextMenu(event, [
      { label: "Copy", icon: Copy, hint: IS_MAC ? "⌘C" : "Ctrl+Shift+C", disabled: !term.hasSelection(), onSelect: copySelection },
      { label: "Paste", icon: ClipboardPaste, hint: IS_MAC ? "⌘V" : "Ctrl+Shift+V", onSelect: () => void pasteFromClipboard() },
      { label: "Select all", icon: TextSelect, onSelect: () => term.selectAll() },
      { separator: true },
      { label: "Find", icon: Search, hint: IS_MAC ? "⌘F" : "Ctrl+Shift+F", onSelect: openSearch },
      { label: "Clear scrollback", icon: Eraser, onSelect: () => term.clear() },
    ]);
  }

  return (
    <section class={styles.Pane} classList={{ [styles.Focused]: focused() && !props.solo, [styles.Solo]: props.solo }}>
      <Show when={!props.solo}>
        <header
          class={styles.PaneHeader}
          onPointerDown={event => {
            if ((event.target as Element).closest("button, input")) return;
            terminals.focus(props.tabId, props.paneId);
            props.controls.grab(event);
          }}
        >
          <GripVertical size={13} class={styles.Grip} />
          <SquareTerminal size={13} class={styles.PaneIcon} />
          <span class={styles.PaneTitle}>{props.title}</span>
          <div class={styles.PaneActions}>
            <Button icon size="sm" tooltip="Find" onClick={openSearch}>
              <Search size={13} />
            </Button>
            <Show when={props.closable}>
              <Button icon size="sm" tooltip="Close pane" onClick={() => terminals.closePane(props.tabId, props.paneId)}>
                <X size={13} />
              </Button>
            </Show>
          </div>
        </header>
      </Show>

      <Show when={pendingPaste() !== null}>
        <div class={styles.PasteBar}>
          <TriangleAlert size={14} class={styles.PasteIcon} />
          <div class={styles.PasteText}>
            <div>{pasteTitle()}</div>
            <pre>{pastePreview()}</pre>
          </div>
          <Button size="sm" variant="ghost" onClick={() => terminals.answerPaste(props.tabId, props.paneId, false)}>Cancel</Button>
          <Button size="sm" variant="subtle" onClick={() => terminals.answerPaste(props.tabId, props.paneId, true)}>Paste</Button>
        </div>
      </Show>

      <Show when={searching()}>
        <div class={styles.SearchBar}>
          <Search size={13} class={styles.SearchIcon} />
          <input
            ref={element => { searchInput = element; }}
            class={styles.SearchInput}
            value={query()}
            placeholder="Find in scrollback"
            spellcheck={false}
            onInput={event => {
              setQuery(event.currentTarget.value);
              if (event.currentTarget.value) search.findNext(event.currentTarget.value, { incremental: true });
              else search.clearDecorations();
            }}
            onKeyDown={event => {
              if (event.key === "Enter") find(!event.shiftKey);
              if (event.key === "Escape") closeSearch();
            }}
          />
          <Button icon size="sm" tooltip="Previous" onClick={() => find(false)}><ArrowUp size={13} /></Button>
          <Button icon size="sm" tooltip="Next" onClick={() => find(true)}><ArrowDown size={13} /></Button>
          <Button icon size="sm" tooltip="Close" onClick={closeSearch}><X size={13} /></Button>
        </div>
      </Show>

      <div class={styles.Screen} ref={host} onContextMenu={onContextMenu} />

      <Show when={connecting()}>
        <div class={styles.Connecting}>
          <Spinner size={16} />
          <div class={styles.ConnectingText}>
            <span>Connecting to {hostLabel()}</span>
            <Show when={vpnWait()}>{label => <em>{label()}</em>}</Show>
          </div>
        </div>
      </Show>
    </section>
  );
}

export default TerminalPane;
