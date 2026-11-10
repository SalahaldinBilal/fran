import styles from "./TileLayout.module.scss";
import { For, Index, JSX, Show, createMemo, createSignal, onCleanup, onMount } from "solid-js";
import { keepOrder } from "@core/helpers";
import {
  DropTarget, Edge, MAX_RATIO, MIN_RATIO, PlacedSplit, Rect, TileNode, dock, dropRect, layout, minSize, prune, removePanel, setRatio,
} from "@core/helpers/tiling";

export type TileControls = {
  grab: (event: PointerEvent) => void,
  remove: () => void,
};

export type TileLayoutProps = {
  tree: TileNode | null,
  label: (panel: string) => string,
  renderPanel: (panel: string, controls: TileControls) => JSX.Element,
  onChange: (tree: TileNode | null) => void,
  visible?: (panel: string) => boolean,
  empty?: JSX.Element,
};

type Drag = { panel: string, x: number, y: number, target: DropTarget | null };

const GAP = 8;
const EDGE_PX = 28;
const MIN_PANEL_PX = 180;
const DRAG_THRESHOLD = 5;

const DROP_LABELS: Record<Edge | "center", string> = {
  left: "Dock left",
  right: "Dock right",
  top: "Dock top",
  bottom: "Dock bottom",
  center: "Swap",
};

const ROOT_LABELS: Record<Edge, string> = {
  left: "Full height, left",
  right: "Full height, right",
  top: "Full width, top",
  bottom: "Full width, bottom",
};

function boxStyle(rect: Rect): JSX.CSSProperties {
  const half = GAP / 2;
  const left = rect.x > 0.0001 ? half : 0;
  const right = rect.x + rect.w < 0.9999 ? half : 0;
  const top = rect.y > 0.0001 ? half : 0;
  const bottom = rect.y + rect.h < 0.9999 ? half : 0;
  return {
    left: `calc(${rect.x * 100}% + ${left}px)`,
    top: `calc(${rect.y * 100}% + ${top}px)`,
    width: `calc(${rect.w * 100}% - ${left + right}px)`,
    height: `calc(${rect.h * 100}% - ${top + bottom}px)`,
  };
}

function splitterStyle(split: PlacedSplit): JSX.CSSProperties {
  const { rect, ratio } = split;
  if (split.dir === "row") {
    return { left: `calc(${(rect.x + rect.w * ratio) * 100}% - ${GAP / 2}px)`, top: `${rect.y * 100}%`, width: `${GAP}px`, height: `${rect.h * 100}%` };
  }
  return { top: `calc(${(rect.y + rect.h * ratio) * 100}% - ${GAP / 2}px)`, left: `${rect.x * 100}%`, height: `${GAP}px`, width: `${rect.w * 100}%` };
}

function swallowClick(event: Event) {
  event.stopPropagation();
  event.preventDefault();
}

function TileLayout(props: TileLayoutProps) {
  let container!: HTMLDivElement;
  const [liveRatio, setLiveRatio] = createSignal<{ id: string, ratio: number } | null>(null);
  const [drag, setDrag] = createSignal<Drag | null>(null);
  const [size, setSize] = createSignal<{ width: number, height: number } | null>(null);

  const shown = createMemo(() => prune(props.tree, panel => props.visible?.(panel) ?? true));
  const placed = createMemo(() => {
    const tree = shown();
    const live = liveRatio();
    const measured = size();
    const fit = measured ? { ...measured, minPanel: MIN_PANEL_PX, gap: GAP } : null;
    return layout(tree && live ? setRatio(tree, live.id, live.ratio) : tree, fit);
  });
  const minimum = createMemo<JSX.CSSProperties>(() => ({
    "min-width": `${minSize(shown(), "row", MIN_PANEL_PX, GAP)}px`,
    "min-height": `${minSize(shown(), "col", MIN_PANEL_PX, GAP)}px`,
  }));

  onMount(() => {
    const observer = new ResizeObserver(() => setSize({ width: container.clientWidth, height: container.clientHeight }));
    observer.observe(container);
    onCleanup(() => observer.disconnect());
  });
  const rects = createMemo(() => new Map(placed().panels.map(item => [item.panel, item.rect])));
  // Panels keep their DOM order when they move, since moving a node resets its scroll.
  const panels = createMemo<string[]>(previous => keepOrder(previous, placed().panels.map(item => item.panel)), []);
  const resizing = createMemo(() => liveRatio() !== null);
  const dropBox = createMemo(() => {
    const target = drag()?.target;
    return target ? dropRect(target, placed().panels) : null;
  });
  const dropLabel = createMemo(() => {
    const target = drag()?.target;
    if (!target) return "";
    return target.root ? ROOT_LABELS[target.edge] : DROP_LABELS[target.zone];
  });

  function setBodyDragging(cursor: string | null) {
    document.body.style.cursor = cursor ?? "";
    document.body.style.userSelect = cursor ? "none" : "";
  }

  function hitTest(x: number, y: number, source: string): DropTarget | null {
    const box = container.getBoundingClientRect();
    if (x < box.left || x > box.right || y < box.top || y > box.bottom) return null;
    if (x - box.left < EDGE_PX) return { root: true, edge: "left" };
    if (box.right - x < EDGE_PX) return { root: true, edge: "right" };
    if (y - box.top < EDGE_PX) return { root: true, edge: "top" };
    if (box.bottom - y < EDGE_PX) return { root: true, edge: "bottom" };

    const fx = (x - box.left) / box.width;
    const fy = (y - box.top) / box.height;
    const hit = placed().panels.find(item =>
      item.panel !== source && fx >= item.rect.x && fx <= item.rect.x + item.rect.w && fy >= item.rect.y && fy <= item.rect.y + item.rect.h);
    if (!hit) return null;

    const rx = (fx - hit.rect.x) / hit.rect.w;
    const ry = (fy - hit.rect.y) / hit.rect.h;
    const zone = rx < 0.25 ? "left" : rx > 0.75 ? "right" : ry < 0.3 ? "top" : ry > 0.7 ? "bottom" : "center";
    return { root: false, panel: hit.panel, zone };
  }

  function startDrag(event: PointerEvent, panel: string) {
    if (event.button !== 0 || placed().panels.length < 2) return;
    event.preventDefault();
    const pointerId = event.pointerId;
    const start = { x: event.clientX, y: event.clientY };
    let active = false;

    function move(moveEvent: PointerEvent) {
      if (moveEvent.pointerId !== pointerId) return;
      if (!active) {
        if (Math.hypot(moveEvent.clientX - start.x, moveEvent.clientY - start.y) < DRAG_THRESHOLD) return;
        active = true;
        setBodyDragging("grabbing");
      }
      setDrag({ panel, x: moveEvent.clientX, y: moveEvent.clientY, target: hitTest(moveEvent.clientX, moveEvent.clientY, panel) });
    }

    function end(endEvent: PointerEvent) {
      if (endEvent.pointerId !== pointerId) return;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", end);
      window.removeEventListener("pointercancel", end);
      if (!active) return;

      setBodyDragging(null);
      const target = drag()?.target;
      setDrag(null);
      if (target && props.tree && endEvent.type === "pointerup") props.onChange(dock(props.tree, panel, target));
      window.addEventListener("click", swallowClick, true);
      setTimeout(() => window.removeEventListener("click", swallowClick, true));
    }

    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", end);
    window.addEventListener("pointercancel", end);
  }

  function startResize(event: PointerEvent, split: PlacedSplit) {
    if (event.button !== 0) return;
    event.preventDefault();
    const box = container.getBoundingClientRect();
    const row = split.dir === "row";
    const origin = row ? box.left + split.rect.x * box.width : box.top + split.rect.y * box.height;
    const length = row ? split.rect.w * box.width : split.rect.h * box.height;
    const low = Math.max(MIN_RATIO, (split.minA + GAP / 2) / length);
    const high = Math.min(MAX_RATIO, 1 - (split.minB + GAP / 2) / length);
    if (low > high) return;

    setBodyDragging(row ? "col-resize" : "row-resize");
    setLiveRatio({ id: split.id, ratio: split.ratio });

    function move(moveEvent: PointerEvent) {
      const at = row ? moveEvent.clientX : moveEvent.clientY;
      setLiveRatio({ id: split.id, ratio: Math.min(high, Math.max(low, (at - origin) / length)) });
    }

    function end() {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", end);
      window.removeEventListener("pointercancel", end);
      setBodyDragging(null);
      const live = liveRatio();
      setLiveRatio(null);
      if (live && props.tree && live.ratio !== split.ratio) props.onChange(setRatio(props.tree, live.id, live.ratio));
    }

    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", end);
    window.addEventListener("pointercancel", end);
  }

  return (
    <div ref={container} class={styles.Layout} classList={{ [styles.Resizing]: resizing() || drag() !== null }} style={minimum()}>
      <Show when={panels().length > 0} fallback={props.empty}>
        <For each={panels()}>
          {panel => {
            const rect = createMemo(() => rects().get(panel));
            const dragged = createMemo(() => drag()?.panel === panel);
            return (
              <Show when={rect()}>
                {current => (
                  <div class={styles.Tile} classList={{ [styles.Dragged]: dragged() }} style={boxStyle(current())}>
                    {props.renderPanel(panel, {
                      grab: event => startDrag(event, panel),
                      remove: () => props.onChange(removePanel(props.tree, panel)),
                    })}
                  </div>
                )}
              </Show>
            );
          }}
        </For>
        <Index each={placed().splits}>
          {split => (
            <div
              class={styles.Splitter}
              classList={{ [styles.Column]: split().dir === "col", [styles.Active]: liveRatio()?.id === split().id }}
              style={splitterStyle(split())}
              onPointerDown={event => startResize(event, split())}
            />
          )}
        </Index>
      </Show>
      <Show when={dropBox()}>
        {box => (
          <div class={styles.Drop} style={boxStyle(box())}>
            <span>{dropLabel()}</span>
          </div>
        )}
      </Show>
      <Show when={drag()}>
        {current => (
          <div class={styles.Ghost} style={{ left: `${current().x}px`, top: `${current().y}px` }}>
            {props.label(current().panel)}
          </div>
        )}
      </Show>
    </div>
  );
}

export default TileLayout;
