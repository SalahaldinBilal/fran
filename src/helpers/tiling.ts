import { generateId } from "@core/helpers";

export type SplitDir = "row" | "col";

export type TileNode =
  | { type: "panel", panel: string }
  | { type: "split", id: string, dir: SplitDir, ratio: number, a: TileNode, b: TileNode };

export type Edge = "left" | "right" | "top" | "bottom";

export type DropTarget =
  | { root: true, edge: Edge }
  | { root: false, panel: string, zone: Edge | "center" };

export type Rect = { x: number, y: number, w: number, h: number };

export type PlacedPanel = { panel: string, rect: Rect };
// `minA` and `minB` are the pixels each side needs along the split's direction.
export type PlacedSplit = { id: string, dir: SplitDir, ratio: number, rect: Rect, minA: number, minB: number };

export type Fit = { width: number, height: number, minPanel: number, gap: number };

export const MIN_RATIO = 0.15;
export const MAX_RATIO = 0.85;
const ROOT_SHARE = 1 / 3;

export function leaf(panel: string): TileNode {
  return { type: "panel", panel };
}

export function split(dir: SplitDir, a: TileNode, b: TileNode, ratio = 0.5): TileNode {
  return { type: "split", id: generateId(), dir, ratio, a, b };
}

export function panelsIn(node: TileNode | null): string[] {
  if (!node) return [];
  return node.type === "panel" ? [node.panel] : [...panelsIn(node.a), ...panelsIn(node.b)];
}

export function removePanel(node: TileNode | null, panel: string): TileNode | null {
  if (!node) return null;
  if (node.type === "panel") return node.panel === panel ? null : node;
  const a = removePanel(node.a, panel);
  const b = removePanel(node.b, panel);
  if (a && b) return a === node.a && b === node.b ? node : { ...node, a, b };
  return a ?? b;
}

export function prune(node: TileNode | null, keep: (panel: string) => boolean): TileNode | null {
  if (!node) return null;
  if (node.type === "panel") return keep(node.panel) ? node : null;
  const a = prune(node.a, keep);
  const b = prune(node.b, keep);
  if (a && b) return a === node.a && b === node.b ? node : { ...node, a, b };
  return a ?? b;
}

function replacePanel(node: TileNode, panel: string, replace: (found: TileNode) => TileNode): TileNode {
  if (node.type === "panel") return node.panel === panel ? replace(node) : node;
  return { ...node, a: replacePanel(node.a, panel, replace), b: replacePanel(node.b, panel, replace) };
}

export function setRatio(node: TileNode, id: string, ratio: number): TileNode {
  if (node.type === "panel") return node;
  if (node.id === id) return { ...node, ratio };
  return { ...node, a: setRatio(node.a, id, ratio), b: setRatio(node.b, id, ratio) };
}

function swapPanels(node: TileNode, first: string, second: string): TileNode {
  if (node.type === "panel") {
    if (node.panel === first) return leaf(second);
    if (node.panel === second) return leaf(first);
    return node;
  }
  return { ...node, a: swapPanels(node.a, first, second), b: swapPanels(node.b, first, second) };
}

// Puts `panel` next to `target`, splitting the space `target` had.
export function splitPanel(node: TileNode, target: string, panel: string, dir: SplitDir): TileNode {
  return replacePanel(node, target, found => split(dir, found, leaf(panel)));
}

export function addPanel(node: TileNode | null, panel: string): TileNode {
  return node ? split("row", node, leaf(panel), 0.7) : leaf(panel);
}

export function dock(tree: TileNode, panel: string, target: DropTarget): TileNode {
  if (!target.root && target.zone === "center") return swapPanels(tree, panel, target.panel);
  const rest = removePanel(tree, panel);
  if (!rest) return tree;

  const edge = target.root ? target.edge : target.zone as Edge;
  const dir: SplitDir = edge === "left" || edge === "right" ? "row" : "col";
  const first = edge === "left" || edge === "top";
  const moved = leaf(panel);

  if (target.root) {
    return first ? split(dir, moved, rest, ROOT_SHARE) : split(dir, rest, moved, 1 - ROOT_SHARE);
  }
  return replacePanel(rest, target.panel, found => (first ? split(dir, moved, found) : split(dir, found, moved)));
}

export function minSize(node: TileNode | null, dir: SplitDir, minPanel: number, gap: number): number {
  if (!node) return 0;
  if (node.type === "panel") return minPanel;
  const a = minSize(node.a, dir, minPanel, gap);
  const b = minSize(node.b, dir, minPanel, gap);
  return node.dir === dir ? a + b + gap : Math.max(a, b);
}

// The stored ratio, moved just enough that both sides keep their minimum size at this many pixels.
function fittedRatio(ratio: number, size: number, minA: number, minB: number, gap: number): number {
  const low = (minA + gap / 2) / size;
  const high = 1 - (minB + gap / 2) / size;
  if (low > high) return minA / (minA + minB);
  return Math.min(high, Math.max(low, ratio));
}

export function layout(node: TileNode | null, fit: Fit | null, rect: Rect = { x: 0, y: 0, w: 1, h: 1 }): { panels: PlacedPanel[], splits: PlacedSplit[] } {
  if (!node) return { panels: [], splits: [] };
  if (node.type === "panel") return { panels: [{ panel: node.panel, rect }], splits: [] };

  const row = node.dir === "row";
  const minA = fit ? minSize(node.a, node.dir, fit.minPanel, fit.gap) : 0;
  const minB = fit ? minSize(node.b, node.dir, fit.minPanel, fit.gap) : 0;
  const pixels = fit ? (row ? rect.w * fit.width : rect.h * fit.height) : 0;
  const ratio = fit && pixels > 0 ? fittedRatio(node.ratio, pixels, minA, minB, fit.gap) : node.ratio;

  const [first, second]: [Rect, Rect] = row
    ? [{ ...rect, w: rect.w * ratio }, { ...rect, x: rect.x + rect.w * ratio, w: rect.w * (1 - ratio) }]
    : [{ ...rect, h: rect.h * ratio }, { ...rect, y: rect.y + rect.h * ratio, h: rect.h * (1 - ratio) }];
  const a = layout(node.a, fit, first);
  const b = layout(node.b, fit, second);
  return {
    panels: [...a.panels, ...b.panels],
    splits: [{ id: node.id, dir: node.dir, ratio, rect, minA, minB }, ...a.splits, ...b.splits],
  };
}

export function dropRect(target: DropTarget, panels: PlacedPanel[]): Rect | null {
  if (target.root) {
    switch (target.edge) {
      case "left": return { x: 0, y: 0, w: ROOT_SHARE, h: 1 };
      case "right": return { x: 1 - ROOT_SHARE, y: 0, w: ROOT_SHARE, h: 1 };
      case "top": return { x: 0, y: 0, w: 1, h: ROOT_SHARE };
      case "bottom": return { x: 0, y: 1 - ROOT_SHARE, w: 1, h: ROOT_SHARE };
    }
  }
  const rect = panels.find(placed => placed.panel === target.panel)?.rect;
  if (!rect) return null;
  switch (target.zone) {
    case "left": return { ...rect, w: rect.w / 2 };
    case "right": return { ...rect, x: rect.x + rect.w / 2, w: rect.w / 2 };
    case "top": return { ...rect, h: rect.h / 2 };
    case "bottom": return { ...rect, y: rect.y + rect.h / 2, h: rect.h / 2 };
    case "center": return rect;
  }
}

// Undefined when the stored value isn't a tree at all, so the caller can fall back to its default layout.
export function readTree(value: unknown, known: (panel: string) => boolean): TileNode | null | undefined {
  if (value === null) return null;
  const seen = new Set<string>();
  let valid = true;

  function read(node: unknown): TileNode | null {
    if (typeof node !== "object" || node === null) {
      valid = false;
      return null;
    }
    const candidate = node as Record<string, unknown>;
    if (candidate.type === "panel" && typeof candidate.panel === "string") {
      if (!known(candidate.panel) || seen.has(candidate.panel)) return null;
      seen.add(candidate.panel);
      return leaf(candidate.panel);
    }
    if (candidate.type === "split" && (candidate.dir === "row" || candidate.dir === "col") && typeof candidate.ratio === "number") {
      const a = read(candidate.a);
      const b = read(candidate.b);
      const ratio = Math.min(MAX_RATIO, Math.max(MIN_RATIO, candidate.ratio));
      if (a && b) return { type: "split", id: typeof candidate.id === "string" ? candidate.id : generateId(), dir: candidate.dir, ratio, a, b };
      return a ?? b;
    }
    valid = false;
    return null;
  }

  const tree = read(value);
  return valid ? tree : undefined;
}
