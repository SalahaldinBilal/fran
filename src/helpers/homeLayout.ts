import { TileNode, leaf, split } from "./tiling";

export const HOME_PANELS = ["databases", "hosts", "recent", "forwards", "snippets", "vpn"] as const;

export type HomePanelId = typeof HOME_PANELS[number];

export function isHomePanel(panel: string): panel is HomePanelId {
  return (HOME_PANELS as readonly string[]).includes(panel);
}

// What you open on the left, what you opened lately on the right, VPNs under it. Port forwards and snippets are in the Panels menu.
// The VPN panel is hidden while the VPN client is off, so Recent then takes the whole column.
export function defaultHomeLayout(): TileNode {
  return split("row", split("col", leaf("databases"), leaf("hosts"), 0.58), split("col", leaf("recent"), leaf("vpn"), 0.5), 0.72);
}

function shape(node: TileNode): string {
  return node.type === "panel" ? node.panel : `${node.dir}(${shape(node.a)},${shape(node.b)})`;
}

// Earlier defaults as read today, with the Open now panel already dropped and ratios ignored.
// A layout still shaped like one of them was never arranged by hand.
const OLD_DEFAULTS = [
  "row(col(databases,col(hosts,recent)),col(forwards,snippets))",
  "row(col(databases,hosts),recent)",
];

export function isOldDefaultLayout(node: TileNode): boolean {
  return OLD_DEFAULTS.includes(shape(node));
}
