import { Component } from "solid-js";
import { ArrowLeftRight, CodeXml, Database, History, LucideIcon, Server, Shield } from "lucide-solid";
import { HomePanelId } from "@core/helpers/homeLayout";
import { Feature } from "@core/helpers/features";
import DatabasesPanel from "./DatabasesPanel";
import SshHostsPanel from "./SshHostsPanel";
import RecentPanel from "./RecentPanel";
import ForwardsPanel from "./ForwardsPanel";
import SnippetsPanel from "./SnippetsPanel";
import VpnPanel from "./VpnPanel";
import { PanelProps } from "./types";

export type HomePanelInfo = {
  title: string,
  icon: LucideIcon,
  feature: Feature,
  view: Component<PanelProps>,
};

export const HOME_PANEL_INFO: Record<HomePanelId, HomePanelInfo> = {
  databases: { title: "Databases", icon: Database, feature: "database", view: DatabasesPanel },
  // Stays with the SSH client off, since database connections tunnel through saved hosts.
  hosts: { title: "SSH hosts", icon: Server, feature: "any", view: SshHostsPanel },
  recent: { title: "Recent", icon: History, feature: "any", view: RecentPanel },
  // Forwards only need saved hosts, so database users keep them too.
  forwards: { title: "Port forwards", icon: ArrowLeftRight, feature: "any", view: ForwardsPanel },
  snippets: { title: "Snippets", icon: CodeXml, feature: "ssh", view: SnippetsPanel },
  vpn: { title: "VPN", icon: Shield, feature: "vpn", view: VpnPanel },
};
