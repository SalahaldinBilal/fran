import { Server } from "@core/icons";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { Cloud, FranServerConfig } from "@core/types";
import type { CloudModule } from "../index";
import AddForm from "./AddForm";
import Account from "./Account";

export function franServerConfig(cloud: Cloud): FranServerConfig {
  return cloud.config as FranServerConfig;
}

export function serverHost(url: string): string {
  return url.replace(/^https?:\/\//, "");
}

const franServer: CloudModule = {
  kind: "franServer",
  label: "Fran sync server",
  description: "Fran Cloud or a server you host. End-to-end encrypted, takes everything.",
  icon: Server,
  accepts: () => true,
  detail: cloud => {
    const config = franServerConfig(cloud);
    const plain = config.url.startsWith("http://") ? " over plain http, testing only" : "";
    return `${config.email} on ${serverHost(config.url)}${plain}`;
  },
  AddForm,
  Account,
  accountLabel: "Account, devices and security",
  removeNote: "This computer is signed out. Everything it synced stays here, and the other computers keep syncing.",
  remove: cloud => safeInvoke("fran_server_sign_out", { cloudId: cloud.id }),
};

export default franServer;
