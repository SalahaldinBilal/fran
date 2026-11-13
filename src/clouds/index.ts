import { Component } from "solid-js";
import { LucideIcon } from "@core/icons";
import { Cloud, CloudKind, SyncCategory } from "@core/types";
import franServer from "./franServer";
import doppler from "./doppler";

// For a kind where a secret can live under a name of its own, readable there.
export type SecretStore = {
  names: (cloud: Cloud) => Promise<string[]>,
  // The name a secret would get there by default.
  suggestName: (secretName: string) => string,
  // Shown before the first secret is stored in or linked from a cloud of this kind.
  notice: string,
  // Deletes the secret in the cloud itself. Only ever called after the user asked for exactly that.
  deleteLinked: (cloud: Cloud, name: string) => Promise<void>,
};

export type AddFormProps = {
  // Set when signing back into a cloud this computer already has.
  cloud: Cloud | null,
  onDone: () => void,
  onCancel: () => void,
};

// Everything the generic sync UI needs from one kind of cloud.
export type CloudModule = {
  kind: CloudKind,
  label: string,
  description: string,
  icon: LucideIcon,
  accepts: (category: SyncCategory) => boolean,
  secretStore?: SecretStore,
  // One line saying which account or project this cloud is.
  detail: (cloud: Cloud) => string,
  AddForm: Component<AddFormProps>,
  // The cloud's own settings: devices, password, tokens.
  Account: Component<{ cloud: Cloud }>,
  // What the bar that opens `Account` says.
  accountLabel: string,
  // What "Remove" says it will do, and the call that does it.
  removeNote: string,
  remove: (cloud: Cloud) => Promise<void>,
};

const modules: Record<CloudKind, CloudModule> = { franServer, doppler };

export const cloudModules: readonly CloudModule[] = Object.values(modules);

export function withCloudModule<T>(cloud: { kind: CloudKind }, use: (module: CloudModule) => T): T {
  return use(modules[cloud.kind]);
}

export function cloudModule(kind: CloudKind): CloudModule {
  return modules[kind];
}
