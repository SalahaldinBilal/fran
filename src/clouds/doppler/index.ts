import { KeyRound } from "@core/icons";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { Cloud, DopplerConfig } from "@core/types";
import type { CloudModule } from "../index";
import AddForm from "./AddForm";
import Account from "./Account";

const MAX_NAME = 200;

export function dopplerConfig(cloud: Cloud): DopplerConfig {
  return cloud.config as DopplerConfig;
}

// Doppler's default naming: uppercase letters, digits and underscores, not starting with a digit.
export function dopplerName(secretName: string): string {
  const cleaned = secretName.trim().toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  return (/^[0-9]/.test(cleaned) ? `_${cleaned}` : cleaned).slice(0, MAX_NAME);
}

const doppler: CloudModule = {
  kind: "doppler",
  label: "Doppler config",
  description: "Secrets only. They're normal Doppler secrets, readable in Doppler, so a password rotated there reaches Fran.",
  icon: KeyRound,
  accepts: () => false,
  secretStore: {
    names: cloud => safeInvoke("doppler_names", { cloudId: cloud.id }),
    suggestName: dopplerName,
    notice: "Secrets kept in Doppler aren't end-to-end encrypted. Doppler can read them, and so can anyone with access to that config.",
    deleteLinked: (cloud, name) => safeInvoke("doppler_delete_secret", { cloudId: cloud.id, name }),
  },
  detail: cloud => {
    const config = dopplerConfig(cloud);
    return `${config.project} / ${config.config}`;
  },
  AddForm,
  Account,
  accountLabel: "Token and config",
  removeNote: "The token is removed from this computer. Secrets linked to this config keep their last value here, and nothing changes in Doppler.",
  remove: cloud => safeInvoke("sync_remove_cloud", { cloudId: cloud.id }),
};

export default doppler;
