import { safeInvoke } from "./safeInvoke";
import { isAppError } from "./errors";
import usePromptState from "@core/states/promptState";
import useSshState from "@core/states/sshState";
import useSecretsState from "@core/states/secretsState";
import { SecretSlot } from "@core/types";

export type ConnectTarget = {
  connectionId: string | null,
  connectionName: string,
};

async function saveSecret(target: ConnectTarget, slot: SecretSlot, value: string) {
  if (slot.store) {
    await safeInvoke("set_owner_secret", { owner: slot.store.owner, slot: slot.store.slot, value });
    // The Secrets view shows whether each secret has a value.
    if (slot.store.owner.kind === "secret") void useSecretsState.load().catch(() => undefined);
  } else if (target.connectionId) {
    await safeInvoke("set_connection_secret", { connectionId: target.connectionId, slot: slot.id, value });
  }
}

// Retries while the backend asks for credentials or a host key decision. Null means the user cancelled.
export async function withConnectPrompts<T>(
  target: ConnectTarget,
  attempt: (secrets: Record<string, string>) => Promise<T>,
  initialSecrets: Record<string, string> = {},
): Promise<T | null> {
  const { askForSecrets, askToTrustHostKey, askToReplaceHostKey } = usePromptState;
  const secrets = { ...initialSecrets };
  let refreshed = false;

  for (;;) {
    try {
      return await attempt(secrets);
    } catch (error) {
      if (!isAppError(error)) throw error;
      const detail = error.detail;

      if (detail.kind === "secretsRequired") {
        // Secrets of a saved SSH host, key or proxy can be saved even before the connection itself is.
        const savable = detail.slots.filter(slot => !slot.oneTime);
        const canSave = savable.some(slot => slot.store) || (target.connectionId !== null && savable.length > 0);
        const answer = await askForSecrets(target.connectionName, detail.slots, canSave);
        if (!answer) return null;

        Object.assign(secrets, answer.values);
        if (answer.save) {
          for (const slot of savable) {
            const value = answer.values[slot.id];
            if (value) await saveSecret(target, slot, value);
          }
        }
        continue;
      }

      if (detail.kind === "unknownHostKey") {
        if (!await askToTrustHostKey(detail)) return null;
        await safeInvoke("trust_host_key", { key: detail.key });
        void useSshState.loadKnownHosts().catch(() => undefined);
        continue;
      }

      if (detail.kind === "hostKeyChanged") {
        const typedHost = await askToReplaceHostKey(detail);
        if (typedHost === null) return null;
        await safeInvoke("replace_host_key", { key: detail.key, typedHost });
        void useSshState.loadKnownHosts().catch(() => undefined);
        continue;
      }

      // A password rotated in a cloud that holds linked secrets: fetch them once and try again if one changed.
      if (!refreshed && error.linkedSecret) {
        refreshed = true;
        if (await safeInvoke("sync_refresh_linked").catch(() => false)) continue;
      }

      throw error;
    }
  }
}
