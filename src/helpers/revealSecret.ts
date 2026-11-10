import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import { RevealOptions, SecretOwner } from "@core/types";
import { safeInvoke } from "./safeInvoke";
import { isAppError } from "./errors";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";

export const SHOW_FOR_MS = 30_000;

// Runs an action that needs the OS to confirm the user, answering what the backend asks for along the way.
// Null means the user cancelled.
export async function withUserCheck<T>(run: (options: RevealOptions) => Promise<T>): Promise<T | null> {
  const prompts = usePromptState;
  const options: RevealOptions = { lockPassword: null, passwordDialog: false };
  for (;;) {
    try {
      return await run({ ...options });
    } catch (error) {
      if (!isAppError(error)) throw error;
      const detail = error.detail;
      if (detail.kind === "osAuthCancelled") return null;

      if (detail.kind === "lockPasswordRequired") {
        const answer = await prompts.askForSecrets(
          "Your system can't confirm it's you, so Fran uses the app lock password instead",
          [{ id: "lock", label: "App lock password" }],
          false,
          { title: "Confirm it's you", submitLabel: "Confirm" },
        );
        if (!answer?.values.lock) return null;
        options.lockPassword = answer.values.lock;
        continue;
      }

      if (detail.kind === "osAuthSetup") {
        const install = detail.canInstall && await prompts.confirm({
          title: "Register Fran with your system?",
          message: "Once this is done, your desktop asks for your own password before Fran shows a saved one. "
            + "Registering asks for an admin password one time. Without it, Fran asks for your password in its own dialog.",
          confirmLabel: "Register",
        });
        if (install) {
          try {
            await safeInvoke("install_os_auth");
            continue;
          } catch (installError) {
            if (isAppError(installError) && installError.detail.kind === "osAuthCancelled") return null;
            useToastState.pushError(installError);
          }
        }
        options.passwordDialog = true;
        continue;
      }

      throw error;
    }
  }
}

export function revealSecret(owner: SecretOwner, slot: string): Promise<string | null> {
  return withUserCheck(options => safeInvoke("reveal_secret", { owner, slot, options }));
}

export async function copySecret(owner: SecretOwner, slot: string, label: string) {
  try {
    const copied = await withUserCheck(options => safeInvoke("copy_secret", { owner, slot, options }));
    if (copied !== null) useToastState.pushToast(`Copied ${label}. The clipboard is cleared in 30 seconds.`, "info", 3000);
  } catch (error) {
    useToastState.pushError(error);
  }
}

// For a value already on screen. Cleared later the same way the backend clears its own copies.
export async function copyShownSecret(value: string, label: string) {
  try {
    await writeText(value);
    useToastState.pushToast(`Copied ${label}. The clipboard is cleared in 30 seconds.`, "info", 3000);
    setTimeout(() => {
      void readText().then(current => {
        if (current === value) void writeText("");
      }).catch(() => undefined);
    }, SHOW_FOR_MS);
  } catch (error) {
    useToastState.pushError(error);
  }
}
