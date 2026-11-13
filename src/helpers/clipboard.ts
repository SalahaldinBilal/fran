import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import useToastState from "@core/states/toastState";

export async function copyText(text: string, label?: string) {
  const { pushToast, pushError } = useToastState;
  try {
    await writeText(text);
    if (label) pushToast(`Copied ${label}`, "info", 1500);
  } catch (error) {
    pushError(error);
  }
}

const CLEAR_SENSITIVE_AFTER_MS = 30_000;

// For a value the window was shown anyway, like a recovery key. Cleared after 30 seconds if nothing else was copied since, like passwords.
export async function copySensitive(text: string, label: string) {
  await copyText(text, label);
  setTimeout(() => {
    void (async () => {
      if (await pasteText() === text) await writeText("").catch(() => undefined);
    })();
  }, CLEAR_SENSITIVE_AFTER_MS);
}

export async function pasteText(): Promise<string | null> {
  try {
    return await readText();
  } catch {
    return null;
  }
}
