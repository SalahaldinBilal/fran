import { platform } from "@tauri-apps/plugin-os";

export const IS_MAC = platform() === "macos";
export const IS_WINDOWS = platform() === "windows";

// Ctrl+click (Cmd+click on macOS, where Ctrl+click is a right click) skips the confirm of actions that don't delete data.
export function skipsConfirm(event: MouseEvent | null | undefined): boolean {
  if (!event) return false;
  return IS_MAC ? event.metaKey : event.ctrlKey;
}
