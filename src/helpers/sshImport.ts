import { createMemo, createSignal } from "solid-js";
import { ImportOutcome, ImportPreview } from "@core/types";
import { safeInvoke } from "./safeInvoke";
import { plural } from ".";
import useSshState from "@core/states/sshState";
import useToastState from "@core/states/toastState";

// Preview, picks and the import run, shared by the import dialog and the welcome screen.
export function createSshImport() {
  const [preview, setPreview] = createSignal<ImportPreview | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);
  const [picked, setPicked] = createSignal<Set<string>>(new Set());

  const importable = createMemo(() => preview()?.candidates.filter(candidate => candidate.skipReason === null) ?? []);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const next = await safeInvoke("preview_ssh_config_import");
      setPreview(next);
      setPicked(new Set(next.candidates.filter(candidate => candidate.skipReason === null).map(candidate => candidate.alias)));
    } catch (failure) {
      setError(failure);
    } finally {
      setLoading(false);
    }
  }

  function toggle(alias: string) {
    const next = new Set(picked());
    if (next.has(alias)) next.delete(alias);
    else next.add(alias);
    setPicked(next);
  }

  async function run(): Promise<ImportOutcome | null> {
    const aliases = [...picked()];
    if (aliases.length === 0) return null;
    const outcome = await safeInvoke("import_ssh_config", { aliases });
    await useSshState.load();
    const { pushToast } = useToastState;
    if (outcome.skipped.length > 0) {
      pushToast(`Imported ${plural(outcome.imported.length, "host")}. Not imported: ${outcome.skipped.join("; ")}`, "info", 8000);
    } else {
      pushToast(`Imported ${plural(outcome.imported.length, "host")}`, "success", 3000);
    }
    return outcome;
  }

  return { preview, loading, error, picked, importable, load, toggle, run };
}
