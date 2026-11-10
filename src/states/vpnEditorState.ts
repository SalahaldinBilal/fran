import { createRoot, createSignal } from "solid-js";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { VpnProfile } from "@core/types";
import useVpnState from "./vpnState";
import useToastState from "./toastState";
import { withConnectPrompts } from "@core/helpers/connectFlow";

type VpnEditorRequest = {
  profile: VpnProfile | null,
  // Set right after an import, so the editor shows what the file brought.
  imported: boolean,
  onSaved?: (profile: VpnProfile) => void,
};

function useVpnEditorStateInner() {
  const [request, setRequest] = createSignal<VpnEditorRequest | null>(null);

  function open(profile: VpnProfile | null, onSaved?: (profile: VpnProfile) => void) {
    setRequest({ profile, imported: false, onSaved });
  }

  function close() {
    setRequest(null);
  }

  // The file is read and saved by the backend. Keys go to the vault and never reach this side.
  async function importFile(onSaved?: (profile: VpnProfile) => void) {
    try {
      const picked = await openDialog();
      if (!picked) return;
      // A profile that keeps its key in a PKCS#12 file asks for that file's password here.
      const name = picked.split(/[\\/]/).pop() ?? picked;
      const saved = await withConnectPrompts({ connectionId: null, connectionName: name }, secrets => useVpnState.importFile(picked, secrets));
      if (!saved) return;
      useToastState.pushToast(`Imported ${saved.label}`, "success", 2500);
      onSaved?.(saved);
      setRequest({ profile: saved, imported: true, onSaved });
    } catch (error) {
      useToastState.pushError(error);
    }
  }

  return { request, open, close, importFile };
}

async function openDialog(): Promise<string | null> {
  const picked = await openFileDialog({
    multiple: false,
    directory: false,
    title: "Import a VPN profile",
    filters: [{ name: "OpenVPN or WireGuard profile", extensions: ["ovpn", "conf"] }],
  });
  return typeof picked === "string" ? picked : null;
}

const useVpnEditorState = createRoot(useVpnEditorStateInner);
export default useVpnEditorState;
