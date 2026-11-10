import { createRoot, createSignal } from "solid-js";
import { SshHost } from "@core/types";

type HostEditorRequest = {
  host: SshHost | null,
  onSaved?: (host: SshHost) => void,
};

function useHostEditorStateInner() {
  const [request, setRequest] = createSignal<HostEditorRequest | null>(null);

  function open(host: SshHost | null, onSaved?: (host: SshHost) => void) {
    setRequest({ host, onSaved });
  }

  function close() {
    setRequest(null);
  }

  return { request, open, close };
}

const useHostEditorState = createRoot(useHostEditorStateInner);
export default useHostEditorState;
