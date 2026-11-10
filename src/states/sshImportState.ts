import { createRoot, createSignal } from "solid-js";

function useSshImportStateInner() {
  const [shown, setShown] = createSignal(false);
  return { shown, open: () => setShown(true), close: () => setShown(false) };
}

const useSshImportState = createRoot(useSshImportStateInner);
export default useSshImportState;
