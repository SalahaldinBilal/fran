import { createMemo, createRoot, createSignal } from "solid-js";

function useModalStateInner() {
  const [openCount, setOpenCount] = createSignal(0);
  const anyOpen = createMemo(() => openCount() > 0);
  let layers = 0;

  /** Marks a modal as open until the returned function is called. */
  function track(): () => void {
    setOpenCount(count => count + 1);
    return () => {
      setOpenCount(count => count - 1);
      if (openCount() === 0) layers = 0;
    };
  }

  // Modals are mounted once at start, so mount order can't decide which is on top. The one opened last is.
  function nextLayer(): number {
    layers += 1;
    return layers;
  }

  return { anyOpen, track, nextLayer };
}

const useModalState = createRoot(useModalStateInner);
export default useModalState;
