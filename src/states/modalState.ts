import { Accessor, createMemo, createRoot, createSignal } from "solid-js";

function useModalStateInner() {
  const [sources, setSources] = createSignal<Accessor<boolean>[]>([]);
  const anyOpen = createMemo(() => sources().some(isOpen => isOpen()));
  let shownLayers = 0;
  let layers = 0;

  /** Counts as an open modal while `isOpen` is true, until the returned function is called. */
  function track(isOpen: Accessor<boolean> = () => true): () => void {
    setSources(list => [...list, isOpen]);
    return () => setSources(list => list.filter(source => source !== isOpen));
  }

  // Modals are mounted once at start, so mount order can't decide which is on top. The one opened last is.
  function nextLayer(): { layer: number, release: () => void } {
    layers += 1;
    shownLayers += 1;
    return {
      layer: layers,
      release() {
        shownLayers -= 1;
        if (shownLayers === 0) layers = 0;
      },
    };
  }

  return { anyOpen, track, nextLayer };
}

const useModalState = createRoot(useModalStateInner);
export default useModalState;
