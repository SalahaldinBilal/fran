import { Accessor, createRoot, createSignal } from "solid-js";
import { JSX } from "@solidjs/web";

export type TooltipSide = "top" | "bottom" | "left" | "right";

export type TooltipOptions = {
  content: JSX.Element,
  side?: TooltipSide,
  blocked?: boolean,
};

// A plain string is shorthand for `{ content }`. Empty values show nothing.
export type TooltipValue = TooltipOptions | string | null | undefined;

export type TooltipAnchor = {
  element: HTMLElement,
  options: Accessor<TooltipOptions | null>,
};

const SHOW_DELAY = 400;
const WARM_WINDOW = 300;

function useTooltipStateInner() {
  const [active, setActive] = createSignal<TooltipAnchor | null>(null);
  // Plain, since the show and hide calls run from effects and need the latest value before a flush.
  let current: TooltipAnchor | null = null;
  let showTimer: ReturnType<typeof setTimeout> | undefined;
  let lastHiddenAt = 0;

  function setCurrent(next: TooltipAnchor | null) {
    current = next;
    setActive(next);
  }

  function isShowing(element: HTMLElement): boolean {
    return current?.element === element;
  }

  // The first tooltip waits a moment. Moving to a neighbour while one is open, or just was, shows it right away.
  function showTooltip(anchor: TooltipAnchor) {
    clearTimeout(showTimer);
    const warm = current !== null || performance.now() - lastHiddenAt < WARM_WINDOW;
    if (warm) {
      setCurrent(anchor);
      return;
    }
    showTimer = setTimeout(() => {
      if (anchor.element.isConnected) setCurrent(anchor);
    }, SHOW_DELAY);
  }

  function hideTooltip() {
    clearTimeout(showTimer);
    if (current) lastHiddenAt = performance.now();
    setCurrent(null);
  }

  function cancelPendingTooltip() {
    clearTimeout(showTimer);
  }

  return { active, isShowing, showTooltip, hideTooltip, cancelPendingTooltip };
}

const useTooltipState = createRoot(useTooltipStateInner);
export default useTooltipState;
