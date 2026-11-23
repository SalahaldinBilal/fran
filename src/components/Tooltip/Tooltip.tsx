import { Accessor, createEffect, createMemo, onCleanup } from "solid-js";
import useTooltipState, { TooltipAnchor, TooltipOptions, TooltipValue } from "@core/states/tooltipState";

function toOptions(value: TooltipValue): TooltipOptions | null {
  if (value === null || value === undefined || value === "") return null;
  return typeof value === "string" ? { content: value } : value;
}

export function tooltip(value: Accessor<TooltipValue>) {
  const { isShowing, showTooltip, hideTooltip, cancelPendingTooltip } = useTooltipState;
  const options = createMemo(() => toOptions(value()));
  let anchor: TooltipAnchor | undefined;
  let hovered = false;
  const isActive = () => anchor !== undefined && isShowing(anchor.element);
  const hidden = createMemo(() => {
    const current = options();
    return current === null || current.blocked === true;
  });

  function onEnter() {
    hovered = true;
    if (anchor && !isActive() && !hidden()) showTooltip(anchor);
  }

  function onLeave() {
    hovered = false;
    if (isActive()) hideTooltip();
    else cancelPendingTooltip();
  }

  createEffect(hidden, isHidden => {
    if (isHidden && isActive()) hideTooltip();
    else if (!isHidden && hovered && anchor && !isActive()) showTooltip(anchor);
  }, { defer: true });

  onCleanup(() => {
    if (!anchor) return;
    anchor.element.removeEventListener("pointerenter", onEnter);
    anchor.element.removeEventListener("pointerleave", onLeave);
    anchor.element.removeEventListener("pointerdown", hideTooltip);
    if (isActive()) hideTooltip();
    else if (hovered) cancelPendingTooltip();
  });

  return (element: HTMLElement) => {
    anchor = { element, options };
    element.addEventListener("pointerenter", onEnter);
    element.addEventListener("pointerleave", onLeave);
    element.addEventListener("pointerdown", hideTooltip);
  };
}
