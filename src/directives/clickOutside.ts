import { onCleanup } from "solid-js";

export function clickOutside(onOutsideClick: () => void) {
  let element: HTMLElement | undefined;

  function onPointerDown(event: MouseEvent) {
    if (element && event.target instanceof Node && !element.contains(event.target)) onOutsideClick();
  }

  document.addEventListener("mousedown", onPointerDown, { capture: true });
  onCleanup(() => document.removeEventListener("mousedown", onPointerDown, { capture: true }));

  return (next: HTMLElement) => {
    element = next;
  };
}
