import { StoreSetter, flush } from "solid-js";

// Solid 2 applies writes on a microtask, and the state modules read their own writes on the next line.
export function immediateWrite<T>(set: StoreSetter<T>): StoreSetter<T> {
  return change => flush(() => set(change));
}

export function fieldSetter<T extends object>(set: StoreSetter<T>) {
  return <K extends keyof T>(key: K, value: T[K]) => set(state => {
    state[key] = value;
  });
}
