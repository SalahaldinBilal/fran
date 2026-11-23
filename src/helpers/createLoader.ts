import { Accessor, createEffect, createMemo, createSignal, untrack } from "solid-js";

export type LoaderState = "pending" | "refreshing" | "ready" | "errored";

export type Loader<T> = Accessor<T | undefined> & {
  readonly loading: boolean,
  readonly error: unknown,
  readonly latest: T | undefined,
  readonly state: LoaderState,
};

export type LoaderActions<T> = {
  refetch: () => Promise<void>,
  mutate: (next: T | ((previous: T | undefined) => T)) => void,
};

type Source<S> = Accessor<S | null | undefined | false>;

// Solid 2's async memos suspend to a Loading boundary. This keeps the page on screen and reports progress instead.
export function createLoader<T>(fetcher: () => Promise<T>): [Loader<T>, LoaderActions<T>];
export function createLoader<S, T>(source: Source<S>, fetcher: (input: S) => Promise<T>): [Loader<T>, LoaderActions<T>];
export function createLoader<S, T>(
  first: Source<S> | (() => Promise<T>),
  second?: (input: S) => Promise<T>,
): [Loader<T>, LoaderActions<T>] {
  const source = (second ? first : () => true) as Source<S>;
  const fetcher = (second ?? first) as (input: S) => Promise<T>;
  const [value, setValue] = createSignal<T | undefined>(undefined, { ownedWrite: true });
  const [loading, setLoading] = createSignal(isInput(untrack(source)), { ownedWrite: true });
  const [error, setError] = createSignal<unknown>(undefined, { ownedWrite: true });
  let request = 0;

  function isInput(input: S | null | undefined | false): input is S {
    return input !== null && input !== undefined && input !== false;
  }

  async function run(input: S) {
    const id = ++request;
    setLoading(true);
    setError(undefined);
    try {
      // Fetchers read props for their arguments, which an effect callback can't do.
      await null;
      if (id !== request) return;
      const result = await fetcher(input);
      if (id === request) setValue(() => result);
    } catch (failure) {
      if (id === request) setError(() => failure);
    } finally {
      if (id === request) setLoading(false);
    }
  }

  createEffect(source, input => {
    if (isInput(input)) {
      void run(input);
      return;
    }
    request++;
    setLoading(false);
  });

  const state = createMemo<LoaderState>(() => {
    if (error() !== undefined) return "errored";
    if (loading()) return value() === undefined ? "pending" : "refreshing";
    return "ready";
  });

  const loader = (() => value()) as Loader<T>;
  Object.defineProperties(loader, {
    loading: { get: loading },
    error: { get: error },
    latest: { get: value },
    state: { get: state },
  });

  return [loader, {
    refetch: async () => {
      const input = untrack(source);
      if (isInput(input)) await run(input);
    },
    mutate: next => {
      request++;
      setLoading(false);
      setValue(previous => (typeof next === "function" ? (next as (previous: T | undefined) => T)(previous) : next));
    },
  }];
}
