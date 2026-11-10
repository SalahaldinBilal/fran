import { FileEntry } from "@core/types";
import { isFolder } from "@core/states/sftpState";

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

export function formatModified(ms: number | null): string {
  return ms === null ? "" : dateFormat.format(new Date(ms));
}

function triple(mode: number, shift: number, special: boolean, specialChar: string): string {
  const bits = (mode >> shift) & 0o7;
  const exec = bits & 0o1;
  const last = special ? (exec ? specialChar : specialChar.toUpperCase()) : exec ? "x" : "-";
  return `${bits & 0o4 ? "r" : "-"}${bits & 0o2 ? "w" : "-"}${last}`;
}

// `drwxr-xr-x` style, with setuid, setgid and sticky shown the way ls does.
export function modeString(entry: FileEntry): string {
  if (entry.mode === null) return "";
  const mode = entry.mode;
  const type = entry.kind === "dir" ? "d" : entry.kind === "symlink" ? "l" : "-";
  return type
    + triple(mode, 6, (mode & 0o4000) !== 0, "s")
    + triple(mode, 3, (mode & 0o2000) !== 0, "s")
    + triple(mode, 0, (mode & 0o1000) !== 0, "t");
}

export function octal(mode: number): string {
  return (mode & 0o7777).toString(8).padStart(3, "0");
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

export type SortKey = "name" | "size" | "modified";

export type Sort = { key: SortKey, descending: boolean };

function compareBy(key: SortKey, a: FileEntry, b: FileEntry): number {
  switch (key) {
    case "size": return (a.size ?? -1) - (b.size ?? -1);
    case "modified": return (a.modified ?? 0) - (b.modified ?? 0);
    case "name": return collator.compare(a.name, b.name);
  }
}

// Folders stay on top either way, like a file manager. Ties fall back to the name.
export function sortEntries(entries: FileEntry[], sort: Sort = { key: "name", descending: false }): FileEntry[] {
  const direction = sort.descending ? -1 : 1;
  return [...entries].sort((a, b) => Number(isFolder(b)) - Number(isFolder(a))
    || direction * compareBy(sort.key, a, b)
    || collator.compare(a.name, b.name));
}
