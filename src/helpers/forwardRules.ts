import { ForwardKind, ForwardRule } from "@core/types";

export const FORWARD_KIND_LABELS: Record<ForwardKind, string> = {
  local: "Local",
  remote: "Remote",
  dynamic: "Dynamic (SOCKS)",
};

export function listenAddress(rule: ForwardRule): string {
  return `${rule.allNetworks ? "0.0.0.0" : "127.0.0.1"}:${rule.listenPort}`;
}

export function describeForward(rule: ForwardRule): string {
  switch (rule.kind) {
    case "local":
      return `${listenAddress(rule)} → ${rule.targetHost}:${rule.targetPort}`;
    case "remote":
      return `server ${rule.remoteBind}:${rule.listenPort} → ${rule.targetHost}:${rule.targetPort}`;
    case "dynamic":
      return `SOCKS5 on ${listenAddress(rule)}`;
  }
}
