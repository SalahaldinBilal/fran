import { SshOptions } from "@core/types";
import useSshState from "@core/states/sshState";
import { VpnLeg } from "../types";

// For drivers whose only VPN-capable methods are TCP and the SSH tunnel.
export function tcpOrSshLeg(method: string, ssh: SshOptions): VpnLeg | null {
  if (method === "tcp") return { kind: "direct" };
  if (method !== "sshTunnel") return null;
  return ssh.hostId === null ? { kind: "ssh" } : { kind: "savedHost", hostId: ssh.hostId };
}

// The saved host's name, or user@host for a tunnel set up only for this connection.
export function sshVia(ssh: SshOptions): string {
  if (ssh.hostId === null) return `${ssh.user}@${ssh.host}`;
  if (!ssh.hostId) return "(no SSH host picked)";
  const host = useSshState.host(ssh.hostId);
  if (host) return host.label;
  return useSshState.loaded() ? "a deleted SSH host" : "a saved SSH host";
}

export function sshName(ssh: SshOptions): string {
  if (ssh.hostId === null) return ssh.host.trim();
  return ssh.hostId ? useSshState.host(ssh.hostId)?.label ?? "" : "";
}
