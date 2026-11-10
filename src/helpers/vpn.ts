import { VpnProfile, VpnStatus } from "@core/types";
import { plural } from "@core/helpers";

export function vpnRunning(status: VpnStatus | undefined): boolean {
  return status !== undefined && status.phase !== "down";
}

// What the badge on a VPN says. Null while it's off.
export function vpnStateLabel(status: VpnStatus | undefined): string | null {
  switch (status?.phase) {
    case "connecting":
      return status.system ? "Turning on" : "Connecting";
    case "reconnecting":
      return "Reconnecting";
    case "up":
      if (status.system) return "On for this computer";
      return status.users > 0 ? `Own tunnel, ${plural(status.users, "user")}` : "Own tunnel, closing soon";
    default:
      return null;
  }
}

// What a connect through the VPN is waiting on. Null once the VPN is up.
export function vpnWaitLabel(profile: VpnProfile | undefined, status: VpnStatus | undefined): string | null {
  if (!profile || status?.phase === "up") return null;
  if (status?.phase === "reconnecting") return `VPN ${profile.label} is reconnecting`;
  return status?.system ? `Turning on VPN ${profile.label}` : `Connecting to VPN ${profile.label}`;
}

// Which program runs a VPN that's on for the computer, for detail lines. Null otherwise.
export function vpnBackendLabel(status: VpnStatus | undefined): string | null {
  if (!status?.system || status.phase === "down" || !status.with) return null;
  return status.with === "fran" ? "with Fran" : "with OpenVPN";
}

// For the route preview and the terminal status bar.
export function vpnModeLabel(status: VpnStatus | undefined): string {
  if (!status?.system || status.phase === "down") return "own tunnel";
  const backend = vpnBackendLabel(status);
  return backend ? `this computer ${backend}` : "this computer";
}

export function vpnServer(profile: VpnProfile): string {
  const first = profile.remotes[0];
  if (!first) return "No server";
  const more = profile.remotes.length > 1 ? ` and ${plural(profile.remotes.length - 1, "more")}` : "";
  return `${first.host}:${first.port} ${first.proto.toUpperCase()}${more}`;
}
