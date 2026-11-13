import styles from "./Secrets.module.scss";
import { For, Show, createMemo } from "solid-js";
import { save } from "@tauri-apps/plugin-dialog";
import { Download, FileKey, Shield } from "@core/icons";
import useSavedSecretsState from "@core/states/savedSecretsState";
import useVpnState from "@core/states/vpnState";
import useToastState from "@core/states/toastState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { withUserCheck } from "@core/helpers/revealSecret";
import { VpnProfile } from "@core/types";
import Button from "@core/components/Button/Button";
import EmptyState from "@core/components/EmptyState/EmptyState";

const COLUMNS = "minmax(180px, 1.4fr) minmax(200px, 2fr) 120px";

function fileExtension(profile: VpnProfile): string {
  return profile.kind === "wireGuard" ? "conf" : "ovpn";
}

async function exportProfile(profile: VpnProfile) {
  const { pushToast, pushError } = useToastState;
  const extension = fileExtension(profile);
  try {
    const path = await save({
      title: `Export ${profile.label}`,
      defaultPath: `${profile.label.replace(/[^\w.-]+/g, "_")}.${extension}`,
      filters: [{ name: profile.kind === "wireGuard" ? "WireGuard config" : "OpenVPN profile", extensions: [extension] }],
    });
    if (!path) return;
    const exported = await withUserCheck(options => safeInvoke("export_vpn_profile", { id: profile.id, path, options }));
    if (exported !== null) pushToast(`Saved ${profile.label} to ${path}`, "success", 4000);
  } catch (error) {
    pushError(error);
  }
}

function VpnKeysView() {
  const saved = useSavedSecretsState;
  const vpn = useVpnState;
  // Every profile that has a key in the vault, plus profiles whose keys are gone but still listed.
  const rows = createMemo(() => {
    const keys = saved.secrets.filter(secret => secret.group === "vpn" && !secret.revealable);
    const ids = [...new Set(keys.map(secret => secret.owner?.id ?? ""))];
    return ids.map(id => ({ id, profile: vpn.profile(id), keys: keys.filter(secret => secret.owner?.id === id) }));
  });

  return (
    <>
      <div class={styles.Head}>
        <h2>VPN keys</h2>
      </div>
      <p class={styles.Description}>
        Keys of VPN profiles. To use a profile on another computer, export it as an .ovpn or WireGuard .conf with its keys inside.
        Fran asks your system to confirm it's you first. Keep that file private, the key in it isn't protected.
      </p>
      <div class={styles.List} style={{ "--columns": COLUMNS }}>
        <div class={styles.ListHead}><span>VPN</span><span>Keys in the vault</span><span /></div>
        <Show
          when={rows().length > 0}
          fallback={<div class={styles.Empty}><EmptyState icon={Shield} title="No VPN keys" description="Keys from imported or new VPN profiles show up here." /></div>}
        >
          <For each={rows()}>
            {row => {
              const label = createMemo(() => row.profile?.label ?? "A deleted VPN");
              const kind = createMemo(() => row.keys.map(secret => (secret.slot === "private" && row.profile?.keyKind
                ? `Client key, ${row.profile.keyKind}`
                : secret.label)).join(", "));
              return (
                <div class={styles.ListRow}>
                  <div class={styles.Name}>
                    <span class={styles.ItemIcon}><Shield size={15} /></span>
                    <span class={styles.NameText}><b>{label()}</b></span>
                  </div>
                  <span class={styles.Cell}><FileKey size={12} />{kind()}</span>
                  <div class={styles.Tools}>
                    <Show when={row.profile}>
                      {profile => (
                        <Button size="sm" variant="subtle" onClick={() => void exportProfile(profile())}>
                          <Download size={13} />
                          Export .{fileExtension(profile())}
                        </Button>
                      )}
                    </Show>
                  </div>
                </div>
              );
            }}
          </For>
        </Show>
      </div>
    </>
  );
}

export default VpnKeysView;
