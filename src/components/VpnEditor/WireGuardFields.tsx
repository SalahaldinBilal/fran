import hostStyles from "../HostEditor/HostEditor.module.scss";
import styles from "./VpnEditor.module.scss";
import { Show, createMemo, createSignal } from "solid-js";
import { SetStoreFunction } from "solid-js/store";
import { Copy, KeyRound, Server } from "@core/icons";
import { VpnProfile } from "@core/types";
import { PendingSecret } from "@core/databases/types";
import { copyText } from "@core/helpers/clipboard";
import { toPort } from "@core/databases/shared/fields";
import { SecretRefsEditor } from "@core/helpers/secretRefs";
import Button from "../Button/Button";
import Field, { FieldRow } from "../Field/Field";
import Input from "../Input/Input";
import SecretInput from "../SecretInput/SecretInput";

export const WIREGUARD_PORT = 51820;

export type WireGuardFieldsProps = {
  draft: VpnProfile,
  setDraft: SetStoreFunction<VpnProfile>,
  pending: Record<string, PendingSecret>,
  setPending: SetStoreFunction<Record<string, PendingSecret>>,
  refs?: SecretRefsEditor,
  stored: string[],
  generate: boolean,
  setGenerate: (generate: boolean) => void,
};

function listText(items: string[]): string {
  return items.join(", ");
}

function listItems(text: string): string[] {
  return text.split(",").map(item => item.trim()).filter(Boolean);
}

function looksLikeIp(text: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(text) || text.includes(":");
}

function toNumber(text: string): number | null {
  const value = Number.parseInt(text, 10);
  return Number.isFinite(value) && value > 0 ? value : null;
}

// Mounted fresh for each profile the editor opens, so the list fields keep what's typed, spaces and all.
function WireGuardFields(props: WireGuardFieldsProps) {
  const [allowedIps, setAllowedIps] = createSignal(listText(props.draft.wireGuard.allowedIps));
  const [addresses, setAddresses] = createSignal(listText(props.draft.wireGuard.addresses));
  const [dns, setDns] = createSignal(listText([...props.draft.wireGuard.dns, ...props.draft.wireGuard.searchDomains]));

  const remote = createMemo(() => props.draft.remotes[0] ?? { host: "", port: WIREGUARD_PORT, proto: "udp" as const });
  const pendingKey = createMemo(() => props.pending.private);
  const keyText = createMemo(() => (typeof pendingKey() === "string" ? pendingKey() as string : ""));
  const publicKey = createMemo(() => (pendingKey() === undefined && !props.generate ? props.draft.wireGuard.publicKey : null));
  const keyStatus = createMemo(() => {
    if (props.generate) return "A new key is made when you save";
    if (typeof pendingKey() === "string") return "Saved to the vault when you save";
    return props.draft.wireGuard.publicKey ? "Key in the vault" : "No key saved";
  });
  const keySaved = createMemo(() => publicKey() !== null);
  const presharedStored = createMemo(() => props.stored.includes("presharedKey"));
  const presharedText = createMemo(() => (typeof props.pending.presharedKey === "string" ? props.pending.presharedKey : ""));
  const presharedPlaceholder = createMemo(() => (presharedStored() ? "Saved in the vault. Paste a new one to replace it." : "Optional"));

  function setRemote(change: Partial<VpnProfile["remotes"][number]>) {
    props.setDraft("remotes", [{ ...remote(), ...change, proto: "udp" }]);
  }

  function setDnsText(text: string) {
    setDns(text);
    const items = listItems(text);
    props.setDraft("wireGuard", "dns", items.filter(looksLikeIp));
    props.setDraft("wireGuard", "searchDomains", items.filter(item => !looksLikeIp(item)));
  }

  function generateKey() {
    props.setGenerate(true);
    props.setPending("private", undefined);
  }

  function pasteKey(text: string) {
    props.setGenerate(false);
    props.setPending("private", text.trim() ? text : undefined);
  }

  return (
    <>
      <section class={hostStyles.Section}>
        <h3><Server size={14} />Server</h3>
        <div class={styles.Remote}>
          <SecretInput path="remotes.0.host" refs={props.refs} class={hostStyles.Grow} value={remote().host} onValue={host => setRemote({ host })} placeholder="vpn.example.com" />
          <SecretInput path="remotes.0.port" refs={props.refs} class={styles.Port} type="number" value={remote().port} onValue={value => setRemote({ port: toPort(value) })} />
        </div>
        <Field label="Server's public key">
          <Input value={props.draft.wireGuard.peerPublicKey} onValue={value => props.setDraft("wireGuard", "peerPublicKey", value)} mono />
        </Field>
        <Field label="Allowed IPs" hint="Networks reached through this VPN. 0.0.0.0/0, ::/0 means everything.">
          <Input
            value={allowedIps()}
            onValue={value => {
              setAllowedIps(value);
              props.setDraft("wireGuard", "allowedIps", listItems(value));
            }}
            placeholder="10.0.0.0/8, 192.168.50.0/24"
            mono
          />
        </Field>
        <FieldRow>
          <Field label="Preshared key" grow>
            <Show
              when={props.pending.presharedKey !== null}
              fallback={
                <div class={styles.KeyStatus}>
                  <span class={styles.Removed}>Removed on save</span>
                  <Button size="sm" onClick={() => props.setPending("presharedKey", undefined)}>Undo</Button>
                </div>
              }
            >
              <Input
                type="password"
                value={presharedText()}
                onValue={value => props.setPending("presharedKey", value || undefined)}
                placeholder={presharedPlaceholder()}
                after={
                  <Show when={presharedStored() && props.pending.presharedKey === undefined}>
                    <Button size="sm" variant="danger" onClick={() => props.setPending("presharedKey", null)}>Remove</Button>
                  </Show>
                }
              />
            </Show>
          </Field>
          <Field label="Keepalive" hint="Seconds. Empty is off." width={150}>
            <Input
              type="number"
              value={props.draft.wireGuard.keepaliveSecs ?? ""}
              onValue={value => props.setDraft("wireGuard", "keepaliveSecs", toNumber(value))}
              placeholder="Off"
            />
          </Field>
        </FieldRow>
      </section>

      <section class={hostStyles.Section}>
        <h3><KeyRound size={14} />This side</h3>
        <Field label="Private key" hint="Goes straight to the vault. Give the server the public key below.">
          <div class={styles.KeyStatus}>
            <KeyRound size={14} class={keySaved() ? styles.Saved : undefined} />
            <span>{keyStatus()}</span>
            <Show
              when={props.generate}
              fallback={<Button size="sm" onClick={generateKey}>Generate</Button>}
            >
              <Button size="sm" onClick={() => props.setGenerate(false)}>Undo</Button>
            </Show>
          </div>
          <Input type="password" value={keyText()} onValue={pasteKey} placeholder="Paste a private key to save a new one" mono />
        </Field>
        <Show when={publicKey()}>
          {key => (
            <Field label="Public key">
              <Input
                value={key()}
                readOnly
                mono
                after={
                  <Button icon size="sm" tooltip="Copy" onClick={() => void copyText(key(), "Public key")}>
                    <Copy size={14} />
                  </Button>
                }
              />
            </Field>
          )}
        </Show>
        <FieldRow>
          <Field label="Address" hint="This side's address in the VPN, from the server's admin." grow>
            <Input
              value={addresses()}
              onValue={value => {
                setAddresses(value);
                props.setDraft("wireGuard", "addresses", listItems(value));
              }}
              placeholder="10.64.0.2/32"
              mono
            />
          </Field>
          <Field label="MTU" width={110}>
            <Input
              type="number"
              value={props.draft.wireGuard.mtu ?? ""}
              onValue={value => props.setDraft("wireGuard", "mtu", toNumber(value))}
              placeholder="1420"
            />
          </Field>
        </FieldRow>
        <Field label="DNS" hint="Servers and search domains, like in a wg-quick file.">
          <Input value={dns()} onValue={setDnsText} placeholder="10.64.0.1, corp.example" mono />
        </Field>
      </section>
    </>
  );
}

export default WireGuardFields;
