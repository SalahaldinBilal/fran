import styles from "./Secrets.module.scss";
import own from "./PasswordsView.module.scss";
import { For, Show, createMemo, createResource, createSignal, onCleanup } from "solid-js";
import { Copy, Database, Globe, KeyRound, Lock, LockOpen, Shield, TriangleAlert, User } from "lucide-solid";
import useSavedSecretsState from "@core/states/savedSecretsState";
import useToastState from "@core/states/toastState";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage } from "@core/helpers/errors";
import { copySecret, copyShownSecret } from "@core/helpers/revealSecret";
import { SavedSecret, SecretGroup } from "@core/types";
import Button from "@core/components/Button/Button";
import EmptyState from "@core/components/EmptyState/EmptyState";

const COLUMNS = "minmax(180px, 1.3fr) minmax(120px, 1fr) minmax(160px, 1.4fr) 44px";

const GROUPS: { group: SecretGroup, title: string, icon: typeof Lock, deleted: string }[] = [
  { group: "connection", title: "Database connections", icon: Database, deleted: "A deleted connection" },
  { group: "identity", title: "Identities", icon: User, deleted: "A deleted identity" },
  { group: "key", title: "SSH key passphrases", icon: KeyRound, deleted: "A deleted key" },
  { group: "proxy", title: "Proxies", icon: Globe, deleted: "A deleted proxy" },
  { group: "vpn", title: "VPNs", icon: Shield, deleted: "A deleted VPN" },
];

// "Password" reads as "password" in a sentence, "SSH password" stays as it is.
const inSentence = (label: string): string => (/^[A-Z][a-z]/.test(label) ? label[0].toLowerCase() + label.slice(1) : label);

function countdown(milliseconds: number): string {
  const seconds = Math.max(0, Math.ceil(milliseconds / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function PasswordRow(props: { secret: SavedSecret, deleted: string, icon: typeof Lock }) {
  const saved = useSavedSecretsState;
  const [busy, setBusy] = createSignal(false);

  const name = createMemo(() => props.secret.ownerLabel ?? props.deleted);
  const shown = createMemo(() => saved.values[props.secret.id] ?? null);
  const value = createMemo(() => shown() ?? "••••••••••");
  const what = createMemo(() => `the ${inSentence(props.secret.label)} for ${name()}`);

  async function copy() {
    const current = shown();
    if (current !== null) {
      await copyShownSecret(current, what());
      return;
    }
    const owner = props.secret.owner;
    if (!owner) return;
    setBusy(true);
    try {
      await copySecret(owner, props.secret.slot, what());
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class={styles.ListRow}>
      <div class={styles.Name}>
        <span class={styles.ItemIcon}><props.icon size={15} /></span>
        <span class={styles.NameText}>
          <b classList={{ [own.Deleted]: props.secret.ownerLabel === null }}>{name()}</b>
        </span>
      </div>
      <span class={styles.Cell}>{props.secret.label}</span>
      <span class={`${styles.Cell} ${styles.Mono}`} classList={{ [own.Shown]: shown() !== null }}>
        <span class={own.Value}>{value()}</span>
      </span>
      <div class={styles.Tools}>
        <Button icon size="sm" tooltip="Copy" disabled={busy()} onClick={copy}><Copy size={14} /></Button>
      </div>
    </div>
  );
}

function PasswordsView() {
  const saved = useSavedSecretsState;
  const [unprotected] = createResource(() => safeInvoke("get_os_auth_status").catch(() => false));
  const [now, setNow] = createSignal(Date.now());
  const [unlocking, setUnlocking] = createSignal(false);
  const ticker = setInterval(() => setNow(Date.now()), 1000);
  onCleanup(() => clearInterval(ticker));

  const passwords = createMemo(() => saved.secrets.filter(secret => secret.revealable));
  const unlocked = createMemo(() => {
    const until = saved.unlockedUntil();
    return until !== null && until > now();
  });
  const remaining = createMemo(() => countdown((saved.unlockedUntil() ?? 0) - now()));

  async function unlock() {
    setUnlocking(true);
    try {
      await saved.unlock();
    } catch (error) {
      useToastState.pushError(error);
    } finally {
      setUnlocking(false);
    }
  }

  return (
    <>
      <div class={styles.Head}>
        <h2>Passwords</h2>
      </div>
      <p class={styles.Description}>
        Every password, passphrase and token saved in the vault. Unlock them once and they stay readable for 5 minutes,
        or until you lock them again or lock Fran. Leaving this page hides them until you come back. A copied password is cleared from the clipboard after 30 seconds.
      </p>

      <Show when={passwords().length > 0}>
        <div class={own.LockBar} classList={{ [own.Open]: unlocked() }}>
          <span class={own.LockIcon}>
            <Show when={unlocked()} fallback={<Lock size={16} />}><LockOpen size={16} /></Show>
          </span>
          <span class={own.LockText}>
            <Show
              when={unlocked()}
              fallback={
                <>
                  <b>Locked</b>
                  <small>Your system asks you to confirm it's you, then every password here is shown.</small>
                </>
              }
            >
              <b>Unlocked</b>
              <small>Locks again in {remaining()}. Show in the editors doesn't ask until then either.</small>
            </Show>
          </span>
          <Show
            when={unlocked()}
            fallback={
              <Button variant="primary" disabled={unlocking()} onClick={unlock}>
                <LockOpen size={14} />
                Unlock
              </Button>
            }
          >
            <Button variant="subtle" onClick={() => void saved.lock()}>
              <Lock size={14} />
              Lock now
            </Button>
          </Show>
        </div>
      </Show>

      <Show when={unprotected()}>
        <div class={`${styles.Note} ${styles.Warn} ${own.Warning}`}>
          <TriangleAlert size={15} />
          <span>
            Your account has no password, so anyone at this computer can see these. Set one, or turn on the app lock in Settings, Security.
          </span>
        </div>
      </Show>

      <Show when={saved.loadError()}>
        <div class={`${styles.Note} ${styles.Warn} ${own.Warning}`}>
          <TriangleAlert size={15} />
          <span>The vault couldn't be read. {errorMessage(saved.loadError())}</span>
        </div>
      </Show>

      <Show
        when={passwords().length > 0}
        fallback={
          <div class={styles.List}>
            <div class={styles.Empty}>
              <EmptyState icon={Lock} title="No saved passwords" description="Passwords you save when connecting show up here." />
            </div>
          </div>
        }
      >
        <For each={GROUPS}>
          {group => {
            const items = createMemo(() => passwords().filter(secret => secret.group === group.group));
            return (
              <Show when={items().length > 0}>
                <h3 class={own.GroupTitle}>{group.title}</h3>
                <div class={`${styles.List} ${own.Group}`} style={{ "--columns": COLUMNS }}>
                  <div class={styles.ListHead}><span>Belongs to</span><span>What</span><span>Value</span><span /></div>
                  <For each={items()}>
                    {secret => <PasswordRow secret={secret} deleted={group.deleted} icon={group.icon} />}
                  </For>
                </div>
              </Show>
            );
          }}
        </For>
      </Show>
    </>
  );
}

export default PasswordsView;
