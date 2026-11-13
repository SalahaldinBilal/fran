import styles from "./Secrets.module.scss";
import { For, Show, createMemo, createSignal } from "solid-js";
import { Info, Search, ShieldCheck, Trash2 } from "@core/icons";
import useSshState from "@core/states/sshState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import { HostKeyInfo } from "@core/types";
import Button from "@core/components/Button/Button";
import Input from "@core/components/Input/Input";
import EmptyState from "@core/components/EmptyState/EmptyState";
import { tooltip } from "@core/components/Tooltip/Tooltip";

const COLUMNS = "minmax(170px, 1.2fr) 120px minmax(200px, 2.2fr) 100px 40px";

function hostLabel(known: HostKeyInfo): string {
  return known.port === 22 ? known.host : `${known.host}:${known.port}`;
}

function KnownHostsView() {
  const ssh = useSshState;
  const { confirm } = usePromptState;
  const { pushError } = useToastState;
  const [search, setSearch] = createSignal("");

  const filtered = createMemo(() => {
    const needle = search().trim().toLowerCase();
    if (!needle) return ssh.knownHosts;
    return ssh.knownHosts.filter(known => [known.host, known.fingerprint, known.algorithm].some(text => text.toLowerCase().includes(needle)));
  });

  const hasAny = createMemo(() => ssh.knownHosts.length > 0);
  const emptyTitle = createMemo(() => (hasAny() ? "Nothing matches" : "No trusted hosts yet"));
  const emptyText = createMemo(() => (hasAny() ? undefined : "They're added when you trust a host's key the first time you connect."));

  async function forget(known: HostKeyInfo) {
    const confirmed = await confirm({
      title: `Forget ${hostLabel(known)}?`,
      message: "The next connection asks you to check its key again.",
      confirmLabel: "Forget",
      danger: true,
    });
    if (confirmed) await ssh.forgetKnownHost(known).catch(pushError);
  }

  return (
    <>
      <div class={styles.Head}>
        <h2>Known hosts</h2>
        <Input class={styles.Search} type="search" value={search()} onValue={setSearch} placeholder="Search" before={<Search size={14} />} clearable />
      </div>
      <p class={styles.Description}>
        Every server you've trusted, checked on each hop of every connection. A key that changes stops the connection
        until you replace it from the warning or forget it here.
      </p>

      <div class={styles.List} style={{ "--columns": COLUMNS }}>
        <div class={styles.ListHead}><span>Host</span><span>Key type</span><span>Fingerprint</span><span>Trusted</span><span /></div>
        <Show
          when={filtered().length > 0}
          fallback={
            <div class={styles.Empty}>
              <EmptyState icon={ShieldCheck} title={emptyTitle()} description={emptyText()} />
            </div>
          }
        >
          <For each={filtered()}>
            {known => {
              const added = createMemo(() => (known.added ? new Date(known.added).toLocaleDateString() : "Earlier"));
              return (
                <div class={styles.ListRow}>
                  <div class={styles.Name}>
                    <span class={styles.ItemIcon}><ShieldCheck size={15} /></span>
                    <span class={styles.NameText}><b class={styles.Mono}>{hostLabel(known)}</b></span>
                  </div>
                  <span class={styles.Cell}>{known.algorithm}</span>
                  <span class={`${styles.Cell} ${styles.Mono}`} ref={element => tooltip(element, () => known.fingerprint)}>{known.fingerprint}</span>
                  <span class={styles.Cell}>{added()}</span>
                  <div class={styles.Tools}>
                    <Button icon size="sm" tooltip="Forget this key" onClick={() => forget(known)}><Trash2 size={14} /></Button>
                  </div>
                </div>
              );
            }}
          </For>
        </Show>
      </div>

      <div class={styles.Note}>
        <Info size={14} />
        <span>
          When a server isn't listed here but OpenSSH on this computer already trusts it in <code>~/.ssh/known_hosts</code>,
          the prompt says so. You still confirm it once. That file is only read, never written.
        </span>
      </div>
    </>
  );
}

export default KnownHostsView;
