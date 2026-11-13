import styles from "./Server.module.scss";
import { For, JSX, Match, Show, Switch as Branch, createMemo, createResource, createSignal } from "solid-js";
import { Dynamic } from "solid-js/web";
import { Copy, Crown, KeyRound, Laptop, ShieldCheck, TriangleAlert, User as UserIcon } from "@core/icons";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage } from "@core/helpers/errors";
import { copyText } from "@core/helpers/clipboard";
import { formatAgo, formatBytes, plural } from "@core/helpers";
import useToastState from "@core/states/toastState";
import usePromptState from "@core/states/promptState";
import { AdminInvite, AdminLogEntry, AdminUser, Cloud, FranServerAccount, ServerRole, ServerSettings, SignupMode, UpdateServerSettings } from "@core/types";
import Button from "@core/components/Button/Button";
import Field from "@core/components/Field/Field";
import Input from "@core/components/Input/Input";
import Select, { SelectItem } from "@core/components/Select/Select";
import Spinner from "@core/components/Spinner/Spinner";
import SegmentedControl, { SegmentedOption } from "@core/components/SegmentedControl/SegmentedControl";

type Tab = "accounts" | "invites" | "settings" | "log";

const TABS: SegmentedOption<Tab>[] = [
  { value: "accounts", label: "Accounts" },
  { value: "invites", label: "Invites" },
  { value: "settings", label: "Settings" },
  { value: "log", label: "Log" },
];

const SIGNUP_LABELS: Record<SignupMode, string> = { open: "Anyone", invite: "With an invite", closed: "Closed" };
const SIGNUP_ITEMS: SelectItem<SignupMode>[] = [
  { value: "open", label: "Anyone can sign up" },
  { value: "invite", label: "With an invite code" },
  { value: "closed", label: "Only invited emails" },
];
const ROLE_LABELS: Record<ServerRole, string> = { owner: "Owner", admin: "Admin", user: "User" };
const EXPIRY_ITEMS: SelectItem<number>[] = [
  { value: 1, label: "In a day" },
  { value: 7, label: "In a week" },
  { value: 30, label: "In 30 days" },
  { value: 0, label: "Never" },
];
const LOG_TEXT: Record<string, string> = {
  claim: "claimed the server",
  role: "changed the role of",
  transfer: "handed the server to",
  quota: "changed the limit of",
  signOut: "signed out",
  deleteUser: "deleted",
  inviteCreate: "made an invite for",
  inviteRevoke: "revoked an invite for",
  settings: "changed settings",
};

const MIB = 1024 * 1024;

function day(seconds: number): string {
  return new Date(seconds * 1000).toLocaleDateString(undefined, { dateStyle: "medium" });
}

function when(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function mib(bytes: number): string {
  return String(Math.round((bytes / MIB) * 100) / 100);
}

// Typed in MiB, so a number like 50 or 0.5 is what people expect to enter.
function bytesFromMib(text: string): number | null {
  const value = Number(text.trim());
  return text.trim() === "" || !Number.isFinite(value) || value < 0 ? null : Math.round(value * MIB);
}

function Meter(props: { used: number, limit: number }) {
  const width = createMemo(() => `${props.limit > 0 ? Math.max(1.5, Math.min(100, (props.used / props.limit) * 100)) : 0}%`);
  const full = createMemo(() => props.limit > 0 && props.used >= props.limit * 0.9);
  return (
    <div class={styles.Meter}>
      <div class={styles.MeterFill} classList={{ [styles.MeterFull]: full() }} style={{ width: width() }} />
    </div>
  );
}

function Problem(props: { text: string | null }) {
  return (
    <Show when={props.text}>
      {text => (
        <div class={styles.Problem}>
          <TriangleAlert size={14} />
          <span>{text()}</span>
        </div>
      )}
    </Show>
  );
}

export function ClaimCard(props: { cloud: Cloud, onClaimed: () => void }) {
  const [code, setCode] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const label = createMemo(() => (busy() ? "Claiming" : "Claim this server"));

  async function claim(event: SubmitEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await safeInvoke("fran_server_admin_claim", { cloudId: props.cloud.id, code: code() });
      useToastState.pushToast("This server is yours now", "success", 3000);
      props.onClaimed();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form class={styles.Claim} onSubmit={claim}>
      <div class={styles.ClaimHead}>
        <span class={styles.ClaimIcon}><Crown size={16} /></span>
        <div class={styles.ClaimText}>
          <strong>This server has no owner yet</strong>
          <span>
            The server prints a setup code in its log each time it starts, while nobody owns it. Enter it here to become the owner and manage
            its accounts, invites and limits.
          </span>
        </div>
      </div>
      <div class={styles.ClaimRow}>
        <Input mono value={code()} onValue={setCode} placeholder="XXXX-XXXX-XXXX" />
        <Button type="submit" variant="primary" disabled={busy() || code().trim() === ""}>
          <Show when={busy()}><Spinner size={14} /></Show>
          {label()}
        </Button>
      </div>
      <Problem text={error()} />
    </form>
  );
}

function UserRow(props: { cloud: Cloud, me: FranServerAccount, user: AdminUser, onChanged: () => void }) {
  const { pushToast } = useToastState;
  const [open, setOpen] = createSignal(false);
  const [quota, setQuota] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [confirming, setConfirming] = createSignal<"delete" | "transfer" | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [detail] = createResource(() => (open() ? props.user.id : null), userId => safeInvoke("fran_server_admin_user", { cloudId: props.cloud.id, userId }));

  const isMe = createMemo(() => props.user.id === props.me.id);
  const iOwn = createMemo(() => props.me.role === "owner");
  const canDelete = createMemo(() => !isMe() && props.user.role !== "owner" && (props.user.role === "user" || iOwn()));
  const canSignOut = createMemo(() => props.user.role !== "owner" || iOwn());
  const initial = createMemo(() => (props.user.email[0] ?? "?").toUpperCase());
  const ownLimit = createMemo(() => props.user.ownQuotaBytes > 0);
  const limitText = createMemo(() => `${formatBytes(props.user.usedBytes)} of ${formatBytes(props.user.quotaBytes)}${ownLimit() ? ", own limit" : ""}`);
  const seenText = createMemo(() => {
    if (props.user.devices === 0) return "No device signed in";
    return `${plural(props.user.devices, "device")}, last seen ${formatAgo(props.user.lastSeenAt * 1000)}`;
  });
  const roleTarget = createMemo<ServerRole>(() => (props.user.role === "admin" ? "user" : "admin"));
  const roleLabel = createMemo(() => (props.user.role === "admin" ? "Make a user" : "Make an admin"));
  const confirmLabel = createMemo(() => {
    if (busy()) return "Working";
    return confirming() === "delete" ? "Delete for good" : "Hand it over";
  });
  const confirmVariant = createMemo(() => (confirming() === "delete" ? "danger" : "primary"));
  const confirmLead = createMemo(() => (confirming() === "delete"
    ? `Everything ${props.user.email} stored on this server is removed. Their computers keep their own copy but stop syncing. Type your password to confirm.`
    : `${props.user.email} becomes the owner and you become an admin. Only they can undo it. Type your password to confirm.`));

  function toggle() {
    setOpen(shown => !shown);
    setQuota(props.user.ownQuotaBytes > 0 ? mib(props.user.ownQuotaBytes) : "");
    setConfirming(null);
    setPassword("");
    setError(null);
  }

  async function act(action: () => Promise<unknown>, done: string) {
    setBusy(true);
    setError(null);
    try {
      await action();
      pushToast(done, "success", 2500);
      setConfirming(null);
      setPassword("");
      props.onChanged();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  }

  function saveQuota(useDefault: boolean) {
    const bytes = useDefault ? 0 : bytesFromMib(quota());
    if (bytes === null) {
      setError("Type the limit in MiB, like 100");
      return;
    }
    void act(() => safeInvoke("fran_server_admin_set_quota", { cloudId: props.cloud.id, userId: props.user.id, quotaBytes: bytes }), "Limit saved");
  }

  async function signOut() {
    const confirmed = await usePromptState.confirm({
      title: `Sign ${props.user.email} out everywhere?`,
      message: "Every device of theirs stops syncing until they sign in again. Nothing is deleted.",
      confirmLabel: "Sign out",
      danger: true,
    });
    if (confirmed) void act(() => safeInvoke("fran_server_admin_sign_out_user", { cloudId: props.cloud.id, userId: props.user.id }), "Signed out everywhere");
  }

  function finish(event: SubmitEvent) {
    event.preventDefault();
    const args = { cloudId: props.cloud.id, userId: props.user.id, password: password() };
    if (confirming() === "delete") void act(() => safeInvoke("fran_server_admin_delete_user", args), `Deleted ${props.user.email}`);
    else void act(() => safeInvoke("fran_server_admin_transfer", args), `${props.user.email} owns the server now`);
  }

  return (
    <div class={styles.UserRow} classList={{ [styles.Open]: open() }}>
      <button type="button" class={styles.UserHead} onClick={toggle}>
        <span class={styles.Avatar}>{initial()}</span>
        <span class={styles.UserText}>
          <span class={styles.UserName}>
            {props.user.email}
            <Show when={props.user.role !== "user"}>
              <span class={styles.Badge} classList={{ [styles.BadgeOwner]: props.user.role === "owner" }}>{ROLE_LABELS[props.user.role]}</span>
            </Show>
            <Show when={isMe()}><span class={styles.Faint}>You</span></Show>
          </span>
          <span class={styles.UserDetail}>{seenText()}</span>
        </span>
        <span class={styles.UserUsage}>
          <span>{limitText()}</span>
          <Meter used={props.user.usedBytes} limit={props.user.quotaBytes} />
        </span>
      </button>

      <Show when={open()}>
        <div class={styles.UserBody}>
          <div class={styles.Facts}>
            <span>Joined {day(props.user.createdAt)}</span>
            <span>Two-step sign-in {props.user.totpEnabled ? "on" : "off"}</span>
          </div>

          <Show when={!detail.loading} fallback={<div class={styles.Loading}><Spinner size={14} /></div>}>
            <Show when={(detail()?.sessions.length ?? 0) > 0}>
              <div class={styles.Devices}>
                <For each={detail()?.sessions ?? []}>
                  {session => (
                    <div class={styles.Device}>
                      <Laptop size={13} />
                      <span>{session.device.name}</span>
                      <span class={styles.Faint}>last seen {formatAgo(session.lastSeenAt * 1000)}</span>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </Show>

          <Field label="Storage limit (MiB)" hint="Empty or the default button uses the server's limit. Lowering it never deletes anything, it only stops growth.">
            <div class={styles.Inline}>
              <Input value={quota()} onValue={setQuota} placeholder={mib(props.user.quotaBytes)} />
              <Button variant="subtle" disabled={busy()} onClick={() => saveQuota(false)}>Save limit</Button>
              <Show when={ownLimit()}>
                <Button variant="ghost" disabled={busy()} onClick={() => saveQuota(true)}>Use the default</Button>
              </Show>
            </div>
          </Field>

          <div class={styles.Actions}>
            <Show when={canSignOut() && !isMe()}>
              <Button variant="subtle" size="sm" disabled={busy()} onClick={() => void signOut()}>Sign out everywhere</Button>
            </Show>
            <Show when={iOwn() && !isMe()}>
              <Button
                variant="subtle"
                size="sm"
                disabled={busy()}
                onClick={() => void act(() => safeInvoke("fran_server_admin_set_role", { cloudId: props.cloud.id, userId: props.user.id, role: roleTarget() }), "Role changed")}
              >
                {roleLabel()}
              </Button>
              <Button variant="subtle" size="sm" disabled={busy()} onClick={() => setConfirming("transfer")}>Hand the server over</Button>
            </Show>
            <div class={styles.Grow} />
            <Show when={canDelete()}>
              <Button variant="danger" size="sm" disabled={busy()} onClick={() => setConfirming("delete")}>Delete account</Button>
            </Show>
          </div>

          <Show when={confirming()}>
            <form class={styles.Confirm} onSubmit={finish}>
              <p>{confirmLead()}</p>
              <div class={styles.Inline}>
                <Input type="password" value={password()} onValue={setPassword} placeholder="Your password" autofocus />
                <Button variant="ghost" onClick={() => setConfirming(null)}>Cancel</Button>
                <Button type="submit" variant={confirmVariant()} disabled={busy() || password() === ""}>{confirmLabel()}</Button>
              </div>
            </form>
          </Show>
          <Problem text={error()} />
        </div>
      </Show>
    </div>
  );
}

function Accounts(props: { cloud: Cloud, me: FranServerAccount, onChanged: () => void }) {
  const [search, setSearch] = createSignal("");
  const [page, { refetch }] = createResource(search, text => safeInvoke("fran_server_admin_users", { cloudId: props.cloud.id, search: text, offset: 0 }));
  const more = createMemo(() => {
    const found = page();
    return found && found.total > found.users.length ? `Showing ${found.users.length} of ${found.total}. Search to narrow it down.` : "";
  });

  function changed() {
    void refetch();
    props.onChanged();
  }

  return (
    <div class={styles.Pane}>
      <Input type="search" value={search()} onValue={setSearch} placeholder="Search by email" clearable />
      <Show when={page()} fallback={<div class={styles.Loading}><Spinner size={14} /></div>}>
        {found => (
          <Show when={found().users.length > 0} fallback={<div class={styles.Empty}>No account matches that</div>}>
            <div class={styles.List}>
              <For each={found().users}>{user => <UserRow cloud={props.cloud} me={props.me} user={user} onChanged={changed} />}</For>
            </div>
          </Show>
        )}
      </Show>
      <Show when={more()}>{text => <span class={styles.Faint}>{text()}</span>}</Show>
    </div>
  );
}

function inviteState(invite: AdminInvite): { text: string, tone: "used" | "expired" | "open" } {
  if (invite.usedAt > 0) return { text: `Used by ${invite.usedBy || "an account that was deleted"}`, tone: "used" };
  if (invite.expiresAt > 0 && invite.expiresAt * 1000 < Date.now()) return { text: "Expired", tone: "expired" };
  return { text: invite.expiresAt > 0 ? `Open until ${day(invite.expiresAt)}` : "Open, never expires", tone: "open" };
}

function Invites(props: { cloud: Cloud }) {
  const { pushError } = useToastState;
  const [email, setEmail] = createSignal("");
  const [days, setDays] = createSignal(7);
  const [made, setMade] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [invites, { refetch }] = createResource(() => safeInvoke("fran_server_admin_invites", { cloudId: props.cloud.id }));
  const makeLabel = createMemo(() => (busy() ? "Making" : "Make an invite"));

  async function make(event: SubmitEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = await safeInvoke("fran_server_admin_create_invite", { cloudId: props.cloud.id, email: email(), expiresInDays: days() });
      setMade(created.code);
      setEmail("");
      void refetch();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(invite: AdminInvite) {
    try {
      await safeInvoke("fran_server_admin_delete_invite", { cloudId: props.cloud.id, inviteId: invite.id });
      void refetch();
    } catch (failure) {
      pushError(failure);
    }
  }

  return (
    <div class={styles.Pane}>
      <form class={styles.NewInvite} onSubmit={make}>
        <div class={styles.Inline}>
          <Input value={email()} onValue={setEmail} placeholder="Email, or empty for anyone" />
          <Select value={days()} items={EXPIRY_ITEMS} onChange={setDays} style={{ width: "140px", "flex-shrink": 0 }} />
          <Button type="submit" variant="primary" disabled={busy()}>{makeLabel()}</Button>
        </div>
        <span class={styles.Faint}>An invite works once. One made for an email only works for that email, even when sign-up is closed.</span>
        <Problem text={error()} />
      </form>

      <Show when={made()}>
        {code => (
          <div class={styles.Made}>
            <div class={styles.MadeText}>
              <strong>Send this code to them</strong>
              <span>It's only shown now. They enter it when they create their account in Fran.</span>
            </div>
            <div class={styles.Code}>
              <span>{code()}</span>
              <Button icon size="sm" tooltip="Copy" onClick={() => void copyText(code(), "Invite code")}>
                <Copy size={13} />
              </Button>
            </div>
          </div>
        )}
      </Show>

      <Show when={invites()} fallback={<div class={styles.Loading}><Spinner size={14} /></div>}>
        {list => (
          <Show when={list().length > 0} fallback={<div class={styles.Empty}>No invites yet</div>}>
            <div class={styles.List}>
              <For each={list()}>
                {invite => {
                  const state = createMemo(() => inviteState(invite));
                  return (
                    <div class={styles.Invite}>
                      <KeyRound size={14} class={styles.Faint} />
                      <div class={styles.UserText}>
                        <span class={styles.UserName}>{invite.email || "Anyone"}</span>
                        <span class={styles.UserDetail}>Made {day(invite.createdAt)}</span>
                      </div>
                      <span class={styles.State} classList={{ [styles.StateUsed]: state().tone === "used", [styles.StateExpired]: state().tone === "expired" }}>
                        {state().text}
                      </span>
                      <Show when={invite.usedAt === 0}>
                        <Button variant="ghost" size="sm" onClick={() => void revoke(invite)}>Revoke</Button>
                      </Show>
                    </div>
                  );
                }}
              </For>
            </div>
          </Show>
        )}
      </Show>
    </div>
  );
}

function SettingLine(props: { label: string, hint: string, children: JSX.Element }) {
  return (
    <div class={styles.SettingLine}>
      <div class={styles.UserText}>
        <span class={styles.UserName}>{props.label}</span>
        <span class={styles.UserDetail}>{props.hint}</span>
      </div>
      {props.children}
    </div>
  );
}

function Settings(props: { cloud: Cloud, onChanged: () => void }) {
  const { pushToast } = useToastState;
  const [loaded, { mutate }] = createResource(() => safeInvoke("fran_server_admin_settings", { cloudId: props.cloud.id }));
  const [draft, setDraft] = createSignal<Record<string, string>>({});
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const dirty = createMemo(() => Object.keys(draft()).length > 0);
  const saveLabel = createMemo(() => (busy() ? "Saving" : "Save changes"));

  function text(name: string, fallback: string): string {
    return draft()[name] ?? fallback;
  }

  function edit(name: string, value: string) {
    setDraft(current => ({ ...current, [name]: value }));
  }

  function update(current: ServerSettings): UpdateServerSettings | string {
    const result: UpdateServerSettings = {};
    const values = draft();
    if (values.signup !== undefined) result.signup = values.signup as SignupMode;
    for (const name of ["accountBytes", "recordBytes", "serverBytes"] as const) {
      if (values[name] === undefined) continue;
      const bytes = bytesFromMib(values[name]);
      if (bytes === null) return "Sizes are typed in MiB, like 50";
      if (bytes !== current[name]) result[name] = bytes;
    }
    if (values.batchRecords !== undefined) {
      const count = Number(values.batchRecords);
      if (!Number.isInteger(count) || count < 1) return "Records per push is a whole number, 1 or more";
      result.batchRecords = count;
    }
    return result;
  }

  async function save() {
    const current = loaded();
    if (!current) return;
    const changes = update(current);
    if (typeof changes === "string") {
      setError(changes);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      mutate(await safeInvoke("fran_server_admin_update_settings", { cloudId: props.cloud.id, update: changes }));
      setDraft({});
      pushToast("Server settings saved", "success", 2500);
      props.onChanged();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Show when={loaded()} fallback={<div class={styles.Loading}><Spinner size={14} /></div>}>
      {current => (
        <div class={styles.Pane}>
          <div class={styles.Settings}>
            <SettingLine label="Who can sign up" hint="New accounts. Invites made for an email always work.">
              <Select
                value={text("signup", current().signup) as SignupMode}
                items={SIGNUP_ITEMS}
                onChange={value => edit("signup", value)}
                style={{ width: "200px", "flex-shrink": 0 }}
              />
            </SettingLine>
            <SettingLine label="Storage per account (MiB)" hint="Unless an account has its own limit. Lowering it never deletes.">
              <Input value={text("accountBytes", mib(current().accountBytes))} onValue={value => edit("accountBytes", value)} class={styles.Number} />
            </SettingLine>
            <SettingLine label="Total storage (MiB)" hint="For every account together. 0 for no limit.">
              <Input value={text("serverBytes", mib(current().serverBytes))} onValue={value => edit("serverBytes", value)} class={styles.Number} />
            </SettingLine>
            <SettingLine label="Largest item (MiB)" hint="One connection, host or setting, encrypted.">
              <Input value={text("recordBytes", mib(current().recordBytes))} onValue={value => edit("recordBytes", value)} class={styles.Number} />
            </SettingLine>
            <SettingLine label="Items per sync" hint="How many one sync can send at once.">
              <Input value={text("batchRecords", String(current().batchRecords))} onValue={value => edit("batchRecords", value)} class={styles.Number} />
            </SettingLine>
          </div>
          <Problem text={error()} />
          <div class={styles.Actions}>
            <div class={styles.Grow} />
            <Show when={dirty()}>
              <Button variant="ghost" onClick={() => setDraft({})}>Undo</Button>
            </Show>
            <Button variant="primary" disabled={!dirty() || busy()} onClick={() => void save()}>{saveLabel()}</Button>
          </div>
        </div>
      )}
    </Show>
  );
}

function Log(props: { cloud: Cloud }) {
  const [entries] = createResource(() => safeInvoke("fran_server_admin_log", { cloudId: props.cloud.id }));

  function sentence(entry: AdminLogEntry): string {
    const verb = LOG_TEXT[entry.action] ?? entry.action;
    return [entry.actor, verb, entry.target].filter(Boolean).join(" ");
  }

  return (
    <Show when={entries()} fallback={<div class={styles.Loading}><Spinner size={14} /></div>}>
      {list => (
        <Show when={list().length > 0} fallback={<div class={styles.Empty}>Nothing happened yet</div>}>
          <div class={styles.List}>
            <For each={list()}>
              {entry => (
                <div class={styles.LogEntry}>
                  <span class={styles.LogTime}>{when(entry.at)}</span>
                  <div class={styles.UserText}>
                    <span class={styles.UserName}>{sentence(entry)}</span>
                    <Show when={entry.detail}><span class={styles.UserDetail}>{entry.detail}</span></Show>
                  </div>
                </div>
              )}
            </For>
          </div>
        </Show>
      )}
    </Show>
  );
}

export function ServerAdmin(props: { cloud: Cloud, me: FranServerAccount }) {
  const [tab, setTab] = createSignal<Tab>("accounts");
  const [overview, { refetch }] = createResource(
    () => ({ id: props.cloud.id, synced: props.cloud.lastSync }),
    source => safeInvoke("fran_server_admin_overview", { cloudId: source.id }),
  );
  const roleIcon = createMemo(() => (props.me.role === "owner" ? Crown : ShieldCheck));
  const roleText = createMemo(() => (props.me.role === "owner" ? "You own this server" : "You're an admin on this server"));
  const storageText = createMemo(() => {
    const found = overview();
    if (!found) return "";
    return found.serverBytes > 0 ? `${formatBytes(found.usedBytes)} of ${formatBytes(found.serverBytes)}` : `${formatBytes(found.usedBytes)}, no total limit`;
  });

  function changed() {
    void refetch();
  }

  return (
    <div class={styles.Admin}>
      <div class={styles.Role}>
        <span class={styles.RoleIcon}><Dynamic component={roleIcon()} size={14} /></span>
        <span>{roleText()}</span>
        <Show when={overview()}>{found => <span class={styles.Faint}>Version {found().version}, up since {when(found().startedAt)}</span>}</Show>
      </div>

      <Show when={overview()}>
        {found => (
          <div class={styles.Tiles}>
            <div class={styles.Tile}>
              <span class={styles.TileLabel}><UserIcon size={12} /> Accounts</span>
              <strong>{found().accounts.toLocaleString()}</strong>
            </div>
            <div class={styles.Tile}>
              <span class={styles.TileLabel}>Storage</span>
              <strong>{storageText()}</strong>
              <Show when={found().serverBytes > 0}><Meter used={found().usedBytes} limit={found().serverBytes} /></Show>
            </div>
            <div class={styles.Tile}>
              <span class={styles.TileLabel}>Sign-up</span>
              <strong>{SIGNUP_LABELS[found().signup]}</strong>
            </div>
          </div>
        )}
      </Show>

      <SegmentedControl value={tab()} options={TABS} onChange={setTab} fill />
      <Branch>
        <Match when={tab() === "accounts"}><Accounts cloud={props.cloud} me={props.me} onChanged={changed} /></Match>
        <Match when={tab() === "invites"}><Invites cloud={props.cloud} /></Match>
        <Match when={tab() === "settings"}><Settings cloud={props.cloud} onChanged={changed} /></Match>
        <Match when={tab() === "log"}><Log cloud={props.cloud} /></Match>
      </Branch>
    </div>
  );
}
