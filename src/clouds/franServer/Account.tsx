import styles from "./Account.module.scss";
import { For, JSX, Match, Show, Switch as Branch, createMemo, createResource, createSignal } from "solid-js";
import { Dynamic } from "solid-js/web";
import { Copy, KeyRound, Laptop, Lock, LucideIcon, ShieldCheck, TriangleAlert } from "@core/icons";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage } from "@core/helpers/errors";
import { copySensitive } from "@core/helpers/clipboard";
import { formatAgo, formatBytes, plural } from "@core/helpers";
import useSyncState from "@core/states/syncState";
import usePromptState from "@core/states/promptState";
import useToastState from "@core/states/toastState";
import { Cloud, FranServerConfig, FranServerDevice, FranServerTotp } from "@core/types";
import Button from "@core/components/Button/Button";
import Field from "@core/components/Field/Field";
import Input from "@core/components/Input/Input";
import Spinner from "@core/components/Spinner/Spinner";
import QrCode from "@core/components/QrCode/QrCode";
import SegmentedControl, { SegmentedOption } from "@core/components/SegmentedControl/SegmentedControl";
import { ClaimCard, ServerAdmin } from "./Server";

type Panel = "none" | "password" | "recovery" | "totpOn" | "totpOff" | "delete";

type View = "account" | "server";

const VIEWS: SegmentedOption<View>[] = [
  { value: "account", label: "Your account" },
  { value: "server", label: "Server" },
];

const MIN_PASSWORD = 10;

const OS_NAMES: Record<string, string> = { windows: "Windows", macos: "macOS", linux: "Linux" };

function osName(os: string): string {
  return OS_NAMES[os] ?? os;
}

function day(seconds: number): string {
  return new Date(seconds * 1000).toLocaleDateString(undefined, { dateStyle: "medium" });
}

function Row(props: { icon: LucideIcon, title: string, detail: JSX.Element, badge?: JSX.Element, danger?: boolean, action: JSX.Element, children?: JSX.Element }) {
  return (
    <div class={styles.Row} classList={{ [styles.DangerRow]: props.danger ?? false }}>
      <div class={styles.RowHead}>
        <span class={styles.RowIcon}><Dynamic component={props.icon} size={15} /></span>
        <div class={styles.RowText}>
          <span class={styles.RowTitle}>{props.title}{props.badge}</span>
          <span class={styles.RowDetail}>{props.detail}</span>
        </div>
        {props.action}
      </div>
      {props.children}
    </div>
  );
}

function Account(props: { cloud: Cloud }) {
  const sync = useSyncState;
  const { pushToast } = useToastState;
  const config = createMemo(() => props.cloud.config as FranServerConfig);
  const cloudId = createMemo(() => props.cloud.id);

  const [panel, setPanel] = createSignal<Panel>("none");
  const [current, setCurrent] = createSignal("");
  const [next, setNext] = createSignal("");
  const [repeat, setRepeat] = createSignal("");
  const [code, setCode] = createSignal("");
  const [typedEmail, setTypedEmail] = createSignal("");
  const [setup, setSetup] = createSignal<FranServerTotp | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const signedIn = createMemo(() => !props.cloud.status.signedOut);
  // Read again after each sync, so the storage used keeps up with what was just pushed.
  const [account, { refetch: refetchAccount }] = createResource(
    () => (signedIn() ? { id: cloudId(), synced: props.cloud.lastSync } : null),
    source => safeInvoke("fran_server_account", { cloudId: source.id }).catch(() => null),
  );
  const [devices, { refetch: refetchDevices }] = createResource(
    () => (signedIn() ? cloudId() : null),
    id => safeInvoke("fran_server_devices", { cloudId: id }).catch(() => []),
  );
  const [info, { refetch: refetchInfo }] = createResource(() => config().url, url => safeInvoke("fran_server_info", { url }).catch(() => null));
  const [view, setView] = createSignal<View>("account");
  const unowned = createMemo(() => info()?.owned === false);
  const admin = createMemo(() => account()?.role === "owner" || account()?.role === "admin");
  // The account, once it can see the server's side, and only while that view is picked.
  const serverView = createMemo(() => (admin() && view() === "server" ? account() ?? null : null));

  function claimed() {
    void refetchInfo();
    void refetchAccount();
    setView("server");
  }

  const initial = createMemo(() => (config().email.trim()[0] ?? "?").toUpperCase());
  const insecure = createMemo(() => config().url.startsWith("http://"));
  const twoStepOn = createMemo(() => account()?.totpEnabled ?? false);
  const usedBytes = createMemo(() => account()?.usedBytes ?? 0);
  const limitBytes = createMemo(() => account()?.quotaBytes || info()?.limits.accountBytes || 0);
  const usedText = createMemo(() => {
    if (!account()) return "";
    return limitBytes() > 0 ? `${formatBytes(usedBytes())} of ${formatBytes(limitBytes())}` : `${formatBytes(usedBytes())} used`;
  });
  const usedWidth = createMemo(() => `${limitBytes() > 0 ? Math.max(1.5, Math.min(100, (usedBytes() / limitBytes()) * 100)) : 0}%`);
  const sortedDevices = createMemo(() => [...(devices() ?? [])].sort((a, b) => Number(b.current) - Number(a.current) || b.lastSeenAt - a.lastSeenAt));
  const devicesText = createMemo(() => (devices.loading ? "Loading" : `${plural(sortedDevices().length, "device")} signed in`));
  const sinceText = createMemo(() => {
    const created = account()?.createdAt;
    return created ? `Account made ${day(created)}` : "";
  });

  const longEnough = createMemo(() => [...next()].length >= MIN_PASSWORD);
  const matches = createMemo(() => repeat() !== "" && repeat() === next());
  const canSubmit = createMemo(() => {
    if (busy()) return false;
    switch (panel()) {
      case "password": return current() !== "" && longEnough() && matches();
      case "recovery":
      case "totpOff": return current() !== "";
      case "totpOn": return code().trim().length >= 6;
      case "delete": return current() !== "" && typedEmail().trim().toLowerCase() === config().email.toLowerCase();
      default: return false;
    }
  });
  const submitLabel = createMemo(() => {
    if (busy()) return "Working";
    switch (panel()) {
      case "password": return "Change password";
      case "recovery": return "Make a new key";
      case "totpOn": return "Turn on";
      case "totpOff": return "Turn off";
      default: return "Delete for good";
    }
  });
  const submitVariant = createMemo(() => (panel() === "delete" ? "danger" : "primary"));
  const deleteVariant = createMemo(() => (panel() === "delete" ? "subtle" : "danger"));
  const deleteLabel = createMemo(() => (panel() === "delete" ? "Cancel" : "Delete"));
  const twoStepOpen = createMemo(() => panel() === "totpOn" || panel() === "totpOff");
  const twoStepLabel = createMemo(() => {
    if (twoStepOpen()) return "Cancel";
    return twoStepOn() ? "Turn off" : "Turn on";
  });
  const twoStepBadge = createMemo(() => (twoStepOn() ? "On" : "Off"));

  function open(which: Panel) {
    setPanel(currentPanel => (currentPanel === which ? "none" : which));
    setCurrent("");
    setNext("");
    setRepeat("");
    setCode("");
    setTypedEmail("");
    setSetup(null);
    setError(null);
  }

  async function openTwoStep() {
    if (twoStepOn()) {
      open("totpOff");
      return;
    }
    open("totpOn");
    if (panel() !== "totpOn") return;
    try {
      setSetup(await safeInvoke("fran_server_totp", { cloudId: cloudId(), action: { action: "begin" } }));
    } catch (failure) {
      setError(errorMessage(failure));
    }
  }

  async function act(): Promise<string> {
    switch (panel()) {
      case "password":
        await safeInvoke("fran_server_change_password", { cloudId: cloudId(), current: current(), next: next() });
        return "Password changed. The other devices were signed out.";
      case "recovery": {
        const key = await safeInvoke("fran_server_new_recovery_key", { cloudId: cloudId(), password: current() });
        sync.showRecoveryKey(props.cloud.name, key);
        return "The old recovery key no longer works";
      }
      case "totpOn":
        await safeInvoke("fran_server_totp", { cloudId: cloudId(), action: { action: "confirm", code: code() } });
        return "Two-step sign-in is on";
      case "totpOff":
        await safeInvoke("fran_server_totp", { cloudId: cloudId(), action: { action: "disable", password: current() } });
        return "Two-step sign-in is off";
      default:
        await safeInvoke("fran_server_delete_account", { cloudId: cloudId(), password: current(), typedEmail: typedEmail() });
        return "The account was deleted. This computer kept its own copy.";
    }
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSubmit()) return;
    setBusy(true);
    setError(null);
    try {
      pushToast(await act(), "info");
      open("none");
      await sync.load();
      void refetchAccount();
      void refetchDevices();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(device: FranServerDevice) {
    const confirmed = await usePromptState.confirm({
      title: `Sign out ${device.device.name}?`,
      message: "It stops syncing until someone signs in on it again. What it already has stays on it.",
      confirmLabel: "Sign out",
      danger: true,
    });
    if (!confirmed) return;
    try {
      await safeInvoke("fran_server_revoke_device", { cloudId: cloudId(), sessionId: device.id });
      void refetchDevices();
    } catch (failure) {
      useToastState.pushError(failure);
    }
  }

  function PasswordField(field: { label: string, value: string, onValue: (value: string) => void, autofocus?: boolean }) {
    return (
      <Field label={field.label}>
        <Input type="password" value={field.value} onValue={field.onValue} autofocus={field.autofocus} />
      </Field>
    );
  }

  function Form(form: { lead: string, children: JSX.Element }) {
    return (
      <form class={styles.Form} onSubmit={submit}>
        <p class={styles.Lead}>{form.lead}</p>
        {form.children}
        <Show when={error()}>
          {text => (
            <div class={styles.Problem}>
              <TriangleAlert size={14} />
              <span>{text()}</span>
            </div>
          )}
        </Show>
        <div class={styles.Actions}>
          <Button variant="ghost" onClick={() => open("none")}>Cancel</Button>
          <Button type="submit" variant={submitVariant()} disabled={!canSubmit()}>
            <Show when={busy()}><Spinner size={14} /></Show>
            {submitLabel()}
          </Button>
        </div>
      </form>
    );
  }

  function toggle(which: Panel, label: string) {
    const opened = createMemo(() => panel() === which);
    const text = createMemo(() => (opened() ? "Cancel" : label));
    return <Button variant="subtle" size="sm" active={opened()} onClick={() => open(which)}>{text()}</Button>;
  }

  return (
    <div class={styles.Account}>
      <div class={styles.Summary}>
        <span class={styles.Avatar}>{initial()}</span>
        <div class={styles.SummaryText}>
          <strong>{config().email}</strong>
          <span class={styles.SummaryLine}>
            <span class={styles.Mono}>{config().url}</span>
            <Show when={insecure()}><span class={styles.InsecureTag}>http, testing only</span></Show>
          </span>
        </div>
        <Show when={usedText()}>
          <div class={styles.Usage}>
            <span>{usedText()}</span>
            <Show when={limitBytes() > 0}>
              <div class={styles.Meter}><div class={styles.MeterFill} style={{ width: usedWidth() }} /></div>
            </Show>
          </div>
        </Show>
      </div>

      <Show
        when={signedIn()}
        fallback={
          <div class={styles.SignedOut}>
            <span>This computer was signed out of this account.</span>
            <Button variant="primary" onClick={() => sync.openAdd(props.cloud.kind, props.cloud.id)}>Sign in again</Button>
          </div>
        }
      >
        <Show when={unowned()}>
          <ClaimCard cloud={props.cloud} onClaimed={claimed} />
        </Show>
        <Show when={admin()}>
          <SegmentedControl value={view()} options={VIEWS} onChange={setView} fill />
        </Show>
        <Show when={serverView()} fallback={<>
        <div class={styles.Section}>
          <div class={styles.SectionHead}>
            <span>Devices</span>
            <span class={styles.SectionNote}>{devicesText()}</span>
          </div>
          <div class={styles.Group}>
            <Show when={!devices.loading} fallback={<div class={styles.Loading}><Spinner size={14} /></div>}>
              <For each={sortedDevices()}>
                {device => (
                  <div class={styles.Device}>
                    <span class={styles.RowIcon}><Laptop size={15} /></span>
                    <div class={styles.RowText}>
                      <span class={styles.RowTitle}>
                        {device.device.name}
                        <Show when={device.current}><span class={styles.Badge}>This computer</span></Show>
                      </span>
                      <span class={styles.RowDetail}>
                        {osName(device.device.os)}, signed in {day(device.createdAt)}
                        <Show when={!device.current}>, last seen {formatAgo(device.lastSeenAt * 1000)}</Show>
                      </span>
                    </div>
                    <Show when={!device.current}>
                      <Button variant="ghost" size="sm" onClick={() => void revoke(device)}>Sign out</Button>
                    </Show>
                  </div>
                )}
              </For>
            </Show>
          </div>
        </div>

        <div class={styles.Section}>
          <div class={styles.SectionHead}>
            <span>Security</span>
            <span class={styles.SectionNote}>{sinceText()}</span>
          </div>
          <div class={styles.Group}>
            <Row icon={Lock} title="Password" detail="Changing it signs out every other device. Nothing is uploaded again." action={toggle("password", "Change")}>
              <Show when={panel() === "password"}>
                <Form lead="Type the current password, then the new one twice.">
                  <PasswordField label="Current password" value={current()} onValue={setCurrent} autofocus />
                  <div class={styles.Pair}>
                    <PasswordField label="New password" value={next()} onValue={setNext} />
                    <PasswordField label="Type it again" value={repeat()} onValue={setRepeat} />
                  </div>
                  <ul class={styles.Rules}>
                    <li classList={{ [styles.Met]: longEnough() }}>At least {MIN_PASSWORD} characters</li>
                    <li classList={{ [styles.Met]: matches() }}>Both match</li>
                  </ul>
                </Form>
              </Show>
            </Row>

            <Row icon={KeyRound} title="Recovery key" detail="The only way back in if the password is forgotten." action={toggle("recovery", "Make a new one")}>
              <Show when={panel() === "recovery"}>
                <Form lead="You get a new key to write down, and the old one stops working right away.">
                  <PasswordField label="Password" value={current()} onValue={setCurrent} autofocus />
                </Form>
              </Show>
            </Row>

            <Row
              icon={ShieldCheck}
              title="Two-step sign-in"
              badge={<span class={styles.Badge} classList={{ [styles.On]: twoStepOn() }}>{twoStepBadge()}</span>}
              detail="Signing in on a new computer also asks for a code from an authenticator app."
              action={<Button variant="subtle" size="sm" active={twoStepOpen()} onClick={() => void openTwoStep()}>{twoStepLabel()}</Button>}
            >
              <Branch>
                <Match when={panel() === "totpOn"}>
                  <Form lead="Scan the code with an authenticator app, then type the 6 digits it shows to finish.">
                    <Show when={setup()} fallback={<div class={styles.Loading}><Spinner size={14} /></div>}>
                      {found => (
                        <div class={styles.TwoStep}>
                          <Show when={found().uri}>{uri => <QrCode value={uri()} size={148} />}</Show>
                          <div class={styles.TwoStepText}>
                            <span class={styles.Step}>Can't scan it? Type this key in the app instead.</span>
                            <div class={styles.Secret}>
                              <span>{found().secret}</span>
                              <Button icon size="sm" tooltip="Copy" onClick={() => void copySensitive(found().secret ?? "", "Key")}>
                                <Copy size={13} />
                              </Button>
                            </div>
                            <Field label="Code from the app">
                              <Input mono value={code()} onValue={setCode} placeholder="123456" autofocus />
                            </Field>
                          </div>
                        </div>
                      )}
                    </Show>
                  </Form>
                </Match>
                <Match when={panel() === "totpOff"}>
                  <Form lead="Signing in will only need the password again.">
                    <PasswordField label="Password" value={current()} onValue={setCurrent} autofocus />
                  </Form>
                </Match>
              </Branch>
            </Row>
          </div>
        </div>

        <div class={styles.Section}>
          <div class={styles.Group}>
            <Row
              icon={TriangleAlert}
              title="Delete account"
              detail="Removes everything stored on the server. Every computer keeps its own copy, but stops syncing."
              danger
              action={<Button variant={deleteVariant()} size="sm" onClick={() => open("delete")}>{deleteLabel()}</Button>}
            >
              <Show when={panel() === "delete"}>
                <Form lead="This can't be undone. Type the password and the account's email to confirm.">
                  <div class={styles.Pair}>
                    <PasswordField label="Password" value={current()} onValue={setCurrent} autofocus />
                    <Field label="Email">
                      <Input value={typedEmail()} onValue={setTypedEmail} placeholder={config().email} />
                    </Field>
                  </div>
                </Form>
              </Show>
            </Row>
          </div>
        </div>
        </>}>
          {me => <ServerAdmin cloud={props.cloud} me={me()} />}
        </Show>
      </Show>
    </div>
  );
}

export default Account;
