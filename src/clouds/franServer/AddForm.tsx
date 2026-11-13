import styles from "./FranServer.module.scss";
import { For, Match, Show, Switch, createEffect, createMemo, createSignal, on, onCleanup } from "solid-js";
import { hostname } from "@tauri-apps/plugin-os";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage, isAppError } from "@core/helpers/errors";
import useSyncState from "@core/states/syncState";
import { ArrowLeft, Check, CircleAlert, Crown, Eye, EyeOff, Lock, Server, TriangleAlert } from "@core/icons";
import { FranServerConfig, FranServerInfo, FranServerLogin } from "@core/types";
import Button from "@core/components/Button/Button";
import Field from "@core/components/Field/Field";
import Input from "@core/components/Input/Input";
import Spinner from "@core/components/Spinner/Spinner";
import Toggle from "@core/components/Switch/Switch";
import { tooltip } from "@core/components/Tooltip/Tooltip";
import SegmentedControl, { SegmentedOption } from "@core/components/SegmentedControl/SegmentedControl";
import type { AddFormProps } from "../index";

type Mode = "signIn" | "create" | "recover";
type ServerCheck = { state: "idle" } | { state: "checking" } | { state: "ok", info: FranServerInfo } | { state: "failed", message: string };

const MIN_PASSWORD = 10;
const CHECK_DELAY_MS = 450;

const TABS: SegmentedOption<Mode>[] = [
  { value: "signIn", label: "Sign in" },
  { value: "create", label: "Create account" },
];

const SIGNUP_TEXT: Record<FranServerInfo["signup"], string> = {
  open: "Anyone can make an account",
  invite: "Accounts need an invite code",
  closed: "Only invited emails can make an account",
};

function AddForm(props: AddFormProps) {
  const sync = useSyncState;
  const saved = createMemo(() => (props.cloud?.config ?? null) as FranServerConfig | null);
  const again = createMemo(() => props.cloud !== null);

  const [step, setStep] = createSignal<"server" | "account">(again() ? "account" : "server");
  const [mode, setMode] = createSignal<Mode>("signIn");
  const [url, setUrl] = createSignal(saved()?.url ?? "");
  const [check, setCheck] = createSignal<ServerCheck>({ state: "idle" });
  const [email, setEmail] = createSignal(saved()?.email ?? "");
  const [password, setPassword] = createSignal("");
  const [repeat, setRepeat] = createSignal("");
  const [shown, setShown] = createSignal(false);
  const [invite, setInvite] = createSignal("");
  const [recoveryKey, setRecoveryKey] = createSignal("");
  const [code, setCode] = createSignal("");
  const [name, setName] = createSignal("");
  const [wantsCode, setWantsCode] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const info = createMemo(() => {
    const current = check();
    return current.state === "ok" ? current.info : null;
  });
  const failed = createMemo(() => {
    const current = check();
    return current.state === "failed" ? current.message : null;
  });
  const host = createMemo(() => url().trim().replace(/^https?:\/\//i, ""));
  const insecure = createMemo(() => /^http:\/\//i.test(url().trim()));
  const [understood, setUnderstood] = createSignal(again());
  const canContinue = createMemo(() => info() !== null && (!insecure() || understood()));
  const setsPassword = createMemo(() => mode() !== "signIn");
  const passwordType = createMemo(() => (shown() ? "text" : "password"));
  const longEnough = createMemo(() => [...password()].length >= MIN_PASSWORD);
  const matches = createMemo(() => repeat() !== "" && repeat() === password());
  const unowned = createMemo(() => !again() && info()?.owned === false);
  // On a server nobody owns, the field takes the setup code, which works whatever the sign-up mode.
  const wantsInvite = createMemo(() => mode() === "create" && (unowned() || info()?.signup !== "open"));
  const needsInvite = createMemo(() => wantsInvite() && info()?.signup !== "open");
  const inviteLabel = createMemo(() => (unowned() ? "Setup code" : "Invite code"));
  const invitePlaceholder = createMemo(() => (unowned() ? "XXXX-XXXX-XXXX" : ""));
  const inviteHint = createMemo(() => {
    if (unowned()) {
      const open = info()?.signup === "open" ? " Leave it empty to join as a regular account instead." : "";
      return `Printed in the server's log each time it starts.${open}`;
    }
    return info()?.signup === "closed" ? "This server only takes emails its admin invited. Ask them for the code." : "Ask the server's admin for one.";
  });
  const tab = createMemo<Mode>(() => (mode() === "create" ? "create" : "signIn"));
  const ready = createMemo(() => {
    if (busy() || email().trim() === "" || password() === "") return false;
    if (wantsCode() && code().trim() === "") return false;
    if (setsPassword() && (!longEnough() || !matches())) return false;
    if (mode() === "recover" && recoveryKey().trim() === "") return false;
    return !(needsInvite() && invite().trim() === "");
  });
  const submitLabel = createMemo(() => {
    if (busy()) return mode() === "create" ? "Creating account" : "Checking password";
    if (mode() === "create") return "Create account";
    if (mode() === "recover") return "Set new password";
    return "Sign in";
  });

  let checkTimer: ReturnType<typeof setTimeout> | undefined;
  let checkRun = 0;
  onCleanup(() => clearTimeout(checkTimer));

  // The address is checked while typing, so a typo shows before the password is typed.
  createEffect(on(url, value => {
    clearTimeout(checkTimer);
    const run = ++checkRun;
    if (again() || value.trim() === "") {
      setCheck({ state: "idle" });
      return;
    }
    setCheck({ state: "checking" });
    checkTimer = setTimeout(() => void runCheck(value, run), CHECK_DELAY_MS);
  }));

  async function runCheck(value: string, run: number) {
    try {
      const found = await safeInvoke("fran_server_info", { url: value });
      if (run === checkRun) setCheck({ state: "ok", info: found });
    } catch (failure) {
      if (run === checkRun) setCheck({ state: "failed", message: errorMessage(failure) });
    }
  }

  function pick(next: Mode) {
    setMode(next);
    setError(null);
    setWantsCode(false);
    setRepeat("");
  }

  function continueToAccount(event: SubmitEvent) {
    event.preventDefault();
    if (!canContinue()) return;
    if (unowned()) setMode("create");
    setStep("account");
  }

  async function login(): Promise<FranServerLogin> {
    const deviceName = await hostname().catch(() => null);
    return { url: url(), email: email(), password: password(), name: props.cloud?.name ?? name(), deviceName: deviceName ?? "" };
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready()) return;
    setBusy(true);
    setError(null);
    try {
      switch (mode()) {
        case "create": {
          const created = await safeInvoke("fran_server_create_account", { login: await login(), invite: invite().trim() || null });
          await sync.load();
          sync.showRecoveryKey(sync.cloud(created.cloudId)?.name ?? "this cloud", created.recoveryKey);
          break;
        }
        case "recover":
          await safeInvoke("fran_server_recover", { login: await login(), recoveryKey: recoveryKey() });
          break;
        default:
          await safeInvoke("fran_server_sign_in", { login: await login(), code: wantsCode() ? code() : null });
      }
      await sync.load();
      props.onDone();
    } catch (failure) {
      if (isAppError(failure) && failure.detail.kind === "syncCodeRequired") {
        setWantsCode(true);
        setError(null);
      } else {
        setError(errorMessage(failure));
      }
    } finally {
      setBusy(false);
    }
  }

  const eye = (
    <Button icon size="sm" tooltip={shown() ? "Hide" : "Show"} onClick={() => setShown(value => !value)}>
      <Show when={shown()} fallback={<Eye size={14} />}><EyeOff size={14} /></Show>
    </Button>
  );

  return (
    <Show
      when={step() === "account"}
      fallback={
        <form class={styles.Form} onSubmit={continueToAccount}>
          <p class={styles.Lead}>
            Everything is encrypted on this computer before it's sent. The server stores data it can't read, and never sees your password.
          </p>
          <Field label="Server address" hint="Fran Cloud, or a server you or your team runs. It has to use https.">
            <Input
              mono
              value={url()}
              onValue={setUrl}
              placeholder="sync.example.com"
              autofocus
              before={<Server size={14} />}
              after={
                <Switch>
                  <Match when={check().state === "checking"}><span class={styles.InputState}><Spinner size={14} /></span></Match>
                  <Match when={check().state === "ok"}><span class={`${styles.InputState} ${styles.Good}`}><Check size={14} /></span></Match>
                  <Match when={check().state === "failed"}><span class={`${styles.InputState} ${styles.Bad}`}><CircleAlert size={14} /></span></Match>
                </Switch>
              }
            />
          </Field>
          <Switch>
            <Match when={info()}>
              {found => (
                <div class={styles.ServerCard}>
                  <span class={styles.ServerIcon}><Server size={16} /></span>
                  <span class={styles.ServerText}>
                    <strong>{host()}</strong>
                    <span>Fran sync server {found().version}. {unowned() ? "No owner yet." : `${SIGNUP_TEXT[found().signup]}.`}</span>
                  </span>
                </div>
              )}
            </Match>
            <Match when={failed()}>
              {message => (
                <div class={styles.Problem}>
                  <CircleAlert size={14} />
                  <span>{message()}</span>
                </div>
              )}
            </Match>
          </Switch>
          <Show when={insecure()}>
            <div class={styles.Insecure}>
              <div class={styles.InsecureHead}>
                <TriangleAlert size={18} />
                <strong>Plain http is for testing only</strong>
              </div>
              <p>
                Your items stay end-to-end encrypted, but the connection itself isn't. Anyone on the network between you and this server can read
                your sign-in and session token, then sign in as you, see how much you store, and delete it. They can also pose as the server.
              </p>
              <p>Only use it for a test server on your own computer or network, with an account you don't mind losing. Use https for anything real.</p>
              <Toggle checked={understood()} onChange={setUnderstood} label="I understand, this is only for testing" />
            </div>
          </Show>
          <div class={styles.Actions}>
            <Button variant="subtle" onClick={props.onCancel}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={!canContinue()}>Continue</Button>
          </div>
        </form>
      }
    >
      <form class={styles.Form} onSubmit={submit}>
        <div class={styles.ServerBar}>
          <span class={styles.ServerIcon}><Server size={14} /></span>
          <span class={styles.ServerBarText}>{host()}</span>
          <Show when={insecure()}>
            <span class={styles.InsecureTag}>http, testing only</span>
          </Show>
          <Show when={!again()}>
            <Button variant="ghost" size="sm" onClick={() => setStep("server")}>
              <ArrowLeft size={13} />
              Change
            </Button>
          </Show>
        </div>

        <Show when={unowned()}>
          <div class={styles.Unowned}>
            <Crown size={15} />
            <span>
              <strong>Nobody owns this server yet.</strong> Create the first account with the setup code from the server's log and it's yours: you
              decide who else gets in and how much they can store.
            </span>
          </div>
        </Show>
        <Show when={!again() && mode() !== "recover"}>
          <SegmentedControl value={tab()} options={TABS} onChange={pick} fill />
        </Show>
        <Show when={mode() === "recover"}>
          <div class={styles.RecoverHead}>
            <strong>Use your recovery key</strong>
            <span>It replaces a forgotten password. Your data stays, and every other computer is signed out.</span>
          </div>
        </Show>

        <Field label="Email">
          <Input value={email()} onValue={setEmail} placeholder="you@example.com" disabled={again()} autofocus={!again()} />
        </Field>
        <Show when={mode() === "recover"}>
          <Field label="Recovery key" hint="The 32 letters and digits shown when the account was made. Spaces and case don't matter.">
            <Input mono value={recoveryKey()} onValue={setRecoveryKey} placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" />
          </Field>
        </Show>
        <Field label={mode() === "recover" ? "New password" : "Password"}>
          <Input type={passwordType()} value={password()} onValue={setPassword} autofocus={again()} before={<Lock size={14} />} after={eye} />
        </Field>
        <Show when={mode() === "signIn" && !again()}>
          <button type="button" class={styles.Link} onClick={() => pick("recover")}>Forgot the password? Use the recovery key</button>
        </Show>
        <Show when={setsPassword()}>
          <Field label="Type it again">
            <Input type={passwordType()} value={repeat()} onValue={setRepeat} before={<Lock size={14} />} />
          </Field>
          <ul class={styles.Rules}>
            <For each={[{ ok: longEnough, text: `At least ${MIN_PASSWORD} characters` }, { ok: matches, text: "Both match" }]}>
              {rule => (
                <li classList={{ [styles.Met]: rule.ok() }}>
                  <Check size={12} />
                  {rule.text}
                </li>
              )}
            </For>
          </ul>
        </Show>
        <Show when={wantsInvite()}>
          <Field label={inviteLabel()} hint={inviteHint()}>
            <Input mono value={invite()} onValue={setInvite} placeholder={invitePlaceholder()} />
          </Field>
        </Show>
        <Show when={wantsCode()}>
          <Field label="Two-step code" hint="The 6 digits from your authenticator app.">
            <Input mono value={code()} onValue={setCode} placeholder="123456" autofocus />
          </Field>
        </Show>

        <Show when={!again()}>
          <Field label="Name" hint="Optional. Shown wherever you pick where something syncs, like Personal or Work.">
            <Input value={name()} onValue={setName} placeholder={host()} />
          </Field>
        </Show>

        <Show when={mode() === "create"}>
          <div class={styles.Warning}>
            <CircleAlert size={14} />
            <span>Nobody can reset this password, not even the server. The recovery key shown next is the only other way back in, so keep it somewhere safe.</span>
          </div>
        </Show>
        <Show when={error()}>
          {text => (
            <div class={styles.Problem}>
              <CircleAlert size={14} />
              <span>{text()}</span>
            </div>
          )}
        </Show>

        <div class={styles.Actions}>
          <Show when={mode() === "recover" && !busy()}>
            <Button variant="ghost" onClick={() => pick("signIn")}>Back to sign in</Button>
          </Show>
          <Show when={busy()}>
            <span class={styles.Working} ref={element => tooltip(element, () => "Your password is stretched slowly on purpose, so guessing it is slow too.")}>
              <Spinner size={13} />
              Takes a second on purpose
            </span>
          </Show>
          <div class={styles.Grow} />
          <Button variant="subtle" onClick={props.onCancel} disabled={busy()}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!ready()}>{submitLabel()}</Button>
        </div>
      </form>
    </Show>
  );
}

export default AddForm;
