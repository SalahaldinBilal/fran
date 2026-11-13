import styles from "./Doppler.module.scss";
import { Match, Show, Switch as Branch, createMemo, createSignal } from "solid-js";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { errorMessage } from "@core/helpers/errors";
import useSyncState from "@core/states/syncState";
import { DopplerConfig, DopplerTokenInfo } from "@core/types";
import Button from "@core/components/Button/Button";
import Field from "@core/components/Field/Field";
import Input from "@core/components/Input/Input";
import Select, { SelectItem } from "@core/components/Select/Select";
import type { AddFormProps } from "../index";

function AddForm(props: AddFormProps) {
  const sync = useSyncState;
  const saved = createMemo(() => (props.cloud?.config ?? null) as DopplerConfig | null);

  const [token, setToken] = createSignal("");
  const [info, setInfo] = createSignal<DopplerTokenInfo | null>(null);
  const [project, setProject] = createSignal("");
  const [config, setConfig] = createSignal("");
  const [configs, setConfigs] = createSignal<string[]>([]);
  const [name, setName] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const again = createMemo(() => props.cloud !== null);
  // Step two only exists for a token that isn't tied to one config.
  const picking = createMemo(() => !again() && info() !== null && info()?.project === null);
  const listed = createMemo(() => (info()?.projects.length ?? 0) > 0);
  const projectItems = createMemo<SelectItem<string>[]>(() => (info()?.projects ?? []).map(found => ({ value: found.slug, label: found.name || found.slug })));
  const configItems = createMemo<SelectItem<string>[]>(() => configs().map(found => ({ value: found, label: found })));
  const ready = createMemo(() => {
    if (busy() || token().trim() === "") return false;
    return !picking() || (project().trim() !== "" && config().trim() !== "");
  });
  const submitLabel = createMemo(() => {
    if (busy()) return "Checking";
    if (again()) return "Save token";
    return picking() || info()?.project ? "Add" : "Continue";
  });

  function changeToken(value: string) {
    setToken(value);
    setInfo(null);
    setError(null);
  }

  async function pickProject(slug: string) {
    setProject(slug);
    setConfig("");
    setConfigs([]);
    setError(null);
    try {
      setConfigs(await safeInvoke("doppler_configs", { token: token(), project: slug }));
    } catch (failure) {
      setError(errorMessage(failure));
    }
  }

  async function add(projectName: string, configName: string) {
    await safeInvoke("doppler_add", { token: token(), project: projectName, config: configName, name: name() });
    await sync.load();
    props.onDone();
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready()) return;
    setBusy(true);
    setError(null);
    try {
      const cloud = props.cloud;
      if (cloud) {
        await safeInvoke("doppler_set_token", { cloudId: cloud.id, token: token() });
        await sync.load();
        props.onDone();
      } else if (picking()) {
        await add(project(), config());
      } else {
        const found = await safeInvoke("doppler_check_token", { token: token() });
        setInfo(found);
        if (found.project !== null && found.config !== null) await add(found.project, found.config);
      }
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form class={styles.Form} onSubmit={submit}>
      <Show when={saved()}>
        {found => <p class={styles.Hint}>A new token for {found().project} / {found().config}.</p>}
      </Show>
      <Field label="Token" hint="A service token, personal token or service account token from Doppler. It's kept in the vault.">
        <Input mono type="password" value={token()} onValue={changeToken} placeholder="dp.st..." autofocus />
      </Field>
      <Show when={picking()}>
        <Branch>
          <Match when={listed()}>
            <Field label="Project">
              <Select value={project()} items={projectItems()} onChange={slug => void pickProject(slug)} placeholder="Pick a project" />
            </Field>
            <Field label="Config">
              <Select value={config()} items={configItems()} onChange={setConfig} placeholder="Pick a config" disabled={configs().length === 0} />
            </Field>
          </Match>
          <Match when={!listed()}>
            <Field label="Project" hint="This token can't list projects, so type the names as Doppler shows them.">
              <Input mono value={project()} onValue={setProject} placeholder="backend" />
            </Field>
            <Field label="Config">
              <Input mono value={config()} onValue={setConfig} placeholder="prd" />
            </Field>
          </Match>
        </Branch>
      </Show>
      <Show when={!again()}>
        <Field label="Name in Fran" hint="Optional. Shown where you pick where a secret is stored.">
          <Input value={name()} onValue={setName} placeholder="Doppler prd" />
        </Field>
      </Show>
      <Show when={error()}>
        {text => <p class={styles.Error}>{text()}</p>}
      </Show>
      <div class={styles.Actions}>
        <Button variant="subtle" onClick={props.onCancel}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={!ready()}>{submitLabel()}</Button>
      </div>
      <p class={styles.Hint}>One Doppler cloud is one project and config. Add another one for another config.</p>
    </form>
  );
}

export default AddForm;
