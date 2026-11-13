import styles from "./Doppler.module.scss";
import { Show, createMemo } from "solid-js";
import useSyncState from "@core/states/syncState";
import useSecretsState from "@core/states/secretsState";
import { plural } from "@core/helpers";
import { Cloud, DopplerConfig } from "@core/types";
import Button from "@core/components/Button/Button";

function Account(props: { cloud: Cloud }) {
  const sync = useSyncState;
  const config = createMemo(() => props.cloud.config as DopplerConfig);
  const linked = createMemo(() => useSecretsState.secrets.filter(secret => secret.link?.cloud === props.cloud.identity).length);
  const readOnly = createMemo(() => props.cloud.status.problems.some(problem => problem.reason === "readOnly"));
  const tokenLabel = createMemo(() => (props.cloud.status.signedOut ? "Enter a new token" : "Replace token"));
  const tokenVariant = createMemo(() => (props.cloud.status.signedOut ? "primary" : "subtle"));

  return (
    <div class={styles.Account}>
      <div class={styles.Facts}>
        <span>Project <strong>{config().project}</strong></span>
        <span>Config <strong>{config().config}</strong></span>
        <span>{plural(linked(), "linked secret")}</span>
        <Show when={readOnly()}><span>This token can only read</span></Show>
      </div>
      <div class={styles.Buttons}>
        <Button variant={tokenVariant()} onClick={() => sync.openAdd(props.cloud.kind, props.cloud.id)}>{tokenLabel()}</Button>
      </div>
      <p class={styles.Hint}>Fran only reads the secrets you linked, and checks them when it starts, every 5 minutes and after a failed connect.</p>
    </div>
  );
}

export default Account;
