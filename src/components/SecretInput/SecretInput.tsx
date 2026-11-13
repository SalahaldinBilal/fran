import styles from "./SecretInput.module.scss";
import { Show, createMemo, splitProps } from "solid-js";
import { KeyRound, X } from "@core/icons";
import Input, { InputProps } from "../Input/Input";
import Button from "../Button/Button";
import { tooltip } from "../Tooltip/Tooltip";
import { SecretRefsEditor, pickSecret } from "@core/helpers/secretRefs";
import useSecretsState from "@core/states/secretsState";

// What a field shows while a named secret fills it: the secret's name, never its value.
export function SecretChip(props: { secretId: string, onClear: () => void, class?: string }) {
  const secret = createMemo(() => useSecretsState.find(props.secretId));
  const name = createMemo(() => secret()?.name ?? "Deleted secret");

  return (
    <div
      class={`${styles.Chip} ${props.class ?? ""}`}
      classList={{ [styles.Missing]: !secret() }}
      ref={element => tooltip(element, () => `Filled from the secret ${name()} when connecting`)}
    >
      <KeyRound size={14} />
      <span class={styles.Name}>{name()}</span>
      <Button icon size="sm" tooltip="Type a value instead" onClick={props.onClear}>
        <X size={13} />
      </Button>
    </div>
  );
}

export type SecretInputProps = InputProps & {
  // The field's path in the saved item, like `host`.
  path: string,
  // Left out where the item can't take secrets, and the field is then a plain input.
  refs?: SecretRefsEditor,
};

// An Input that can take its value from a named secret instead.
function SecretInput(props: SecretInputProps) {
  const [own, input] = splitProps(props, ["path", "refs", "after"]);
  const secretId = createMemo(() => own.refs?.get(own.path));
  const canPick = createMemo(() => own.refs !== undefined && !input.disabled && !input.readOnly);

  return (
    <Show
      when={secretId()}
      fallback={
        <Input
          {...input}
          after={
            <>
              {own.after}
              <Show when={canPick()}>
                <Button
                  icon
                  size="sm"
                  tooltip="Use a secret"
                  onClick={event => pickSecret(event, id => own.refs?.set(own.path, id))}
                >
                  <KeyRound size={13} />
                </Button>
              </Show>
            </>
          }
        />
      }
    >
      {id => <SecretChip secretId={id()} class={input.class} onClear={() => own.refs?.set(own.path, null)} />}
    </Show>
  );
}

export default SecretInput;
