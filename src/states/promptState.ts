import { createRoot, createSignal } from "solid-js";
import { ErrorDetail, SecretSlot } from "@core/types";

export type UnknownHostKey = Extract<ErrorDetail, { kind: "unknownHostKey" }>;
export type ChangedHostKey = Extract<ErrorDetail, { kind: "hostKeyChanged" }>;

export type SecretsAnswer = { values: Record<string, string>, save: boolean };

type SecretsRequest = {
  connectionName: string,
  slots: SecretSlot[],
  canSave: boolean,
  title: string,
  submitLabel: string,
  resolve: (answer: SecretsAnswer | null) => void,
};

export type SecretsPromptText = { title?: string, submitLabel?: string };

type HostKeyRequest = {
  detail: UnknownHostKey,
  resolve: (trusted: boolean) => void,
};

// Resolves with the host name the user typed, or null.
type ChangedKeyRequest = {
  detail: ChangedHostKey,
  resolve: (typedHost: string | null) => void,
};

export type ConfirmOptions = {
  title: string,
  message: string,
  confirmLabel: string,
  danger?: boolean,
};

type ConfirmRequest = ConfirmOptions & { resolve: (confirmed: boolean) => void };

export type TextPromptOptions = {
  title: string,
  label: string,
  initial: string,
  confirmLabel: string,
};

type TextRequest = TextPromptOptions & { resolve: (value: string | null) => void };

function usePromptStateInner() {
  const [secretsRequest, setSecretsRequest] = createSignal<SecretsRequest | null>(null);
  const [hostKeyRequest, setHostKeyRequest] = createSignal<HostKeyRequest | null>(null);
  const [changedKeyRequest, setChangedKeyRequest] = createSignal<ChangedKeyRequest | null>(null);
  const [confirmRequest, setConfirmRequest] = createSignal<ConfirmRequest | null>(null);
  const [textRequest, setTextRequest] = createSignal<TextRequest | null>(null);

  function askForText(options: TextPromptOptions): Promise<string | null> {
    return new Promise(resolve => {
      setTextRequest({
        ...options,
        resolve: value => {
          setTextRequest(null);
          resolve(value);
        },
      });
    });
  }

  function confirm(options: ConfirmOptions): Promise<boolean> {
    return new Promise(resolve => {
      setConfirmRequest({
        ...options,
        resolve: confirmed => {
          setConfirmRequest(null);
          resolve(confirmed);
        },
      });
    });
  }

  function askForSecrets(connectionName: string, slots: SecretSlot[], canSave: boolean, text: SecretsPromptText = {}): Promise<SecretsAnswer | null> {
    return new Promise(resolve => {
      setSecretsRequest({
        connectionName,
        slots,
        canSave,
        title: text.title ?? "Credentials needed",
        submitLabel: text.submitLabel ?? "Connect",
        resolve: answer => {
          setSecretsRequest(null);
          resolve(answer);
        },
      });
    });
  }

  function askToTrustHostKey(detail: UnknownHostKey): Promise<boolean> {
    return new Promise(resolve => {
      setHostKeyRequest({
        detail,
        resolve: trusted => {
          setHostKeyRequest(null);
          resolve(trusted);
        },
      });
    });
  }

  function askToReplaceHostKey(detail: ChangedHostKey): Promise<string | null> {
    return new Promise(resolve => {
      setChangedKeyRequest({
        detail,
        resolve: typedHost => {
          setChangedKeyRequest(null);
          resolve(typedHost);
        },
      });
    });
  }

  return {
    secretsRequest,
    hostKeyRequest,
    changedKeyRequest,
    confirmRequest,
    textRequest,
    askForSecrets,
    askToTrustHostKey,
    askToReplaceHostKey,
    confirm,
    askForText,
  };
}

const usePromptState = createRoot(usePromptStateInner);
export default usePromptState;
