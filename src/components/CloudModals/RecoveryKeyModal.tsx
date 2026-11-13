import styles from "./CloudModals.module.scss";
import { createEffect, createMemo, createSignal, on } from "solid-js";
import { Copy } from "@core/icons";
import useSyncState from "@core/states/syncState";
import { copySensitive } from "@core/helpers/clipboard";
import Modal from "../Modal/Modal";
import Button from "../Button/Button";
import Note from "../Note/Note";
import Switch from "../Switch/Switch";

// The one time a recovery key is on screen. Closing needs the box ticked, since it can't be shown again.
function RecoveryKeyModal() {
  const sync = useSyncState;
  const [saved, setSaved] = createSignal(false);

  const shown = createMemo(() => sync.recoveryKey());
  const title = createMemo(() => `Recovery key for ${shown()?.cloudName ?? "this cloud"}`);

  createEffect(on(shown, () => setSaved(false)));

  return (
    <Modal
      show={shown() !== null}
      title={title()}
      width={500}
      dismissible={false}
      footer={
        <>
          <Button variant="subtle" onClick={() => void copySensitive(shown()?.key ?? "", "the recovery key")}>
            <Copy size={14} />
            Copy
          </Button>
          <Button variant="primary" disabled={!saved()} onClick={sync.closeRecoveryKey}>Done</Button>
        </>
      }
    >
      <div class={styles.Recovery}>
        <p class={styles.Lead}>
          Write this down or put it in a password manager. If you forget the password, it's the only way back to what this cloud holds.
        </p>
        <div class={styles.Key}>{shown()?.key}</div>
        <Note tone="warning">Fran doesn't keep it and the server never had it. It won't be shown again.</Note>
        <div class={styles.Check}>
          <Switch checked={saved()} onChange={setSaved} label="I saved it somewhere safe" />
        </div>
      </div>
    </Modal>
  );
}

export default RecoveryKeyModal;
