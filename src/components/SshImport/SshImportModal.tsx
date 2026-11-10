import styles from "./SshImport.module.scss";
import { Match, Switch, createEffect, createMemo, createSignal, on } from "solid-js";
import { CircleAlert, FileX } from "lucide-solid";
import useSshImportState from "@core/states/sshImportState";
import useToastState from "@core/states/toastState";
import { createSshImport } from "@core/helpers/sshImport";
import { errorMessage } from "@core/helpers/errors";
import { plural } from "@core/helpers";
import Modal from "@core/components/Modal/Modal";
import Button from "@core/components/Button/Button";
import EmptyState from "@core/components/EmptyState/EmptyState";
import Spinner from "@core/components/Spinner/Spinner";
import SshImportList from "./SshImportList";

function SshImportModal() {
  const dialog = useSshImportState;
  const { pushError } = useToastState;
  const importer = createSshImport();
  const [running, setRunning] = createSignal(false);

  createEffect(on(dialog.shown, shown => {
    if (shown) void importer.load();
  }));

  const count = createMemo(() => importer.picked().size);
  const importLabel = createMemo(() => `Import ${plural(count(), "host")}`);

  async function run() {
    setRunning(true);
    try {
      if (await importer.run()) dialog.close();
    } catch (error) {
      pushError(error);
    } finally {
      setRunning(false);
    }
  }

  return (
    <Modal
      show={dialog.shown()}
      onHide={dialog.close}
      title="Import SSH hosts"
      subtitle={importer.preview()?.path}
      width={580}
      footer={
        <>
          <Button variant="subtle" onClick={dialog.close}>Cancel</Button>
          <Button variant="primary" disabled={count() === 0 || running()} onClick={run}>{importLabel()}</Button>
        </>
      }
    >
      <Switch>
        <Match when={importer.loading()}>
          <div class={styles.Center}><Spinner size={18} /></div>
        </Match>
        <Match when={importer.error()}>
          <EmptyState tone="danger" icon={CircleAlert} title="The config couldn't be read" description={errorMessage(importer.error())} />
        </Match>
        <Match when={importer.preview() && !importer.preview()!.found}>
          <EmptyState icon={FileX} title="No SSH config" description={`There's no file at ${importer.preview()!.path}.`} />
        </Match>
        <Match when={importer.preview()}>
          {preview => (
            <div class={styles.Body}>
              <p class={styles.Note}>
                ProxyJump becomes jump hosts. IdentityFile becomes a key that keeps using the file, nothing is copied.
                Nothing is written back to <code>~/.ssh/config</code>.
              </p>
              <SshImportList
                candidates={preview().candidates}
                skippedPatterns={preview().skippedPatterns}
                picked={importer.picked()}
                onToggle={importer.toggle}
              />
            </div>
          )}
        </Match>
      </Switch>
    </Modal>
  );
}

export default SshImportModal;
