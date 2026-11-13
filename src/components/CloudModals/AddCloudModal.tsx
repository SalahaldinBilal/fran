import styles from "./CloudModals.module.scss";
import { For, Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { Dynamic } from "solid-js/web";
import { ArrowLeft, ChevronRight } from "@core/icons";
import { cloudModule, cloudModules } from "@core/clouds";
import useSyncState from "@core/states/syncState";
import { CloudKind } from "@core/types";
import Modal from "../Modal/Modal";
import Button from "../Button/Button";

function AddCloudModal() {
  const sync = useSyncState;
  const [kind, setKind] = createSignal<CloudKind | null>(null);
  // Set when the kind was picked in this modal, so there's somewhere to go back to.
  const [picked, setPicked] = createSignal(false);

  const again = createMemo(() => sync.cloud(sync.addRequest()?.cloudId) ?? null);
  const module = createMemo(() => {
    const chosen = kind();
    return chosen ? cloudModule(chosen) : null;
  });
  const titleText = createMemo(() => {
    if (again()) return `Sign in to ${again()?.name}`;
    return module() ? `Connect ${module()?.label}` : "Add a cloud";
  });
  const subtitle = createMemo(() => (module() || again() ? undefined : "Pick where your items should sync to. You can add more later."));

  createEffect(on(sync.addRequest, request => {
    if (!request) return;
    setPicked(false);
    setKind(request.kind ?? (cloudModules.length === 1 ? cloudModules[0].kind : null));
  }));

  function choose(next: CloudKind) {
    setPicked(true);
    setKind(next);
  }

  function back() {
    setPicked(false);
    setKind(null);
  }

  return (
    <Modal
      show={sync.addRequest() !== null}
      onHide={sync.closeAdd}
      title={
        <span class={styles.Title}>
          <Show when={picked() && !again()}>
            <Button icon size="sm" tooltip="Back" onClick={back}>
              <ArrowLeft size={15} />
            </Button>
          </Show>
          {titleText()}
        </span>
      }
      subtitle={subtitle()}
      width={460}
    >
      <Show
        when={module()}
        fallback={
          <div class={styles.Kinds}>
            <For each={cloudModules}>
              {option => (
                <button type="button" class={styles.Kind} onClick={() => choose(option.kind)}>
                  <span class={styles.KindIcon}>
                    <Dynamic component={option.icon} size={18} />
                  </span>
                  <span class={styles.KindText}>
                    <strong>{option.label}</strong>
                    <span>{option.description}</span>
                  </span>
                  <ChevronRight size={16} class={styles.KindArrow} />
                </button>
              )}
            </For>
          </div>
        }
      >
        {found => <Dynamic component={found().AddForm} cloud={again()} onDone={sync.closeAdd} onCancel={sync.closeAdd} />}
      </Show>
    </Modal>
  );
}

export default AddCloudModal;
