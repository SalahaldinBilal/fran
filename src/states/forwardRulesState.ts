import { createRoot, createSignal } from "solid-js";
import { createStore, produce, reconcile } from "solid-js/store";
import { listen } from "@tauri-apps/api/event";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { withConnectPrompts } from "@core/helpers/connectFlow";
import { ForwardRule, RuleForwardInfo, RuleStopped } from "@core/types";
import useToastState from "./toastState";
import useSshState from "./sshState";

type RuleEditorRequest = { rule: ForwardRule | null, hostId?: string };

function useForwardRulesStateInner() {
  const { pushToast, pushError } = useToastState;
  const [running, setRunning] = createStore<Record<string, RuleForwardInfo>>({});
  const [busy, setBusy] = createStore<Record<string, boolean>>({});
  const [editorRequest, setEditorRequest] = createSignal<RuleEditorRequest | null>(null);

  async function load() {
    const list = await safeInvoke("list_running_forward_rules");
    setRunning(reconcile(Object.fromEntries(list.map(info => [info.ruleId, info]))));
  }

  function status(ruleId: string): RuleForwardInfo | undefined {
    return running[ruleId];
  }

  async function start(rule: ForwardRule) {
    if (busy[rule.id]) return;
    setBusy(rule.id, true);
    try {
      const label = useSshState.host(rule.hostId)?.label ?? rule.label;
      const info = await withConnectPrompts(
        { connectionId: null, connectionName: label },
        secrets => safeInvoke("start_forward_rule", { id: rule.id, secrets }),
      );
      if (info) setRunning(info.ruleId, info);
    } catch (error) {
      pushError(error);
    } finally {
      setBusy(rule.id, false);
    }
  }

  async function stop(ruleId: string) {
    try {
      await safeInvoke("stop_forward_rule", { id: ruleId });
      setRunning(produce(all => { delete all[ruleId]; }));
    } catch (error) {
      pushError(error);
    }
  }

  async function toggle(rule: ForwardRule) {
    if (running[rule.id]) await stop(rule.id);
    else await start(rule);
  }

  listen<RuleStopped>("forward-rule-stopped", event => {
    const { ruleId, reason } = event.payload;
    setRunning(produce(all => { delete all[ruleId]; }));
    const label = useSshState.forward(ruleId)?.label ?? "A port forward";
    pushToast(`${label} stopped. ${reason ?? "The SSH connection closed."}`, "error");
  });

  void load().catch(pushError);

  return {
    running,
    busy,
    status,
    start,
    stop,
    toggle,
    editorRequest,
    openEditor: (rule: ForwardRule | null, hostId?: string) => setEditorRequest({ rule, hostId }),
    closeEditor: () => setEditorRequest(null),
  };
}

const useForwardRulesState = createRoot(useForwardRulesStateInner);
export default useForwardRulesState;
