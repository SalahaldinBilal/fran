import { createRoot, createSignal, createStore } from "solid-js";
import { ConnectionProfile, PortForwardInfo } from "@core/types";
import { immediateWrite } from "@core/helpers/immediateWrite";
import { safeInvoke } from "@core/helpers/safeInvoke";
import { withConnectPrompts } from "@core/helpers/connectFlow";
import useConnectionsState from "@core/states/connectionsState";

function usePortForwardStateInner() {
  const [forwards, writeForwards] = createStore<Record<string, PortForwardInfo>>({});
  const setForwards = immediateWrite(writeForwards);
  const [dialogProfile, setDialogProfile] = createSignal<ConnectionProfile | null>(null);

  async function load() {
    const list = await safeInvoke("list_port_forwards");
    setForwards(state => {
      for (const info of list) state[info.connectionId] = info;
    });
  }

  function active(connectionId: string): PortForwardInfo | undefined {
    return forwards[connectionId];
  }

  function all(): PortForwardInfo[] {
    return Object.values(forwards);
  }

  // Null means the user cancelled a credential or host key prompt.
  async function start(profile: ConnectionProfile, localPort: number, allNetworks: boolean): Promise<PortForwardInfo | null> {
    const info = await withConnectPrompts(
      { connectionId: profile.id, connectionName: profile.name },
      secrets => safeInvoke("start_port_forward", { connectionId: profile.id, localPort, allNetworks, secrets }),
    );
    if (info) {
      setForwards(state => {
        state[info.connectionId] = info;
      });
      if (profile.forwardPort !== localPort || profile.forwardAllNetworks !== allNetworks) {
        await useConnectionsState.save({ ...profile, forwardPort: localPort, forwardAllNetworks: allNetworks });
      }
    }
    return info;
  }

  async function stop(connectionId: string) {
    await safeInvoke("stop_port_forward", { connectionId });
    setForwards(all => { delete all[connectionId]; });
  }

  function openDialog(profile: ConnectionProfile) {
    setDialogProfile(profile);
  }

  function closeDialog() {
    setDialogProfile(null);
  }

  void load();

  return { active, all, start, stop, dialogProfile, openDialog, closeDialog };
}

const usePortForwardState = createRoot(usePortForwardStateInner);
export default usePortForwardState;
