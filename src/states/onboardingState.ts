import { createMemo, createRoot, createSignal } from "solid-js";
import { Features, ONBOARDING_VERSION } from "./settingsState";
import useSettingsState from "./settingsState";
import useConnectionsState from "./connectionsState";
import { setFeatures } from "@core/helpers/features";

function useOnboardingStateInner() {
  const settings = useSettingsState;
  const [replaying, setReplaying] = createSignal(false);

  // A settings file that failed to load isn't overwritten, so the welcome screen waits for a good one.
  const shown = createMemo(() =>
    settings.loaded() && !settings.loadError() && useConnectionsState.loaded()
    && (replaying() || settings.settings.onboardingVersion < ONBOARDING_VERSION),
  );

  async function finish(features: Features) {
    if (await setFeatures(features, { onboardingVersion: ONBOARDING_VERSION })) setReplaying(false);
  }

  return { shown, replaying, showAgain: () => setReplaying(true), cancel: () => setReplaying(false), finish };
}

const useOnboardingState = createRoot(useOnboardingStateInner);
export default useOnboardingState;
