import styles from "./Agents.module.scss";
import { Show, createMemo } from "solid-js";
import { Activity } from "@core/icons";
import { agentColor, agentInitial } from "./agentText";

export type AgentMarkProps = {
  // Null marks everything at once instead of one agent.
  agent: string | null,
  dim?: boolean,
};

function AgentMark(props: AgentMarkProps) {
  const color = createMemo(() => (props.agent === null ? undefined : agentColor(props.agent)));
  const initial = createMemo(() => (props.agent ? agentInitial(props.agent) : ""));

  return (
    <span
      class={[styles.AgentMark, { [styles.All]: props.agent === null, [styles.Dim]: props.dim ?? false }]}
      style={{ "--mark": color() }}
    >
      <Show when={props.agent} fallback={<Activity size={14} />}>
        {initial()}
      </Show>
    </span>
  );
}

export default AgentMark;
