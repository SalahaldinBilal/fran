import styles from "./Views.module.scss";
import { For } from "solid-js";
import { Copy } from "@core/icons";
import { copyText } from "@core/helpers/clipboard";
import { tooltip } from "../../Tooltip/Tooltip";

export type Fact = { label: string, value: string, plain?: boolean };

function Facts(props: { items: Fact[] }) {
  return (
    <dl class={styles.Facts}>
      <For each={props.items}>
        {fact => (
          <div class={styles.Fact}>
            <dt>{fact.label}</dt>
            <dd class={{ [styles.Plain]: fact.plain ?? false }}>{fact.value}</dd>
            <button
              class={styles.CopyFact}
              ref={tooltip(() => `Copy ${fact.label.toLowerCase()}`)}
              onClick={() => copyText(fact.value, fact.label.toLowerCase())}
            >
              <Copy size={12} />
            </button>
          </div>
        )}
      </For>
    </dl>
  );
}

export default Facts;
