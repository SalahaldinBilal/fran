import styles from "./RoutePreview.module.scss";
import { For, Show } from "solid-js";
import { ChevronRight, Database, Globe, Monitor, Server, Shield } from "@core/icons";
import { Proxy, SshHost, VpnProfile } from "@core/types";

export type RoutePreviewProps = {
  hosts: SshHost[],
  proxy?: Proxy,
  vpn?: VpnProfile,
  // A database behind the last host, for connections that tunnel through it.
  database?: string,
};

function Arrow() {
  return <ChevronRight size={12} class={styles.Arrow} />;
}

function RoutePreview(props: RoutePreviewProps) {
  return (
    <div class={styles.Route}>
      <span class={`${styles.Hop} ${styles.Me}`}><Monitor size={12} />This computer</span>
      <Show when={props.vpn}>
        {vpn => (
          <>
            <Arrow />
            <span
              class={styles.Hop}
              classList={{ [styles.Colored]: vpn().color !== null }}
              style={{ "--hop-color": vpn().color ?? undefined }}
            >
              <Shield size={12} />
              {vpn().label}
            </span>
          </>
        )}
      </Show>
      <Show when={props.proxy}>
        {proxy => (
          <>
            <Arrow />
            <span class={`${styles.Hop} ${styles.Proxy}`}><Globe size={12} />{proxy().label}</span>
          </>
        )}
      </Show>
      <For each={props.hosts}>
        {(host, index) => (
          <>
            <Arrow />
            <span
              class={styles.Hop}
              classList={{ [styles.End]: !props.database && index() === props.hosts.length - 1 }}
            >
              <Server size={12} />
              {host.label}
            </span>
          </>
        )}
      </For>
      <Show when={props.database}>
        {database => (
          <>
            <Arrow />
            <span class={`${styles.Hop} ${styles.Database}`}><Database size={12} />{database()}</span>
          </>
        )}
      </Show>
    </div>
  );
}

export default RoutePreview;
