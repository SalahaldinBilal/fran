import styles from "./QrCode.module.scss";
import { createMemo } from "solid-js";
import { encode } from "uqr";

export type QrCodeProps = {
  value: string,
  size?: number,
};

// Always dark on white, whatever the theme, since phone cameras read that most reliably.
function QrCode(props: QrCodeProps) {
  const code = createMemo(() => {
    const encoded = encode(props.value, { ecc: "M", border: 2 });
    let path = "";
    encoded.data.forEach((row, y) => row.forEach((dark, x) => {
      if (dark) path += `M${x} ${y}h1v1h-1z`;
    }));
    return { size: encoded.size, path };
  });
  const box = createMemo(() => `0 0 ${code().size} ${code().size}`);
  const pixels = createMemo(() => `${props.size ?? 168}px`);

  return (
    <svg class={styles.Code} viewBox={box()} width={pixels()} height={pixels()} shape-rendering="crispEdges" role="img" aria-label="QR code">
      <rect width="100%" height="100%" fill="#fff" />
      <path d={code().path} fill="#111" />
    </svg>
  );
}

export default QrCode;
