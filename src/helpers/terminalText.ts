// Escape sequences: CSI (colors, cursor moves), OSC (titles, links), DCS and the short two-byte ones.
const ESCAPES = /\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[P^_][^\x1b]*\x1b\\|\x1b[()][A-Za-z0-9]|\x1b[@-Z\\-_]/g;

function lineText(line: string): string {
  // A carriage return rewrites the line, so the last part that has text is what was on screen.
  const parts = line.split("\r");
  let text = [...parts].reverse().find(part => part !== "") ?? "";
  while (text.includes("\x08")) text = text.replace(/[^\x08]?\x08/, "");
  return text.replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
}

// Raw terminal output as plain text, for reading a saved log.
export function terminalToText(raw: string): string {
  return raw.replace(ESCAPES, "").replace(/\r\n/g, "\n").split("\n").map(lineText).join("\n");
}
