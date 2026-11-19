import { TransactionState } from "@core/types";
import { TabStripItem } from "@core/components/TabStrip/TabStrip";

export function transactionFlag(state: TransactionState | undefined): TabStripItem["flag"] {
  if (state === "open") return { label: "TX", tone: "warning", hint: "Transaction open. Run COMMIT or ROLLBACK in this tab to end it." };
  if (state === "failed") return { label: "TX", tone: "danger", hint: "The transaction failed. Only ROLLBACK works in this tab until it's rolled back." };
  return null;
}

// For a connection's tab, which can hold several query tabs with their own transactions.
export function sessionTransactionFlag(transactions: Record<string, TransactionState>): TabStripItem["flag"] {
  const states = Object.values(transactions);
  if (states.length === 0) return null;
  const failed = states.includes("failed");
  const tabs = states.length === 1 ? "A query tab has" : `${states.length} query tabs have`;
  return {
    label: "TX",
    tone: failed ? "danger" : "warning",
    hint: `${tabs} a transaction open${failed ? ", and one failed" : ""}. Disconnecting rolls back what wasn't committed.`,
  };
}
