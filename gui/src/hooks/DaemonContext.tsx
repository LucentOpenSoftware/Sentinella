import { createContext, useContext } from "react";
import type { DaemonState } from "./useDaemon";

const DaemonContext = createContext<DaemonState | null>(null);

export const DaemonProvider = DaemonContext.Provider;

/** Use daemon state from context (provided by App). */
export function useDaemonContext(): DaemonState {
  const ctx = useContext(DaemonContext);
  if (!ctx) throw new Error("useDaemonContext must be inside DaemonProvider");
  return ctx;
}
