// Placeholder tabs — Phase 2-4 work fills these in. Until then,
// the user sees "this tab is coming in the next v0.1.8 phase" and a
// link back to the legacy Settings page so no functionality is lost.

import { Construction } from "lucide-react";
import * as i18n from "../../../i18n";

export function TabStub({
  title,
  phase,
}: {
  title: string;
  phase: number;
}) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-16 px-6">
      <Construction className="w-12 h-12 text-[rgb(var(--muted))] mb-4" />
      <h3 className="text-base font-semibold mb-1">{title}</h3>
      <p className="text-sm text-[rgb(var(--muted))] max-w-md">
        {i18n.t("settings.tab_stub").replace("{phase}", String(phase))}
      </p>
      <p className="text-xs text-[rgb(var(--muted))] mt-3">
        {i18n.t("settings.tab_stub_legacy")}
      </p>
    </div>
  );
}
