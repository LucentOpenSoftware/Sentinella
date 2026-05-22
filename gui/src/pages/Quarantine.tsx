import { useState, useEffect } from "react";
import {
  Archive,
  RotateCcw,
  Trash2,
  FileWarning,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  Loader2,
  WifiOff,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Card } from "../components/Card";
import { getQuarantineItems } from "../api/sentinella";
import type { QuarantineEntry } from "../types/sentinella";

export function QuarantinePage() {
  const [items, setItems] = useState<QuarantineEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    getQuarantineItems()
      .then((r) => { setItems(r); setError(null); })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center py-24">
        <Loader2 size={24} className="text-[rgb(var(--accent))] animate-spin mb-3" />
        <p className="text-sm text-[rgb(var(--text-muted))]">Loading quarantine...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <PageHeader icon={<Archive size={22} />} title="Quarantine" subtitle="Isolated threats" />
        <Card className="text-center py-12">
          <WifiOff size={28} className="mx-auto text-[rgb(var(--warning))] mb-3" />
          <p className="text-sm text-[rgb(var(--text-muted))]">Could not reach daemon</p>
          <p className="text-xs text-[rgb(var(--danger))] mt-1">{error}</p>
        </Card>
      </div>
    );
  }

  return (
    <div>
      <PageHeader icon={<Archive size={22} />} title="Quarantine" subtitle="Isolated threats stored safely">
        <span className="text-xs text-[rgb(var(--text-muted))] bg-[rgb(var(--bg-elevated))] px-3 py-1.5 rounded-lg">
          {items.length} item{items.length !== 1 ? "s" : ""} · AES-256-GCM encrypted
        </span>
      </PageHeader>

      {items.length === 0 ? (
        <Card className="text-center py-20">
          <ShieldCheck size={32} className="mx-auto text-[rgb(var(--success))] mb-4" />
          <h3 className="text-lg font-semibold mb-2">Quarantine is empty</h3>
          <p className="text-sm text-[rgb(var(--text-muted))] max-w-sm mx-auto">
            No threats have been quarantined. Detected threats will appear here
            for you to review and manage safely.
          </p>
          <p className="text-xs text-[rgb(var(--text-muted))] mt-4">
            The quarantine vault will be implemented when the scanning engine is connected.
          </p>
        </Card>
      ) : (
        <div className="space-y-3">
          {items.map((item) => {
            const expanded = expandedId === item.id;
            return (
              <Card key={item.id} className="p-0 overflow-hidden">
                <button
                  onClick={() => setExpandedId(expanded ? null : item.id)}
                  className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-[rgb(var(--bg-elevated))]/30 transition-colors cursor-pointer"
                >
                  <div className="w-10 h-10 rounded-xl bg-[rgb(var(--danger))]/10 flex items-center justify-center flex-shrink-0">
                    <FileWarning size={18} className="text-[rgb(var(--danger))]" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold truncate">{item.original_path.split('\\').pop()}</p>
                    <p className="text-xs text-[rgb(var(--text-muted))] truncate">{item.signature}</p>
                  </div>
                  <div className="text-right flex-shrink-0 mr-2">
                    <p className="text-xs text-[rgb(var(--text-muted))]">
                      {new Date(item.quarantined_at * 1000).toLocaleDateString()}
                    </p>
                    <p className="text-xs text-[rgb(var(--text-muted))]">
                      {(item.original_size / 1024).toFixed(0)} KB
                    </p>
                  </div>
                  {expanded ? <ChevronUp size={16} className="text-[rgb(var(--text-muted))]" />
                    : <ChevronDown size={16} className="text-[rgb(var(--text-muted))]" />}
                </button>

                {expanded && (
                  <div className="px-5 pb-4 pt-1 border-t border-[rgb(var(--border))]/50">
                    <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm mb-4">
                      <MetaRow label="Original path" value={item.original_path} />
                      <MetaRow label="Detection" value={item.signature} />
                      <MetaRow label="SHA-256" value={item.sha256.slice(0, 24) + "..."} />
                      <MetaRow label="Size" value={`${item.original_size.toLocaleString()} bytes`} />
                      <MetaRow label="Quarantined" value={new Date(item.quarantined_at * 1000).toLocaleString()} />
                      <MetaRow label="Restorable" value={item.restorable ? "Yes" : "No"} />
                    </div>
                    <div className="flex gap-2">
                      <button disabled={!item.restorable}
                        className="text-xs font-medium px-3 py-2 rounded-lg bg-[rgb(var(--bg-elevated))] text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text-primary))] transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed">
                        <RotateCcw size={13} /> Restore
                      </button>
                      <button className="text-xs font-medium px-3 py-2 rounded-lg bg-[rgb(var(--danger))]/10 text-[rgb(var(--danger))] hover:bg-[rgb(var(--danger))]/20 transition-colors flex items-center gap-1.5 cursor-pointer">
                        <Trash2 size={13} /> Delete permanently
                      </button>
                    </div>
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[11px] text-[rgb(var(--text-muted))] uppercase tracking-wider">{label}</p>
      <p className="text-sm font-medium truncate">{value}</p>
    </div>
  );
}
