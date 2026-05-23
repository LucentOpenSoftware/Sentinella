import { useState, useEffect, useCallback } from "react";
import { RotateCcw, Trash2, FileWarning, ChevronDown, ChevronUp, Loader2, WifiOff, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import { ShieldIcon } from "../components/ShieldIcon";
import { Card } from "../components/Card";
import { getQuarantineItems, restoreQuarantine, deleteQuarantine } from "../api/sentinella";
import type { QuarantineEntry } from "../types/sentinella";

type Toast = { type: "success" | "error"; message: string };
type ConfirmAction = { type: "restore" | "delete"; item: QuarantineEntry };

export function QuarantinePage() {
  const [items, setItems] = useState<QuarantineEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string|null>(null);
  const [expanded, setExpanded] = useState<string|null>(null);
  const [toast, setToast] = useState<Toast|null>(null);
  const [busy, setBusy] = useState<string|null>(null);
  const [confirm, setConfirm] = useState<ConfirmAction|null>(null);

  const refresh = useCallback(() => {
    getQuarantineItems()
      .then(r => { setItems(r); setErr(null); })
      .catch(e => setErr(String(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Auto-dismiss toast.
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(t);
  }, [toast]);

  const handleRestore = async (item: QuarantineEntry) => {
    setBusy(item.id);
    try {
      const result = await restoreQuarantine(item.id);
      if (result.ok) {
        setToast({ type: "success", message: `Restored to ${result.restored_to || item.original_path}` });
      } else {
        setToast({ type: "error", message: result.error || "Restore failed" });
      }
    } catch (e) {
      setToast({ type: "error", message: String(e) });
    }
    setBusy(null);
    setExpanded(null);
    setConfirm(null);
    refresh();
  };

  const handleDelete = async (item: QuarantineEntry) => {
    setBusy(item.id);
    try {
      const result = await deleteQuarantine(item.id);
      if (result.ok) {
        setToast({ type: "success", message: "Threat permanently deleted" });
      } else {
        setToast({ type: "error", message: result.error || "Delete failed" });
      }
    } catch (e) {
      setToast({ type: "error", message: String(e) });
    }
    setBusy(null);
    setExpanded(null);
    setConfirm(null);
    refresh();
  };

  if (loading) return <div className="flex items-center justify-center py-20"><Loader2 size={20} className="text-[rgb(var(--accent))] animate-spin"/></div>;
  if (err) return <Card className="text-center py-10"><WifiOff size={20} className="mx-auto text-[rgb(var(--amber))] mb-3"/><p className="text-[13px] text-[rgb(var(--t3))]">Could not reach daemon</p></Card>;

  return (
    <div className="page-stack">
      {/* Toast notification */}
      {toast && (
        <div className={`fixed top-6 right-6 z-50 flex items-center gap-2.5 px-5 py-3 rounded shadow-xl text-[13px] font-medium animate-in slide-in-from-right ${
          toast.type === "success"
            ? "bg-[rgb(var(--green))]/12 text-[rgb(var(--green))] border border-[rgb(var(--green))]/15"
            : "bg-[rgb(var(--red))]/12 text-[rgb(var(--red))] border border-[rgb(var(--red))]/15"
        }`}>
          {toast.type === "success" ? <CheckCircle2 size={15}/> : <XCircle size={15}/>}
          <span className="max-w-xs truncate">{toast.message}</span>
          <button onClick={() => setToast(null)} className="ml-2 opacity-50 hover:opacity-100 cursor-pointer">×</button>
        </div>
      )}

      {/* Confirmation dialog */}
      {confirm && (
        <div className="fixed inset-0 bg-black/40 z-40 flex items-center justify-center">
          <div className="glass-card p-6 max-w-md w-full mx-4">
            <div className="flex items-start gap-3 mb-4">
              <AlertTriangle size={20} className={confirm.type === "restore" ? "text-[rgb(var(--amber))] mt-0.5" : "text-[rgb(var(--red))] mt-0.5"}/>
              <div>
                <h3 className="text-[15px] font-semibold mb-1.5">
                  {confirm.type === "restore" ? "Restore Quarantined File?" : "Permanently Delete?"}
                </h3>
                <p className="text-[12px] text-[rgb(var(--t2))] leading-relaxed mb-2">
                  {confirm.type === "restore"
                    ? "This file was quarantined because it was detected as a threat. Restoring it will place the file back at its original location. Only restore if you are sure this is a false positive."
                    : "This will permanently destroy the quarantined file. This action cannot be undone."}
                </p>
                <div className="text-[11px] text-[rgb(var(--t3))] bg-[rgb(var(--raised))]/15 px-3 py-2 rounded-lg">
                  <p className="font-mono truncate">{confirm.item.original_path.split('\\').pop()}</p>
                  <p className="mt-0.5">{confirm.item.signature}</p>
                </div>
              </div>
            </div>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setConfirm(null)}
                disabled={!!busy}
                className="text-[12px] font-medium px-5 py-2.5 rounded-xl bg-[rgb(var(--raised))]/20 text-[rgb(var(--t2))] cursor-pointer disabled:opacity-30"
              >Cancel</button>
              <button
                onClick={() => confirm.type === "restore" ? handleRestore(confirm.item) : handleDelete(confirm.item)}
                disabled={!!busy}
                className={`text-[12px] font-medium px-5 py-2.5 rounded-xl flex items-center gap-1.5 cursor-pointer disabled:opacity-30 ${
                  confirm.type === "restore"
                    ? "bg-[rgb(var(--amber))]/12 text-[rgb(var(--amber))]"
                    : "bg-[rgb(var(--red))]/12 text-[rgb(var(--red))]"
                }`}
              >
                {busy ? <Loader2 size={12} className="animate-spin"/> : confirm.type === "restore" ? <RotateCcw size={12}/> : <Trash2 size={12}/>}
                {confirm.type === "restore" ? "Restore File" : "Delete Forever"}
              </button>
            </div>
          </div>
        </div>
      )}

      {items.length === 0 ? (
        <Card className="text-center py-14">
          <div className="mx-auto w-fit mb-4"><ShieldIcon icon="quarantine" size={36} className="opacity-50" /></div>
          <h3 className="text-[18px] font-semibold mb-2">Quarantine is Empty</h3>
          <p className="text-[13px] text-[rgb(var(--t2))] max-w-sm mx-auto leading-relaxed">
            No threats have been quarantined. Detected threats will appear here for you to review and manage safely.
          </p>
        </Card>
      ) : (
        <Card>
          <div className="flex items-center justify-between px-1 pb-3 mb-1 border-b border-[rgb(var(--border))]/6">
            <p className="text-[12px] text-[rgb(var(--t3))]">{items.length} quarantined {items.length === 1 ? "threat" : "threats"}</p>
          </div>
          {items.map((item, idx) => {
            const exp = expanded === item.id;
            const isBusy = busy === item.id;
            return (
              <div key={item.id} className={idx > 0 ? "border-t border-[rgb(var(--border))]/8" : ""}>
                <button onClick={() => setExpanded(exp ? null : item.id)} className="w-full flex items-center gap-4 py-4 text-left cursor-pointer hover:bg-[rgb(var(--raised))]/10 transition-colors px-1 rounded-lg">
                  <FileWarning size={16} className="text-[rgb(var(--red))] flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-[13px] font-medium">{item.original_path.split('\\').pop()}</p>
                    <p className="text-[11px] text-[rgb(var(--t3))]/40 truncate">{item.signature}</p>
                  </div>
                  <p className="text-[11px] text-[rgb(var(--t3))]/30">{new Date(item.quarantined_at * 1000).toLocaleDateString()}</p>
                  {exp ? <ChevronUp size={14} className="text-[rgb(var(--t3))]/25"/> : <ChevronDown size={14} className="text-[rgb(var(--t3))]/25"/>}
                </button>
                {exp && (
                  <div className="pb-4 pl-10">
                    <div className="mb-4 grid gap-x-8 gap-y-3 text-[12px] md:grid-cols-2">
                      <div><p className="text-[rgb(var(--t3))]/30 text-[10px] uppercase">Path</p><p className="font-medium truncate">{item.original_path}</p></div>
                      <div><p className="text-[rgb(var(--t3))]/30 text-[10px] uppercase">Detection</p><p className="font-medium">{item.signature}</p></div>
                      <div><p className="text-[rgb(var(--t3))]/30 text-[10px] uppercase">SHA-256</p><p className="font-mono text-[11px]">{item.sha256.slice(0, 24)}...</p></div>
                      <div><p className="text-[rgb(var(--t3))]/30 text-[10px] uppercase">Size</p><p className="font-medium">{item.original_size.toLocaleString()} bytes</p></div>
                    </div>
                    <div className="flex gap-3">
                      <button
                        disabled={!item.restorable || isBusy}
                        onClick={() => setConfirm({ type: "restore", item })}
                        className="text-[11px] font-medium px-4 py-2 rounded-xl bg-[rgb(var(--raised))]/25 text-[rgb(var(--t2))] flex items-center gap-1.5 cursor-pointer disabled:opacity-30"
                        title={!item.restorable ? "Vault file missing or already restored" : "Restore file to original location"}
                      >
                        {isBusy ? <Loader2 size={12} className="animate-spin"/> : <RotateCcw size={12}/>}
                        Restore
                      </button>
                      <button
                        disabled={isBusy}
                        onClick={() => setConfirm({ type: "delete", item })}
                        className="text-[11px] font-medium px-4 py-2 rounded-xl bg-[rgb(var(--red))]/6 text-[rgb(var(--red))] flex items-center gap-1.5 cursor-pointer disabled:opacity-30"
                      >
                        <Trash2 size={12}/>Delete
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </Card>
      )}
    </div>
  );
}
