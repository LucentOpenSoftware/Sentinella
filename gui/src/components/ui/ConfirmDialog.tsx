import { AlertTriangle, Loader2 } from "lucide-react";

interface Props {
  open: boolean;
  title: string;
  description: string;
  detail?: React.ReactNode;
  confirmLabel: string;
  confirmColor?: "red" | "amber" | "accent";
  confirmIcon?: React.ReactNode;
  loading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({
  open, title, description, detail,
  confirmLabel, confirmColor = "red", confirmIcon,
  loading = false, onConfirm, onCancel,
}: Props) {
  if (!open) return null;

  const color = `var(--${confirmColor})`;

  return (
    <div className="fixed inset-0 bg-black/40 z-40 flex items-center justify-center" role="dialog" aria-modal="true">
      <div className="glass-card p-6 max-w-md w-full mx-4">
        <div className="flex items-start gap-3 mb-4">
          <AlertTriangle size={20} className="mt-0.5 flex-shrink-0" style={{ color: `rgb(${color})` }} />
          <div>
            <h3 className="text-[15px] font-semibold mb-1.5">{title}</h3>
            <p className="text-[12px] text-[rgb(var(--t2))] leading-relaxed mb-2">
              {description}
            </p>
            {detail}
          </div>
        </div>
        <div className="flex gap-3 justify-end">
          <button
            onClick={onCancel}
            disabled={loading}
            className="text-[12px] font-medium px-5 py-2.5 rounded-xl bg-[rgb(var(--raised))]/20 text-[rgb(var(--t2))] cursor-pointer disabled:opacity-30"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={loading}
            className="text-[12px] font-medium px-5 py-2.5 rounded-xl flex items-center gap-1.5 cursor-pointer disabled:opacity-30"
            style={{ background: `rgba(${color}, 0.12)`, color: `rgb(${color})` }}
          >
            {loading ? <Loader2 size={12} className="animate-spin" /> : confirmIcon}
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
