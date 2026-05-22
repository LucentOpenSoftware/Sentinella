interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
  color?: "accent" | "success" | "warning" | "danger" | "muted";
}

const colorMap = {
  accent: "var(--accent)",
  success: "var(--success)",
  warning: "var(--warning)",
  danger: "var(--danger)",
  muted: "var(--text-muted)",
};

export function StatCard({ icon, label, value, sub, color = "accent" }: StatCardProps) {
  const c = colorMap[color];
  return (
    <div className="rounded-2xl border border-[rgb(var(--border))] bg-[rgb(var(--bg-surface))] p-5 flex items-center gap-4">
      <div
        className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0"
        style={{ backgroundColor: `rgba(${c}, 0.12)`, color: `rgb(${c})` }}
      >
        {icon}
      </div>
      <div className="min-w-0">
        <p className="text-xs text-[rgb(var(--text-muted))] uppercase tracking-wider font-medium">
          {label}
        </p>
        <p className="text-lg font-bold leading-tight">{value}</p>
        {sub && (
          <p className="text-xs text-[rgb(var(--text-muted))] mt-0.5 truncate">{sub}</p>
        )}
      </div>
    </div>
  );
}
