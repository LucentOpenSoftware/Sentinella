type Color = "accent" | "green" | "amber" | "red";

interface Props {
  label: string;
  value: string;
  sub?: string;
  color?: Color;
  icon?: React.ReactNode;
}

export function MetricCard({ label, value, sub, color = "accent", icon }: Props) {
  const palette = `var(--${color})`;
  return (
    <div className="glass-card flex flex-col gap-2 px-5 py-4 h-full">
      {/* Header: icon + label */}
      <div className="flex items-center gap-2.5">
        {icon && (
          <div
            className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-md"
            style={{ background: `rgba(${palette}, 0.08)`, color: `rgb(${palette})` }}
          >
            {icon}
          </div>
        )}
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em]" style={{ color: `rgba(${palette}, 0.65)` }}>
          {label}
        </p>
      </div>
      {/* Value */}
      <p className="text-[22px] font-bold leading-tight text-[rgb(var(--t1))]">{value}</p>
      {/* Subtitle */}
      {sub && <p className="text-[11px] leading-snug text-[rgb(var(--t3))]">{sub}</p>}
    </div>
  );
}
