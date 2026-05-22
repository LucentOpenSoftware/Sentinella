interface QuickActionCardProps {
  icon: React.ReactNode;
  label: string;
  description: string;
  onClick?: () => void;
  accent?: boolean;
}

export function QuickActionCard({
  icon,
  label,
  description,
  onClick,
  accent,
}: QuickActionCardProps) {
  return (
    <button
      onClick={onClick}
      className={`
        flex flex-col items-center gap-3 p-5 rounded-2xl border
        transition-all duration-200 cursor-pointer text-center
        ${accent
          ? "bg-[rgb(var(--accent))]/10 border-[rgb(var(--accent))]/20 hover:bg-[rgb(var(--accent))]/20"
          : "bg-[rgb(var(--bg-surface))] border-[rgb(var(--border))] hover:border-[rgb(var(--accent))]/40 hover:bg-[rgb(var(--bg-elevated))]"
        }
      `}
    >
      <div
        className={`
          w-12 h-12 rounded-xl flex items-center justify-center
          ${accent
            ? "bg-[rgb(var(--accent))]/20 text-[rgb(var(--accent))]"
            : "bg-[rgb(var(--bg-elevated))] text-[rgb(var(--text-muted))]"
          }
        `}
      >
        {icon}
      </div>
      <div>
        <p className="text-sm font-semibold">{label}</p>
        <p className="text-xs text-[rgb(var(--text-muted))] mt-0.5">{description}</p>
      </div>
    </button>
  );
}
