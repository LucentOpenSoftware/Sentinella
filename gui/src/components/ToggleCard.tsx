interface ToggleCardProps {
  icon?: React.ReactNode;
  label: string;
  description?: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}

export function ToggleCard({
  icon,
  label,
  description,
  checked,
  onChange,
  disabled,
}: ToggleCardProps) {
  return (
    <div
      className={`
        flex items-center justify-between py-3 px-1
        ${disabled ? "opacity-50" : ""}
      `}
    >
      <div className="flex items-center gap-3">
        {icon && (
          <div className="w-8 h-8 rounded-lg bg-[rgb(var(--bg-elevated))] flex items-center justify-center text-[rgb(var(--text-muted))]">
            {icon}
          </div>
        )}
        <div>
          <p className="text-sm font-medium">{label}</p>
          {description && (
            <p className="text-xs text-[rgb(var(--text-muted))] mt-0.5 max-w-xs">
              {description}
            </p>
          )}
        </div>
      </div>
      <button
        onClick={() => !disabled && onChange(!checked)}
        disabled={disabled}
        className={`
          w-11 h-6 rounded-full transition-colors duration-200 relative flex-shrink-0
          ${disabled ? "cursor-not-allowed" : "cursor-pointer"}
          ${checked ? "bg-[rgb(var(--accent))]" : "bg-[rgb(var(--border))]"}
        `}
      >
        <div
          className={`
            w-4.5 h-4.5 rounded-full bg-white absolute top-[3px] transition-transform duration-200 shadow-sm
            ${checked ? "translate-x-[22px]" : "translate-x-[3px]"}
          `}
        />
      </button>
    </div>
  );
}
