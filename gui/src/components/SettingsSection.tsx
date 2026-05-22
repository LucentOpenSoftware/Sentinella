interface SettingsSectionProps {
  title: string;
  description?: string;
  children: React.ReactNode;
}

export function SettingsSection({ title, description, children }: SettingsSectionProps) {
  return (
    <div className="rounded-2xl border border-[rgb(var(--border))] bg-[rgb(var(--bg-surface))] p-5 mb-4">
      <h4 className="text-sm font-semibold mb-0.5">{title}</h4>
      {description && (
        <p className="text-xs text-[rgb(var(--text-muted))] mb-4">{description}</p>
      )}
      <div className="divide-y divide-[rgb(var(--border))]/50">{children}</div>
    </div>
  );
}
