interface Props {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
}

export function SectionHeader({ title, subtitle, action }: Props) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div>
        <h3 className="text-[15px] font-semibold">{title}</h3>
        {subtitle && <p className="text-[11px] text-[rgb(var(--t3))] mt-0.5">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}
