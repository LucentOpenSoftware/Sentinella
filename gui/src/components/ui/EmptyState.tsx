import { GlassPanel } from "./GlassPanel";

interface Props {
  icon: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  color?: "green" | "accent" | "amber";
}

export function EmptyState({ icon, title, description, action, color = "accent" }: Props) {
  return (
    <GlassPanel className="text-center py-14">
      <div className={`mx-auto mb-4 text-[rgb(var(--${color}))]`}>
        {icon}
      </div>
      <h3 className="text-[18px] font-semibold mb-2">{title}</h3>
      {description && (
        <p className="text-[13px] text-[rgb(var(--t2))] max-w-sm mx-auto leading-relaxed">
          {description}
        </p>
      )}
      {action && <div className="mt-5">{action}</div>}
    </GlassPanel>
  );
}
