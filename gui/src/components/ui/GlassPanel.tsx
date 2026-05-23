interface Props {
  children: React.ReactNode;
  className?: string;
  padding?: "none" | "sm" | "md" | "lg";
  hover?: boolean;
}

const PAD = { none: "", sm: "p-4", md: "p-6", lg: "p-8" };

export function GlassPanel({ children, className = "", padding = "lg", hover = false }: Props) {
  return (
    <div className={`min-w-0 overflow-hidden glass-card ${PAD[padding]} ${hover ? "hover:translate-y-[-1px]" : ""} ${className}`}>
      {children}
    </div>
  );
}
