interface CardProps {
  children: React.ReactNode;
  className?: string;
}

export function Card({ children, className = "" }: CardProps) {
  return (
    <div
      className={`rounded-2xl border border-[rgb(var(--border))] bg-[rgb(var(--bg-surface))] p-5 ${className}`}
    >
      {children}
    </div>
  );
}
