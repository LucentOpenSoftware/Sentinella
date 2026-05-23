export function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`min-w-0 overflow-hidden glass-card p-8 ${className}`}>
      {children}
    </div>
  );
}
