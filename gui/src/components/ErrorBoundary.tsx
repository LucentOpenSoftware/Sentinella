import { Component, type ReactNode } from "react";

interface Props { children: ReactNode; }
interface State { hasError: boolean; error: string; }

/**
 * Top-level error boundary — catches React render crashes and shows
 * a recovery UI instead of a blank screen.
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: "" };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error: error.message };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[ErrorBoundary] React render crash:", error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-screen items-center justify-center bg-[rgb(var(--base))]">
          <div className="max-w-md text-center px-8">
            <div className="flex h-16 w-16 mx-auto items-center justify-center rounded bg-[rgb(var(--red))]/8 mb-5">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="rgb(var(--red))" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
            </div>
            <h2 className="text-[18px] font-bold text-[rgb(var(--t1))] mb-2">Something went wrong</h2>
            <p className="text-[13px] text-[rgb(var(--t3))] mb-4 leading-relaxed">
              Sentinella encountered an unexpected error. Your protection is still active — the daemon continues running independently.
            </p>
            <p className="text-[11px] text-[rgb(var(--t3))]/40 font-mono mb-6 break-all">{this.state.error}</p>
            <button
              onClick={() => { this.setState({ hasError: false, error: "" }); }}
              className="px-5 py-2.5 rounded-xl bg-[rgb(var(--accent))] text-white text-[13px] font-semibold hover:opacity-90 cursor-pointer"
            >
              Try Again
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
