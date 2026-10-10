import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RotateCcw, Shield } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an unhandled error:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="bg-white rounded-3xl border border-rose-200 p-8 shadow-sm my-4">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-rose-100 text-rose-600 rounded-2xl shrink-0">
              <AlertOctagon className="w-6 h-6" />
            </div>
            <div className="flex-1">
              <h3 className="text-base font-bold text-slate-900 mb-1">
                {this.props.fallbackTitle || 'Component Rendering Error'}
              </h3>
              <p className="text-xs text-slate-500 mb-4">
                An unexpected display error occurred while rendering this triage component. Your file analysis data remains safe.
              </p>

              {this.state.error && (
                <div className="bg-slate-950 text-rose-300 p-4 rounded-2xl font-mono text-xs mb-4 overflow-x-auto border border-slate-800">
                  <div className="font-bold mb-1 text-rose-400">
                    {this.state.error.name}: {this.state.error.message}
                  </div>
                  {this.state.error.stack && (
                    <pre className="text-[11px] text-slate-400 whitespace-pre-wrap leading-tight max-h-48 overflow-y-auto">
                      {this.state.error.stack}
                    </pre>
                  )}
                </div>
              )}

              <div className="flex items-center gap-3">
                <button
                  onClick={this.handleReset}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-semibold flex items-center gap-2 transition-colors cursor-pointer shadow-sm"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Retry View</span>
                </button>

                {this.props.onReset && (
                  <button
                    onClick={this.props.onReset}
                    className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-semibold flex items-center gap-2 transition-colors cursor-pointer"
                  >
                    <Shield className="w-3.5 h-3.5" />
                    <span>Return to Overview</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
