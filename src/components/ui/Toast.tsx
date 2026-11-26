import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { AlertTriangle, CheckCircle2, Info, X } from "lucide-react";
import { classNames } from "../../lib/format";

type Tone = "success" | "error" | "info";

interface ToastItem {
  id: string;
  title: string;
  description?: string;
  tone: Tone;
}

interface ToastContextValue {
  push: (toast: Omit<ToastItem, "id">) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const toneStyles: Record<Tone, { border: string; icon: typeof Info; iconClass: string }> = {
  success: { border: "border-good/25", icon: CheckCircle2, iconClass: "text-good" },
  error: { border: "border-critical/25", icon: AlertTriangle, iconClass: "text-critical" },
  info: { border: "border-lavender/25", icon: Info, iconClass: "text-lavender" },
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const remove = useCallback((id: string) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (toast: Omit<ToastItem, "id">) => {
      const id = `toast-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      setToasts((current) => [...current.slice(-2), { ...toast, id }]);
      window.setTimeout(() => remove(id), 4800);
    },
    [remove],
  );

  const value = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[calc(100%-2rem)] max-w-sm flex-col gap-2"
        aria-live="polite"
        aria-atomic="false"
      >
        {toasts.map((toast) => {
          const style = toneStyles[toast.tone];
          const Icon = style.icon;
          return (
            <div
              key={toast.id}
              className={classNames(
                "animate-fade-up pointer-events-auto flex items-start gap-3 rounded-[8px] border bg-[#1d112b] px-3.5 py-3 shadow-[0_18px_50px_rgba(0,0,0,0.45)]",
                style.border,
              )}
            >
              <Icon className={classNames("mt-0.5 size-4 shrink-0", style.iconClass)} />
              <div className="min-w-0 flex-1">
                <p className="text-[12.5px] font-medium text-paper">{toast.title}</p>
                {toast.description ? (
                  <p className="mt-0.5 text-[11.5px] leading-relaxed text-lilac/55">
                    {toast.description}
                  </p>
                ) : null}
              </div>
              <button
                type="button"
                onClick={() => remove(toast.id)}
                aria-label="Dismiss notification"
                className="text-lilac/35 transition hover:text-paper"
              >
                <X className="size-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider");
  return context;
}
