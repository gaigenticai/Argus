"use client";

import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { AlertTriangle, CheckCircle, Info, X, XCircle } from "lucide-react";

type ToastType = "success" | "error" | "warning" | "info";

interface Toast {
  id: number;
  type: ToastType;
  message: string;
}

interface ToastContextValue {
  toast: (type: ToastType, message: string) => void;
}

const ToastContext = createContext<ToastContextValue>({ toast: () => {} });

let nextId = 0;

const ICONS: Record<ToastType, typeof CheckCircle> = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
};

const STYLES: Record<ToastType, { borderColor: string; iconColor: string; textColor: string }> = {
  success: { borderColor: "#22C55E", iconColor: "#22C55E", textColor: "#14532D" },
  error: { borderColor: "var(--color-error)", iconColor: "var(--color-error)", textColor: "#7F1D1D" },
  warning: { borderColor: "#FFAB00", iconColor: "#FFAB00", textColor: "#B76E00" },
  info: { borderColor: "#00BBD9", iconColor: "#00BBD9", textColor: "#007B8A" },
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((type: ToastType, message: string) => {
    const id = nextId++;
    setToasts((prev) => [...prev, { id, type, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 5000);
  }, []);

  const remove = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}
      {/* Toast container */}
      <div
        className="fixed bottom-6 z-[100] flex flex-col items-center gap-2 pointer-events-none"
        style={{ left: "280px", right: "0" }}
      >
        {toasts.map((t) => {
          const style = STYLES[t.type];
          const Icon = ICONS[t.type];
          return (
            <div
              key={t.id}
              className="pointer-events-auto flex items-center gap-3 px-4 py-3 animate-in slide-in-from-right-5 min-w-[320px] max-w-[420px]"
              style={{
                background: "var(--color-canvas)",
                border: "1px solid var(--color-border)",
                borderLeft: `4px solid ${style.borderColor}`,
                borderRadius: "5px",
                boxShadow: "var(--shadow-z16)",
              }}
            >
              <Icon className="w-5 h-5 shrink-0" style={{ color: style.iconColor }} />
              <span
                className="text-[13px] font-semibold flex-1"
                style={{ color: style.textColor }}
              >
                {t.message}
              </span>
              <button
                onClick={() => remove(t.id)}
                className="p-0.5 shrink-0 transition-opacity hover:opacity-70"
              >
                <X className="w-4 h-4" style={{ color: "var(--color-muted)" }} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}
