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

const STYLES: Record<ToastType, { border: string; text: string; icon: string }> = {
  success: { border: "border-l-success", text: "text-success-dark", icon: "text-success" },
  error: { border: "border-l-error", text: "text-error-dark", icon: "text-error" },
  warning: { border: "border-l-warning", text: "text-warning-dark", icon: "text-warning" },
  info: { border: "border-l-info", text: "text-info-dark", icon: "text-info" },
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
      <div className="fixed bottom-6 z-[100] flex flex-col items-center gap-2 pointer-events-none" style={{ left: "280px", right: "0" }}>
        {toasts.map((t) => {
          const style = STYLES[t.type];
          const Icon = ICONS[t.type];
          return (
            <div
              key={t.id}
              className={`pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-lg border-l-4 ${style.border} bg-white shadow-z16 animate-in slide-in-from-right-5 min-w-[320px] max-w-[420px]`}
            >
              <Icon className={`w-5 h-5 shrink-0 ${style.icon}`} />
              <span className={`text-[13px] font-semibold ${style.text} flex-1`}>{t.message}</span>
              <button onClick={() => remove(t.id)} className="p-0.5 hover:opacity-70 shrink-0">
                <X className={`w-4 h-4 text-grey-500`} />
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
