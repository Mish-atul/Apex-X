"use client";

import React, { createContext, useCallback, useContext, useState, useSyncExternalStore } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { CheckCircle2, AlertTriangle, Info, XCircle, X } from "lucide-react";

type ToastKind = "success" | "error" | "info" | "warning";
interface Toast { id: number; kind: ToastKind; title: string; message?: string; }

interface ConfirmOptions {
  title: string;
  message?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: "default" | "danger";
}

interface FeedbackCtx {
  toast: (kind: ToastKind, title: string, message?: string) => void;
  confirm: (opts: ConfirmOptions) => Promise<boolean>;
}

const Ctx = createContext<FeedbackCtx | null>(null);

const TOAST_STYLES: Record<ToastKind, { icon: React.ElementType; accent: string; iconColor: string }> = {
  success: { icon: CheckCircle2, accent: "border-l-emerald-500", iconColor: "text-emerald-500" },
  error: { icon: XCircle, accent: "border-l-red-500", iconColor: "text-red-500" },
  warning: { icon: AlertTriangle, accent: "border-l-amber-500", iconColor: "text-amber-500" },
  info: { icon: Info, accent: "border-l-indigo-500", iconColor: "text-indigo-500" },
};

export function FeedbackProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [dialog, setDialog] = useState<(ConfirmOptions & { resolve: (v: boolean) => void }) | null>(null);
  // true only on the client, without a setState-in-effect round trip
  const mounted = useSyncExternalStore(() => () => {}, () => true, () => false);

  const toast = useCallback((kind: ToastKind, title: string, message?: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, kind, title, message }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000);
  }, []);

  const confirm = useCallback((opts: ConfirmOptions) => {
    return new Promise<boolean>((resolve) => setDialog({ ...opts, resolve }));
  }, []);

  const close = (v: boolean) => {
    dialog?.resolve(v);
    setDialog(null);
  };

  return (
    <Ctx.Provider value={{ toast, confirm }}>
      {children}
      {mounted && createPortal(
        <>
          {/* Toasts */}
          <div className="fixed top-24 right-4 z-[100] flex flex-col gap-2 w-[min(92vw,380px)]">
            <AnimatePresence>
              {toasts.map((t) => {
                const s = TOAST_STYLES[t.kind];
                const Icon = s.icon;
                return (
                  <motion.div
                    key={t.id}
                    initial={{ opacity: 0, x: 40, scale: 0.95 }}
                    animate={{ opacity: 1, x: 0, scale: 1 }}
                    exit={{ opacity: 0, x: 40, scale: 0.95 }}
                    transition={{ type: "spring", stiffness: 400, damping: 30 }}
                    className={`bg-panel border border-border-subtle ${s.accent} border-l-4 shadow-lg rounded-md p-3 flex items-start gap-3`}
                  >
                    <Icon className={`w-5 h-5 shrink-0 mt-0.5 ${s.iconColor}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-semibold text-text">{t.title}</p>
                      {t.message && <p className="text-xs text-text-muted mt-0.5 whitespace-pre-line break-words">{t.message}</p>}
                    </div>
                    <button onClick={() => setToasts((x) => x.filter((y) => y.id !== t.id))}
                            className="text-text-muted hover:text-text transition-colors shrink-0">
                      <X className="w-4 h-4" />
                    </button>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>

          {/* Confirm dialog */}
          <AnimatePresence>
            {dialog && (
              <motion.div
                className="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm"
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                onClick={() => close(false)}
              >
                <motion.div
                  initial={{ opacity: 0, scale: 0.95, y: 12 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.97, y: 8 }}
                  transition={{ type: "spring", stiffness: 420, damping: 32 }}
                  className="bg-panel border border-border-subtle rounded-lg shadow-2xl w-[min(94vw,440px)] p-6"
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="flex items-start gap-3">
                    <div className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 ${
                      dialog.tone === "danger" ? "bg-red-100 text-red-600" : "bg-indigo-100 text-indigo-600"}`}>
                      <AlertTriangle className="w-5 h-5" />
                    </div>
                    <div className="flex-1">
                      <h3 className="font-display text-lg font-bold text-text">{dialog.title}</h3>
                      {dialog.message && (
                        <p className="text-sm text-text-muted mt-1 whitespace-pre-line">{dialog.message}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex justify-end gap-2 mt-6">
                    <button onClick={() => close(false)}
                            className="px-4 py-2 text-sm font-medium text-text-muted hover:text-text hover:bg-surface rounded-md transition-colors">
                      {dialog.cancelLabel || "Cancel"}
                    </button>
                    <button onClick={() => close(true)}
                            className={`px-4 py-2 text-sm font-semibold text-white rounded-md transition-colors shadow-sm ${
                              dialog.tone === "danger" ? "bg-red-600 hover:bg-red-700" : "bg-indigo-600 hover:bg-indigo-700"}`}>
                      {dialog.confirmLabel || "Confirm"}
                    </button>
                  </div>
                </motion.div>
              </motion.div>
            )}
          </AnimatePresence>
        </>,
        document.body,
      )}
    </Ctx.Provider>
  );
}

export function useFeedback(): FeedbackCtx {
  const ctx = useContext(Ctx);
  if (!ctx) {
    // Safe fallback if used outside the provider (keeps the app functional)
    return {
      toast: (_k, title, message) => console.log(`[toast] ${title} ${message || ""}`),
      confirm: async (o) => window.confirm(`${o.title}\n\n${o.message || ""}`),
    };
  }
  return ctx;
}
