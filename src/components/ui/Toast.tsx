import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
} from "react";
import { CloseIcon } from "../../icons";

export type ToastKind = "info" | "success" | "error";

interface ToastItem {
  id: number;
  kind: ToastKind;
  text: string;
}

const AUTO_DISMISS_MS: Record<ToastKind, number> = {
  info: 6000,
  success: 5000,
  error: 9000,
};

const ToastContext = createContext<(kind: ToastKind, text: string) => void>(
  () => {},
);

/** Push a transient status notification into the corner toast stack. */
export function useToast() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(0);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (kind: ToastKind, text: string) => {
      const id = ++nextId.current;
      setToasts((current) => [...current.slice(-3), { id, kind, text }]);
      const delay = AUTO_DISMISS_MS[kind];
      window.setTimeout(() => dismiss(id), delay);
    },
    [dismiss],
  );

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.kind}`}>
            <span className="toast-dot" />
            <span className="toast-text">{toast.text}</span>
            <button
              type="button"
              className="toast-close"
              onClick={() => dismiss(toast.id)}
              title="Dismiss"
            >
              <CloseIcon size={12} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
