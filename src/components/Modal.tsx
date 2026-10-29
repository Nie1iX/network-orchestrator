import { useEffect, useRef } from "react";
import { CloseIcon } from "../icons";
import { useT } from "../i18n";

interface ModalProps {
  open: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  maxWidth?: string;
}

export default function Modal({
  open,
  title,
  onClose,
  children,
  footer,
  maxWidth = "560px",
}: ModalProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const t = useT();

  // Callers pass inline closures; keeping the latest one in a ref stops the
  // effects below from re-running on every parent render, which used to
  // re-focus the dialog and drop the focused input / open <select>.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCloseRef.current();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    // Move focus into the dialog so keyboard users aren't stranded behind it,
    // unless an autoFocus field inside already took it.
    const dialog = dialogRef.current;
    if (dialog && !dialog.contains(document.activeElement)) dialog.focus();
  }, [open]);

  if (!open) return null;
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        ref={dialogRef}
        className="modal-dialog"
        style={{ maxWidth }}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <h3 className="modal-title">{title}</h3>
          <button
            type="button"
            className="modal-close"
            onClick={onClose}
            title={t("common.close")}
          >
            <CloseIcon size={18} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
}
