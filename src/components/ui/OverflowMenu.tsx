import { tr } from "../../i18n";
import { useEffect, useRef, useState } from "react";

export interface OverflowMenuItem {
  label: string;
  onClick: () => void;
  danger?: boolean;
  disabled?: boolean;
}

interface OverflowMenuProps {
  items: OverflowMenuItem[];
  title?: string;
}

export default function OverflowMenu({ items, title = "More" }: OverflowMenuProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    window.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="overflow-menu" ref={ref}>
      <button
        type="button"
        className="overflow-menu-trigger"
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        title={tr(title)}
      >
        ⋮
      </button>
      {open && (
        <div className="overflow-menu-dropdown" onClick={(e) => e.stopPropagation()}>
          {items.map((item, i) => (
            <button
              key={i}
              type="button"
              className={`overflow-menu-item ${item.danger ? "danger" : ""}`}
              disabled={item.disabled}
              onClick={() => {
                setOpen(false);
                item.onClick();
              }}
            >
              {tr(item.label)}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
