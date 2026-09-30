import { useEffect, useRef } from "react";
import type { OverflowMenuItem } from "./OverflowMenu";

interface ContextMenuProps {
  x: number;
  y: number;
  items: (OverflowMenuItem | "separator")[];
  onClose: () => void;
}

/** Right-click menu positioned at the cursor; closes on click-away,
 * Escape, second right-click, or scroll. */
export default function ContextMenu({ x, y, items, onClose }: ContextMenuProps) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDocMouseDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    const onScroll = () => onClose();
    document.addEventListener("mousedown", onDocMouseDown);
    window.addEventListener("keydown", onKey);
    window.addEventListener("scroll", onScroll, true);
    return () => {
      document.removeEventListener("mousedown", onDocMouseDown);
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", onScroll, true);
    };
  }, [onClose]);

  // Keep the menu inside the viewport.
  const style: React.CSSProperties = { left: x, top: y };
  if (ref.current) {
    const rect = ref.current.getBoundingClientRect();
    if (x + rect.width > window.innerWidth) {
      style.left = Math.max(4, window.innerWidth - rect.width - 4);
    }
    if (y + rect.height > window.innerHeight) {
      style.top = Math.max(4, window.innerHeight - rect.height - 4);
    }
  }

  return (
    <div className="overflow-menu-dropdown ctx-menu" style={style} ref={ref}>
      {items.map((item, i) =>
        item === "separator" ? (
          <div key={i} className="ctx-menu-separator" />
        ) : (
          <button
            key={i}
            type="button"
            className={`overflow-menu-item ${item.danger ? "danger" : ""}`}
            disabled={item.disabled}
            onClick={() => {
              onClose();
              item.onClick();
            }}
          >
            {item.label}
          </button>
        ),
      )}
    </div>
  );
}
