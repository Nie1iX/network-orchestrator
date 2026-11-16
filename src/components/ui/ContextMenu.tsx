import { useEffect, useLayoutEffect, useRef } from "react";
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

  // Measure the untransformed size and clamp before the first paint.
  useLayoutEffect(() => {
    const menu = ref.current;
    if (!menu) return;
    const left = Math.min(x, window.innerWidth - menu.offsetWidth - 4);
    const top = Math.min(y, window.innerHeight - menu.offsetHeight - 4);
    menu.style.left = `${Math.max(4, left)}px`;
    menu.style.top = `${Math.max(4, top)}px`;
  }, [x, y, items]);

  return (
    <div className="overflow-menu-dropdown ctx-menu" style={{ left: x, top: y }} ref={ref}>
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
