import { AlertTriangleIcon, backendIcon, GripVerticalIcon } from "../../icons";
import { Profile, TunnelStatus } from "../../types";
import { useT } from "../../i18n";
import RateText from "../ui/RateText";
import ToggleSwitch from "../ui/ToggleSwitch";

interface ProfileRowProps {
  profile: Profile;
  status: TunnelStatus;
  rate: { rxRate: number; txRate: number } | null;
  /** Delay chip text; null hides the chip (non-subscription profiles). */
  delayText: string | null;
  isBusy: boolean;
  /** The profile's interface is occupied by a tunnel managed elsewhere. */
  conflict: boolean;
  selected: boolean;
  dragging: boolean;
  /** False in grouped mode — the group header already shows the backend. */
  showBackendBadge?: boolean;
  dropBefore: boolean;
  dropAfter: boolean;
  canReorder: boolean;
  onSelect: () => void;
  onToggle: () => void;
  onContextMenu: (e: React.MouseEvent) => void;
  onDragStart: (e: React.DragEvent<HTMLElement>) => void;
  onDragEnd: () => void;
  onDragOver: (e: React.DragEvent<HTMLElement>) => void;
  onDrop: (e: React.DragEvent<HTMLElement>) => void;
}

export default function ProfileRow({
  profile,
  status,
  rate,
  delayText,
  isBusy,
  conflict,
  selected,
  dragging,
  showBackendBadge = true,
  dropBefore,
  dropAfter,
  canReorder,
  onSelect,
  onToggle,
  onContextMenu,
  onDragStart,
  onDragEnd,
  onDragOver,
  onDrop,
}: ProfileRowProps) {
  const t = useT();
  return (
    <div
      role="button"
      tabIndex={0}
      data-profile-id={profile.id}
      className={`profile-row${selected ? " selected" : ""}${
        status.state === "running" ? " state-running" : ""
      }${status.state === "failed" ? " state-failed" : ""}${
        dragging ? " drag-source" : ""
      }${dropBefore ? " drop-before" : dropAfter ? " drop-after" : ""}`}
      onClick={onSelect}
      onContextMenu={onContextMenu}
      onKeyDown={(event) => {
        if (event.target !== event.currentTarget) return;
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          if (selected) onToggle();
          else onSelect();
        }
      }}
      onDragOver={onDragOver}
      onDrop={onDrop}
    >
      <span
        className={`connection-drag-handle${canReorder ? "" : " disabled"}`}
        draggable={canReorder}
        onDragStart={onDragStart}
        onDragEnd={onDragEnd}
        title={canReorder ? t("profiles.dragTitle") : undefined}
      >
        <GripVerticalIcon size={13} />
      </span>
      <span className={`status-dot state-${status.state}`} />
      {showBackendBadge && (
        <span className={`backend-avatar backend-avatar-${profile.backend}`}>
          {backendIcon(profile.backend, 14)}
        </span>
      )}
      <span className="profile-row-name">{profile.name}</span>
      {(status.state === "failed" && status.message) || conflict ? (
        <span
          className={`profile-row-meta${conflict && status.state !== "failed" ? " warn" : ""}`}
          title={
            status.state === "failed" && status.message
              ? status.message
              : t("profiles.ifaceConflict", { name: profile.interfaceName })
          }
        >
          <AlertTriangleIcon size={13} />
        </span>
      ) : rate ? (
        <span className="profile-row-meta">
          <RateText rx={rate.rxRate} tx={rate.txRate} live />
        </span>
      ) : null}
      {delayText !== null && (
        <span className="profile-row-delay" title={t("profiles.delayTitle")}>
          {delayText}
        </span>
      )}
      <ToggleSwitch
        checked={status.state === "running"}
        onChange={onToggle}
        disabled={isBusy}
        busy={isBusy}
        title={status.state === "running" ? t("common.disconnect") : t("common.connect")}
      />
    </div>
  );
}
