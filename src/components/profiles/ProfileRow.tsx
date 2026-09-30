import { backendIcon, GripVerticalIcon } from "../../icons";
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
  selected: boolean;
  dragging: boolean;
  dropBefore: boolean;
  dropAfter: boolean;
  canReorder: boolean;
  onSelect: () => void;
  onToggle: () => void;
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
  selected,
  dragging,
  dropBefore,
  dropAfter,
  canReorder,
  onSelect,
  onToggle,
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
      className={`profile-row${selected ? " selected" : ""}${
        status.state === "running" ? " state-running" : ""
      }${status.state === "failed" ? " state-failed" : ""}${
        dragging ? " drag-source" : ""
      }${dropBefore ? " drop-before" : dropAfter ? " drop-after" : ""}`}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect();
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
        <GripVerticalIcon size={15} />
      </span>
      <span className={`status-dot state-${status.state}`} />
      <span className={`backend-avatar backend-avatar-${profile.backend}`}>
        {backendIcon(profile.backend, 18)}
      </span>
      <div className="profile-row-info">
        <span className="profile-row-name">{profile.name}</span>
        <span
          className="profile-row-meta"
          title={
            status.state === "failed" && status.message
              ? status.message
              : undefined
          }
        >
          {status.state === "failed" && status.message ? (
            status.message
          ) : rate ? (
            <RateText rx={rate.rxRate} tx={rate.txRate} live />
          ) : (
            profile.interfaceName || t("profiles.noIface")
          )}
        </span>
      </div>
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
