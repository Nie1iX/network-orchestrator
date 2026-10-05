import { useT } from "../i18n";
import { NmConnection } from "../types";
import ToggleSwitch from "./ui/ToggleSwitch";

interface NmConnectionPanelProps {
  conn: NmConnection;
  busy: boolean;
  onToggle: () => void;
  avatarClass: string;
  icon: React.ReactElement;
}

/**
 * A NetworkManager connection profile: NM owns the config, secrets and the
 * interface it brings up. Read-only details plus activate/deactivate.
 */
export default function NmConnectionPanel({
  conn,
  busy,
  onToggle,
  avatarClass,
  icon,
}: NmConnectionPanelProps) {
  const t = useT();
  const active = conn.state !== "inactive";

  return (
    <div className="profile-detail">
      <div className="profile-detail-head">
        <span
          className={`backend-avatar backend-avatar-lg ${avatarClass}`}
        >
          {icon}
        </span>
        <div className="profile-detail-title">
          <div className="connection-card-name-row">
            <span className="profile-detail-name">{conn.id}</span>
            <span className="badge badge-external">
              {t("detail.external")}
            </span>
          </div>
          <span className="profile-detail-meta">
            {conn.kind} ·{" "}
            {conn.state === "activating"
              ? t("common.connecting")
              : active
                ? t("iface.stateUp")
                : t("iface.stateDown")}
          </span>
        </div>
        <ToggleSwitch
          checked={active}
          onChange={onToggle}
          disabled={busy || conn.state === "activating"}
          busy={busy || conn.state === "activating"}
          title={
            active ? t("common.disconnect") : t("common.connect")
          }
        />
      </div>

      <div className="profile-detail-body">
        {conn.interfaceName && (
          <div className="interface-row">
            <span className="row-label">{t("detail.interface")}</span>
            <span className="row-value mono">{conn.interfaceName}</span>
          </div>
        )}
        <p className="external-note">{t("profiles.nmNote")}</p>
      </div>
    </div>
  );
}
