import { formatBytes } from "../format";
import { useT } from "../i18n";
import { backendAvatarClass, kindIcon } from "../icons";
import { formatKind, NetworkInterface } from "../types";
import RateText from "./ui/RateText";
import ToggleSwitch from "./ui/ToggleSwitch";

interface ExternalTunnelPanelProps {
  iface: NetworkInterface;
  rate: { rxRate: number; txRate: number } | null;
  busy: boolean;
  onToggle: () => void;
}

/**
 * A tunnel-kind interface raised outside our control (wg-quick, another VPN
 * app, …): read-only view so its routes/DNS conflicts are explainable.
 * Ownership is excluded by name — the running managed tunnel wins.
 */
export default function ExternalTunnelPanel({
  iface,
  rate,
  busy,
  onToggle,
}: ExternalTunnelPanelProps) {
  const t = useT();
  const up = iface.state === "up";

  return (
    <div className="profile-detail">
      <div className="profile-detail-head">
        <span
          className={`backend-avatar backend-avatar-lg ${backendAvatarClass(iface.kind)}`}
        >
          {kindIcon(iface.kind, 20)}
        </span>
        <div className="profile-detail-title">
          <div className="connection-card-name-row">
            <span className="profile-detail-name">{iface.name}</span>
            <span className="badge badge-external">
              {t("detail.external")}
            </span>
          </div>
          <span className="profile-detail-meta">
            {formatKind(iface.kind)} ·{" "}
            {up ? t("iface.stateUp") : t("iface.stateDown")}
          </span>
        </div>
        <ToggleSwitch
          checked={up}
          onChange={onToggle}
          disabled={busy}
          busy={busy}
          title={up ? t("profiles.externalStop") : t("iface.bringUp")}
        />
      </div>

      <div className="profile-detail-body">
        {iface.addresses.length > 0 && (
          <div className="interface-row">
            <span className="row-label">{t("iface.addresses")}</span>
            <span className="row-value mono">
              {iface.addresses
                .map((a) => `${a.address}/${a.prefixLen}`)
                .join(", ")}
            </span>
          </div>
        )}
        {iface.mtu !== null && (
          <div className="interface-row">
            <span className="row-label">{t("detail.cfg.mtu")}</span>
            <span className="row-value mono">{iface.mtu}</span>
          </div>
        )}
        <div className="interface-row">
          <span className="row-label">{t("detail.traffic")}</span>
          <span className="row-value mono">
            {rate ? (
              <RateText rx={rate.rxRate} tx={rate.txRate} live />
            ) : (
              `↓ ${formatBytes(iface.rxBytes ?? 0)} · ↑ ${formatBytes(iface.txBytes ?? 0)}`
            )}
          </span>
        </div>
        <p className="external-note">{t("profiles.externalNote")}</p>
      </div>
    </div>
  );
}
