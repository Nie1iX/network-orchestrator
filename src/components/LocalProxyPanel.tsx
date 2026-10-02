import { useT } from "../i18n";
import { LoopbackIcon } from "../icons";
import { LocalProxy } from "../types";
import { useToast } from "./ui/Toast";

interface LocalProxyPanelProps {
  proxy: LocalProxy;
}

/**
 * A loopback proxy service detected by handshake probes: informational view
 * with the endpoint ready to copy — nothing routes through it implicitly.
 */
export default function LocalProxyPanel({ proxy }: LocalProxyPanelProps) {
  const t = useT();
  const toast = useToast();
  const endpoint = `${proxy.address}:${proxy.port}`;
  const uri = `${proxy.kind}://${endpoint}`;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(uri);
      toast("success", t("profiles.proxyCopied"));
    } catch {
      toast("error", t("native.copyFailed"));
    }
  };

  return (
    <div className="profile-detail">
      <div className="profile-detail-head">
        <span className="backend-avatar backend-avatar-lg backend-avatar-service">
          <LoopbackIcon size={20} />
        </span>
        <div className="profile-detail-title">
          <div className="connection-card-name-row">
            <span className="profile-detail-name">{endpoint}</span>
            <span className="badge badge-external">{proxy.kind}</span>
          </div>
          <span className="profile-detail-meta">
            {t("profiles.localProxies")}
          </span>
        </div>
        <button type="button" className="btn-sm" onClick={() => void copy()}>
          {t("profiles.copyProxyUri")}
        </button>
      </div>

      <div className="profile-detail-body">
        <div className="interface-row">
          <span className="row-label">{t("detail.peerEndpoint")}</span>
          <span className="row-value mono">{endpoint}</span>
        </div>
        <div className="interface-row">
          <span className="row-label">{t("detail.cfg.protocol")}</span>
          <span className="row-value mono">{proxy.kind}</span>
        </div>
        <p className="external-note">{t("profiles.localProxiesHint")}</p>
      </div>
    </div>
  );
}
