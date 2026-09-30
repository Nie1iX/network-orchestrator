import { TailscaleStatusResult } from "../types";
import { TailscaleIcon } from "../icons";
import ToggleSwitch from "./ui/ToggleSwitch";
import { useT } from "../i18n";

interface TailscalePanelProps {
  status: TailscaleStatusResult;
  busy: boolean;
  onToggle: () => void;
}

/**
 * The system `tailscaled` is a foreign daemon — we only proxy its LocalAPI:
 * a status view (peers and the routes they advertise) plus WantRunning
 * up/down. It owns no journal entry and is not a profile.
 */
export default function TailscalePanel({
  status,
  busy,
  onToggle,
}: TailscalePanelProps) {
  const t = useT();
  const running = status.available && status.backendState === "Running";
  const needsLogin = status.backendState === "NeedsLogin";

  return (
    <div className="profile-detail">
      <div className="profile-detail-head">
        <span className="backend-avatar backend-avatar-lg backend-avatar-service">
          <TailscaleIcon size={20} />
        </span>
        <div className="profile-detail-title">
          <div className="connection-card-name-row">
            <span className="profile-detail-name">Tailscale</span>
            {status.exitNodeActive && (
              <span className="badge badge-managed">{t("ts.exitNode")}</span>
            )}
          </div>
          <span className="profile-detail-meta">
            {status.available
              ? status.backendState
              : t("ts.unavailable")}
          </span>
        </div>
        <ToggleSwitch
          checked={running}
          onChange={onToggle}
          disabled={!status.available || needsLogin || busy}
          busy={busy}
          title={
            !status.available
              ? t("ts.notInstalled")
              : needsLogin
                ? t("ts.loginFirst")
                : running
                  ? t("ts.down")
                  : t("ts.up")
          }
        />
      </div>

      <div className="profile-detail-body">
        {!status.available ? (
          <p className="empty-state">
            {t("ts.notInstalled")}
          </p>
        ) : (
          <>
            <div className="interface-row">
              <span className="row-label">{t("ts.state")}</span>
              <span className="row-value">
                {status.backendState}
                {status.tailnet ? ` · ${status.tailnet}` : ""}
              </span>
            </div>
            {status.selfIps.length > 0 && (
              <div className="interface-row">
                <span className="row-label">{t("ts.thisNode")}</span>
                <span className="row-value mono">
                  {status.selfHostName} · {status.selfIps.join(", ")}
                </span>
              </div>
            )}
            {needsLogin && (
              <p className="empty-state">
                {t("ts.notLoggedInPre")} <code>tailscale login</code>{" "}
                {t("ts.notLoggedInPost")}
              </p>
            )}
            {status.peers.length > 0 && (
              <div className="interface-section">
                <span className="section-label">
                  {t("ts.peers")} · {status.peers.length}
                </span>
                <div className="active-now-list">
                  {status.peers.map((peer) => (
                    <div key={peer.hostName} className="active-now-card">
                      <div className="active-now-info">
                        <span className="active-now-name">
                          {peer.hostName}
                          {peer.exitNode && ` · ${t("ts.exitNode")}`}
                        </span>
                        <span className="active-now-meta">
                          {peer.tailscaleIps.join(", ")}
                          {peer.routes.length > 0 &&
                            ` → ${peer.routes.join(", ")}`}
                        </span>
                      </div>
                      {!peer.online && (
                        <span className="badge">{t("ts.offline")}</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
