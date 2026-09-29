import { TailscaleStatusResult } from "../types";
import { TailscaleIcon } from "../icons";
import ToggleSwitch from "./ui/ToggleSwitch";

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
              <span className="badge badge-managed">exit node</span>
            )}
          </div>
          <span className="profile-detail-meta">
            {status.available
              ? status.backendState
              : "tailscaled unavailable"}
          </span>
        </div>
        <ToggleSwitch
          checked={running}
          onChange={onToggle}
          disabled={!status.available || needsLogin || busy}
          busy={busy}
          title={
            !status.available
              ? "tailscaled is not installed or not running"
              : needsLogin
                ? "Log in first: tailscale login"
                : running
                  ? "tailscale down"
                  : "tailscale up"
          }
        />
      </div>

      <div className="profile-detail-body">
        {!status.available ? (
          <p className="empty-state">
            tailscaled is not installed or not running.
          </p>
        ) : (
          <>
            <div className="interface-row">
              <span className="row-label">State</span>
              <span className="row-value">
                {status.backendState}
                {status.tailnet ? ` · ${status.tailnet}` : ""}
              </span>
            </div>
            {status.selfIps.length > 0 && (
              <div className="interface-row">
                <span className="row-label">This node</span>
                <span className="row-value mono">
                  {status.selfHostName} · {status.selfIps.join(", ")}
                </span>
              </div>
            )}
            {needsLogin && (
              <p className="empty-state">
                Not logged in — run <code>tailscale login</code> in a terminal.
              </p>
            )}
            {status.peers.length > 0 && (
              <div className="interface-section">
                <span className="section-label">
                  Peers · {status.peers.length}
                </span>
                <div className="active-now-list">
                  {status.peers.map((peer) => (
                    <div key={peer.hostName} className="active-now-card">
                      <div className="active-now-info">
                        <span className="active-now-name">
                          {peer.hostName}
                          {peer.exitNode && " · exit node"}
                        </span>
                        <span className="active-now-meta">
                          {peer.tailscaleIps.join(", ")}
                          {peer.routes.length > 0 &&
                            ` → ${peer.routes.join(", ")}`}
                        </span>
                      </div>
                      {!peer.online && <span className="badge">offline</span>}
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
