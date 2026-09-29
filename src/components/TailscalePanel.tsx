import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { TailscaleStatusResult } from "../types";
import { usePlatformCapabilities } from "../platform";
import { useToast } from "./ui/Toast";

/**
 * The system `tailscaled` is a foreign daemon — we only proxy its LocalAPI:
 * a status view (peers and the routes they advertise) plus WantRunning
 * up/down. It owns no journal entry and is not a profile.
 */
export default function TailscalePanel() {
  const caps = usePlatformCapabilities();
  const toast = useToast();
  const [status, setStatus] = useState<TailscaleStatusResult | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setStatus(await invoke<TailscaleStatusResult>("tailscale_status"));
    } catch {
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    refresh();
    const onChanged = () => void refresh();
    window.addEventListener("route-changed", onChanged);
    return () => window.removeEventListener("route-changed", onChanged);
  }, [refresh]);

  if (caps?.os !== "linux" || status === null) {
    return null;
  }

  const running = status.available && status.backendState === "Running";
  const toggle = async () => {
    setBusy(true);
    try {
      setStatus(
        await invoke<TailscaleStatusResult>("tailscale_set_running", {
          running: !running,
        }),
      );
    } catch (err) {
      toast("error", String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <h2>Tailscale</h2>
      {!status.available ? (
        <p className="empty-state">tailscaled is not installed or not running.</p>
      ) : (
        <>
          <div className="interface-row">
            <span className="row-label">State</span>
            <span className="row-value">
              <span className="badge-group">
                <span className={`state-badge ${running ? "state-up" : "state-down"}`}>
                  {status.backendState}
                </span>
                {status.exitNodeActive && <span className="badge">exit node</span>}
              </span>
              {status.tailnet && ` · ${status.tailnet}`}
            </span>
            <button
              type="button"
              className="btn-sm"
              onClick={toggle}
              disabled={busy}
            >
              {busy ? "…" : running ? "Down" : "Up"}
            </button>
          </div>
          {status.selfIps.length > 0 && (
            <div className="interface-row">
              <span className="row-label">This node</span>
              <span className="row-value">
                {status.selfHostName} · {status.selfIps.join(", ")}
              </span>
            </div>
          )}
          {status.backendState === "NeedsLogin" && (
            <p className="empty-state">
              Not logged in — run <code>tailscale login</code> in a terminal.
            </p>
          )}
          {status.peers.length > 0 && (
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
                      {peer.routes.length > 0 && ` → ${peer.routes.join(", ")}`}
                    </span>
                  </div>
                  {!peer.online && <span className="badge">offline</span>}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}
