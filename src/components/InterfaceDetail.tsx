import { tr } from "../i18n";
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { NetworkInterface, RouteEntry, formatKind, CATEGORY_LABELS, ifTypeName } from "../types";
import { kindIcon, CloseIcon } from "../icons";
import { ensureElevation } from "../elevation";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

interface Props {
  iface: NetworkInterface;
  onClose: () => void;
}

export default function InterfaceDetail({ iface, onClose }: Props) {
  const [routes, setRoutes] = useState<RouteEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState(false);
  const [toggleError, setToggleError] = useState<string | null>(null);

  useEffect(() => {
    invoke<RouteEntry[]>("get_routes")
      .then((all) => {
        setRoutes(all.filter((r) => r.interfaceIndex === iface.ifIndex));
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [iface.ifIndex]);

  const toggleState = async () => {
    setToggling(true);
    setToggleError(null);
    try {
      if (!(await ensureElevation(tr("Changing interface state")))) return;
      await invoke("set_interface_state", { name: iface.name, up: iface.state !== "Up" });
    } catch (err) {
      setToggleError(String(err));
    } finally {
      setToggling(false);
    }
  };

  return (
    <div className="detail-overlay" onClick={onClose}>
      <div className="detail-panel" onClick={(e) => e.stopPropagation()}>
        <div className="detail-header">
          <div className="detail-title">
            {kindIcon(iface.kind, 22)}
            <span>{iface.friendlyName}</span>
          </div>
          <button className="close-btn" aria-label={tr("Close interface details")} onClick={onClose}>
            <CloseIcon size={20} />
          </button>
        </div>

        <div className="detail-body">
          <div className="detail-badges">
            <span className={`badge cat-badge cat-${iface.category.toLowerCase()}`}>
              {tr(iface.category === "system" ? "System interfaces" : CATEGORY_LABELS[iface.category])}
            </span>
            <span className={`badge ${iface.physical ? "badge-physical" : "badge-virtual"}`}>
              {iface.physical ? tr("Physical") : tr("Virtual")}
            </span>
            <span className={`state-badge state-${iface.state.toLowerCase()}`}>
              {tr(iface.state)}
            </span>
            <span className="meta-label">{tr(formatKind(iface.kind))}</span>
          </div>

          <button
            className="toggle-btn"
            onClick={toggleState}
            disabled={toggling || iface.kind === "loopback"}
            title={iface.kind === "loopback" ? tr("Loopback cannot be toggled") : ""}
          >
            {toggling ? "..." : iface.state === "Up" ? tr("Bring Down") : tr("Bring Up")}
          </button>
          {toggleError && <p className="error toggle-error">{toggleError}</p>}

          <table className="detail-table">
            <tbody>
              <tr><td>{tr("ifIndex")}</td><td className="mono">{iface.ifIndex}</td></tr>
              <tr><td>{tr("ifType")}</td><td className="mono">{iface.ifType} ({ifTypeName(iface.ifType)})</td></tr>
              <tr><td>{tr("Name")}</td><td className="mono">{iface.name}</td></tr>
              {iface.description && <tr><td>{tr("Driver")}</td><td className="mono">{iface.description}</td></tr>}
              {iface.tunnelType && <tr><td>{tr("Tunnel type")}</td><td className="mono">{iface.tunnelType}</td></tr>}
              {iface.mac && <tr><td>{tr("MAC")}</td><td className="mono">{iface.mac}</td></tr>}
              {iface.mtu !== null && <tr><td>{tr("MTU")}</td><td>{iface.mtu}</td></tr>}
              {iface.linkSpeedMbps !== null && <tr><td>{tr("Link speed")}</td><td>{iface.linkSpeedMbps} {tr(" Mbps")}</td></tr>}
              {iface.gateway && <tr><td>{tr("Gateway")}</td><td className="mono">{iface.gateway}</td></tr>}
              {iface.ipv6Gateway && <tr><td>{tr("IPv6 gateway")}</td><td className="mono">{iface.ipv6Gateway}</td></tr>}
              {iface.dnsSuffix && <tr><td>{tr("DNS suffix")}</td><td className="mono">{iface.dnsSuffix}</td></tr>}
              {iface.rxBytes !== null && <tr><td>{tr("RX total")}</td><td>{formatBytes(iface.rxBytes)}</td></tr>}
              {iface.txBytes !== null && <tr><td>{tr("TX total")}</td><td>{formatBytes(iface.txBytes)}</td></tr>}
            </tbody>
          </table>

          {iface.addresses.length > 0 && (
            <div className="detail-section">
              <span className="section-label">{tr("Addresses")}</span>
              <ul className="address-list">
                {iface.addresses.map((addr, i) => (
                  <li key={i}>
                    <span className="mono">{addr.address}/{addr.prefixLen}</span>
                    <span className="family-tag">{addr.family}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {iface.dnsServers.length > 0 && (
            <div className="detail-section">
              <span className="section-label">{tr("DNS servers")}</span>
              <ul className="dns-list">
                {iface.dnsServers.map((dns, i) => (
                  <li key={i} className="mono">{dns}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="detail-section">
            <span className="section-label">
              {tr("Routes (")}{loading ? "..." : routes.length})
            </span>
            {loading ? (
              <p>{tr("Loading routes...")}</p>
            ) : routes.length === 0 ? (
              <p>{tr("No routes on this interface.")}</p>
            ) : (
              <table className="route-table compact">
                <thead>
                  <tr>
                    <th>{tr("Destination")}</th>
                    <th>{tr("Prefix")}</th>
                    <th>{tr("Gateway")}</th>
                    <th>{tr("Metric")}</th>
                  </tr>
                </thead>
                <tbody>
                  {routes.map((r, i) => (
                    <tr key={i}>
                      <td className="mono">{r.destination}</td>
                      <td>/{r.prefixLen}</td>
                      <td className="mono">{r.gateway ?? "—"}</td>
                      <td>{r.metric}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
