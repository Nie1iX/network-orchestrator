import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { NetworkInterface, RouteEntry, formatKind, ifTypeName } from "../types";
import { kindIcon, CloseIcon } from "../icons";
import { ensureElevation } from "../elevation";
import { formatBytes } from "../format";
import { useT } from "../i18n";
import { CATEGORY_LABEL_KEYS } from "../i18n/labels";

interface Props {
  iface: NetworkInterface;
  onClose: () => void;
}

export default function InterfaceDetail({ iface, onClose }: Props) {
  const t = useT();
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
      if (!(await ensureElevation(t("iface.elevationState")))) return;
      await invoke("set_interface_state", { name: iface.name, up: iface.state !== "Up" });
    } catch (err) {
      setToggleError(String(err));
    } finally {
      setToggling(false);
    }
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="detail-overlay" onClick={onClose}>
      <div
        className="detail-panel"
        role="dialog"
        aria-modal="true"
        aria-label={iface.friendlyName}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="detail-header">
          <div className="detail-title">
            {kindIcon(iface.kind, 22)}
            <span>{iface.friendlyName}</span>
          </div>
          <button
            className="close-btn"
            onClick={onClose}
            title={t("common.close")}
            aria-label={t("Close interface details")}
          >
            <CloseIcon size={20} />
          </button>
        </div>

        <div className="detail-body">
          <div className="detail-badges">
            <span className={`badge cat-badge cat-${iface.category.toLowerCase()}`}>
              {t(CATEGORY_LABEL_KEYS[iface.category])}
            </span>
            <span className={`badge ${iface.physical ? "badge-physical" : "badge-virtual"}`}>
              {iface.physical ? t("iface.physical") : t("iface.virtual")}
            </span>
            <span className={`state-badge state-${iface.state.toLowerCase()}`}>
              {iface.state}
            </span>
            <span className="meta-label">{formatKind(iface.kind)}</span>
          </div>

          <button
            className="toggle-btn"
            onClick={toggleState}
            disabled={toggling || iface.kind === "loopback"}
            title={iface.kind === "loopback" ? t("iface.loopbackNoToggle") : ""}
          >
            {toggling ? "…" : iface.state === "Up" ? t("iface.bringDown") : t("iface.bringUp")}
          </button>
          {toggleError && <p className="error toggle-error">{toggleError}</p>}

          <table className="detail-table">
            <tbody>
              <tr><td>ifIndex</td><td className="mono num">{iface.ifIndex}</td></tr>
              <tr><td>ifType</td><td className="mono">{iface.ifType} ({ifTypeName(iface.ifType)})</td></tr>
              <tr><td>{t("iface.name")}</td><td className="mono">{iface.name}</td></tr>
              {iface.description && <tr><td>{t("iface.driver")}</td><td className="mono">{iface.description}</td></tr>}
              {iface.tunnelType && <tr><td>{t("iface.tunnelType")}</td><td className="mono">{iface.tunnelType}</td></tr>}
              {iface.mac && <tr><td>MAC</td><td className="mono">{iface.mac}</td></tr>}
              {iface.mtu !== null && <tr><td>MTU</td><td className="num">{iface.mtu}</td></tr>}
              {iface.linkSpeedMbps !== null && <tr><td>{t("iface.linkSpeed")}</td><td className="num">{iface.linkSpeedMbps} Mbps</td></tr>}
              {iface.gateway && <tr><td>{t("iface.gateway")}</td><td className="mono">{iface.gateway}</td></tr>}
              {iface.ipv6Gateway && <tr><td>{t("iface.gatewayV6")}</td><td className="mono">{iface.ipv6Gateway}</td></tr>}
              {iface.dnsSuffix && <tr><td>{t("iface.dnsSuffix")}</td><td className="mono">{iface.dnsSuffix}</td></tr>}
              {iface.rxBytes !== null && <tr><td>{t("iface.rxTotal")}</td><td className="num">{formatBytes(iface.rxBytes)}</td></tr>}
              {iface.txBytes !== null && <tr><td>{t("iface.txTotal")}</td><td className="num">{formatBytes(iface.txBytes)}</td></tr>}
            </tbody>
          </table>

          {iface.addresses.length > 0 && (
            <div className="detail-section">
              <span className="section-label">{t("iface.addresses")}</span>
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
              <span className="section-label">{t("iface.dnsServers")}</span>
              <ul className="dns-list">
                {iface.dnsServers.map((dns, i) => (
                  <li key={i} className="mono">{dns}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="detail-section">
            <span className="section-label">
              {t("iface.routesCount", { n: loading ? "…" : routes.length })}
            </span>
            {loading ? (
              <p>{t("iface.loadingRoutes")}</p>
            ) : routes.length === 0 ? (
              <p>{t("iface.noRoutes")}</p>
            ) : (
              <table className="route-table compact">
                <thead>
                  <tr>
                    <th>{t("routes.destination")}</th>
                    <th>{t("routes.prefix")}</th>
                    <th>{t("routes.gateway")}</th>
                    <th className="num">{t("routes.metricCol")}</th>
                  </tr>
                </thead>
                <tbody>
                  {routes.map((r, i) => (
                    <tr key={i}>
                      <td className="mono">{r.destination}</td>
                      <td className="num">/{r.prefixLen}</td>
                      <td className="mono">{r.gateway ?? "—"}</td>
                      <td className="num">{r.metric}</td>
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
