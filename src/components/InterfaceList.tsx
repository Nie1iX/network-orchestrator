import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { NetworkInterface, formatKind } from "../types";
import { kindIcon } from "../icons";
import InterfaceDetail from "./InterfaceDetail";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
}

interface Throughput {
  rxRate: number;
  txRate: number;
}

export default function InterfaceList() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [throughput, setThroughput] = useState<Record<number, Throughput>>({});
  const [selected, setSelected] = useState<NetworkInterface | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const prevStats = useRef<Record<number, { rx: number; tx: number; time: number }>>({});

  const fetchInterfaces = async () => {
    try {
      setError(null);
      const data = await invoke<NetworkInterface[]>("get_interfaces");
      setInterfaces(data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  // Poll for throughput every 1 second
  useEffect(() => {
    const poll = async () => {
      try {
        const data = await invoke<NetworkInterface[]>("get_interfaces");
        const now = Date.now();
        const newThroughput: Record<number, Throughput> = {};
        for (const iface of data) {
          if (iface.rxBytes === null || iface.txBytes === null) continue;
          const prev = prevStats.current[iface.ifIndex];
          if (prev) {
            const dt = (now - prev.time) / 1000;
            if (dt > 0) {
              newThroughput[iface.ifIndex] = {
                rxRate: Math.max(0, (iface.rxBytes - prev.rx) / dt),
                txRate: Math.max(0, (iface.txBytes - prev.tx) / dt),
              };
            }
          }
          prevStats.current[iface.ifIndex] = {
            rx: iface.rxBytes,
            tx: iface.txBytes,
            time: now,
          };
        }
        setThroughput(newThroughput);
      } catch {
        // ignore polling errors
      }
    };

    const interval = setInterval(poll, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    fetchInterfaces();
  }, []);

  useEffect(() => {
    const handler = () => fetchInterfaces();
    window.addEventListener("route-changed", handler);
    return () => window.removeEventListener("route-changed", handler);
  }, []);

  if (loading) return <p>Loading interfaces...</p>;
  if (error) return <p className="error">Error loading interfaces: {error}</p>;

  return (
    <section>
      <h2>Interfaces</h2>
      {interfaces.length === 0 ? (
        <p>No interfaces found.</p>
      ) : (
        <div className="interface-grid">
          {[...interfaces]
            .sort((a, b) => Number(b.physical) - Number(a.physical))
            .map((iface) => {
            const tp = throughput[iface.ifIndex];
            return (
              <div
                key={iface.ifIndex}
                className="interface-card clickable"
                onClick={() => setSelected(iface)}
              >
                <div className="interface-header">
                  <div className="interface-title">
                    {kindIcon(iface.kind, 18)}
                    <span className="interface-name">{iface.friendlyName}</span>
                  </div>
                  <div className="badge-group">
                    <span className={`badge ${iface.physical ? "badge-physical" : "badge-virtual"}`}>
                      {iface.physical ? "Physical" : "Virtual"}
                    </span>
                    <span className={`state-badge state-${iface.state.toLowerCase()}`}>
                      {iface.state}
                    </span>
                  </div>
                </div>
                <div className="interface-meta">
                  <span className="meta-label">{formatKind(iface.kind)}</span>
                  {iface.mtu !== null && (
                    <span className="meta-label">MTU: {iface.mtu}</span>
                  )}
                  {iface.linkSpeedMbps !== null && (
                    <span className="meta-label">{iface.linkSpeedMbps} Mbps</span>
                  )}
                </div>
                {iface.mac && (
                  <div className="interface-row">
                    <span className="row-label">MAC</span>
                    <span className="row-value mono">{iface.mac}</span>
                  </div>
                )}
                {iface.gateway && (
                  <div className="interface-row">
                    <span className="row-label">Gateway</span>
                    <span className="row-value mono">{iface.gateway}</span>
                  </div>
                )}
                {iface.addresses.length > 0 && (
                  <div className="interface-section">
                    <span className="section-label">Addresses</span>
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
                  <div className="interface-section">
                    <span className="section-label">DNS</span>
                    <ul className="dns-list">
                      {iface.dnsServers.map((dns, i) => (
                        <li key={i} className="mono">{dns}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {iface.dnsSuffix && (
                  <div className="interface-row">
                    <span className="row-label">DNS suffix</span>
                    <span className="row-value mono">{iface.dnsSuffix}</span>
                  </div>
                )}
                {iface.rxBytes !== null && iface.txBytes !== null && (
                  <div className="traffic-row">
                    <div className="interface-row">
                      <span className="row-label">Total</span>
                      <span className="row-value">
                        <span className="traffic">↓ {formatBytes(iface.rxBytes)}</span>
                        <span className="traffic">↑ {formatBytes(iface.txBytes)}</span>
                      </span>
                    </div>
                    {tp && (
                      <div className="interface-row">
                        <span className="row-label">Rate</span>
                        <span className="row-value">
                        <span className="traffic rate">↓ {formatRate(tp.rxRate)}</span>
                        <span className="traffic rate">↑ {formatRate(tp.txRate)}</span>
                      </span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      {selected && (
        <InterfaceDetail iface={selected} onClose={() => setSelected(null)} />
      )}
    </section>
  );
}
