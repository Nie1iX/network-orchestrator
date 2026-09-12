import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { NetworkInterface, formatKind } from "../types";

export default function InterfaceList() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
          {interfaces.map((iface) => (
            <div key={iface.ifIndex} className="interface-card">
              <div className="interface-header">
                <span className="interface-name">{iface.friendlyName}</span>
                <span className={`state-badge state-${iface.state.toLowerCase()}`}>
                  {iface.state}
                </span>
              </div>
              <div className="interface-meta">
                <span className="meta-label">{formatKind(iface.kind)}</span>
                <span className="meta-label">ifIndex: {iface.ifIndex}</span>
                {iface.mtu !== null && (
                  <span className="meta-label">MTU: {iface.mtu}</span>
                )}
              </div>
              {iface.addresses.length > 0 && (
                <div className="interface-section">
                  <span className="section-label">Addresses</span>
                  <ul className="address-list">
                    {iface.addresses.map((addr, i) => (
                      <li key={i}>
                        {addr.address}/{addr.prefixLen}
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
                      <li key={i}>{dns}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
