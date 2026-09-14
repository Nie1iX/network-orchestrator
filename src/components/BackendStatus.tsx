import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { BackendAvailability, TunnelBackend } from "../types";

const BACKEND_LABELS: Record<TunnelBackend, string> = {
  none: "Static routes",
  wireGuard: "WireGuard",
  openVpn: "OpenVPN",
  xray: "Xray",
};

export default function BackendStatus() {
  const [items, setItems] = useState<BackendAvailability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await invoke<BackendAvailability[]>("get_backend_availability"));
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="backend-status">
      <div className="backend-status-head">
        <span className="section-label">Backend prerequisites</span>
        <button type="button" onClick={load} disabled={loading}>
          {loading ? "Checking…" : "Refresh"}
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {!error &&
        items.map((item) => (
          <div key={item.backend} className="backend-status-row">
            <span className="backend-name">{BACKEND_LABELS[item.backend]}</span>
            <span
              className={`badge ${item.available ? "badge-managed" : "badge-external"}`}
            >
              {item.available ? "Available" : "Missing"}
            </span>
            <span className="row-value mono backend-detail">
              {item.available ? item.path : item.message}
            </span>
          </div>
        ))}
    </div>
  );
}
