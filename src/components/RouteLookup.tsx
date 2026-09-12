import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { RouteLookupResult } from "../types";

export default function RouteLookup() {
  const [dest, setDest] = useState("");
  const [result, setResult] = useState<RouteLookupResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const lookup = async () => {
    const target = dest.trim();
    if (!target) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await invoke<RouteLookupResult>("lookup_destination", {
        dest: target,
      });
      setResult(data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    lookup();
  };

  return (
    <section>
      <h2>Route Lookup</h2>
      <form className="lookup-input" onSubmit={onSubmit}>
        <input
          type="text"
          value={dest}
          onChange={(e) => setDest(e.currentTarget.value)}
          placeholder="Enter IP address or hostname..."
          autoFocus
        />
        <button type="submit" disabled={loading || !dest.trim()}>
          {loading ? "Looking up..." : "Lookup"}
        </button>
      </form>
      {error && <p className="error">{error}</p>}
      {result && (
        <div className="lookup-result">
          <p>
            <span className="section-label">Destination:</span> {result.destination}
          </p>
          <p>
            <span className="section-label">Interface:</span> {result.interfaceName}
          </p>
          <div className="matched-route">
            <span className="section-label">Matched route</span>
            <table className="route-table">
              <thead>
                <tr>
                  <th>Destination</th>
                  <th>Prefix</th>
                  <th>Gateway</th>
                  <th>Interface</th>
                  <th>Metric</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>{result.matchedRoute.destination}</td>
                  <td>/{result.matchedRoute.prefixLen}</td>
                  <td>{result.matchedRoute.gateway ?? "—"}</td>
                  <td>{result.matchedRoute.interfaceName}</td>
                  <td>{result.matchedRoute.metric}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}
