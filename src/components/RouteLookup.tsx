import { tr } from "../i18n";
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
      <h2>{tr("Route Lookup")}</h2>
      <form className="lookup-input" onSubmit={onSubmit}>
        <input
          type="text"
          value={dest}
          onChange={(e) => setDest(e.currentTarget.value)}
          placeholder={tr("Enter IPv4 or IPv6 address...")}
          autoFocus
        />
        <button type="submit" disabled={loading || !dest.trim()}>
          {loading ? tr("Looking up...") : tr("Lookup")}
        </button>
      </form>
      {error && <p className="error">{tr(error)}</p>}
      {result && (
        <div className="lookup-result">
          <p>
            <span className="section-label">{tr("Destination:")}</span> {result.destination}
          </p>
          <p>
            <span className="section-label">{tr("Interface:")}</span> {result.interfaceName}
          </p>
          {result.table && (
            <p>
              <span className="section-label">{tr("Routing table:")}</span> {result.table}
            </p>
          )}
          <div className="matched-route">
            <span className="section-label">{tr("Matched route")}</span>
            <table className="route-table">
              <thead>
                <tr>
                  <th>{tr("Destination")}</th>
                  <th>{tr("Prefix")}</th>
                  <th>{tr("Gateway")}</th>
                  <th>{tr("Interface")}</th>
                  <th>{tr("Metric")}</th>
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
