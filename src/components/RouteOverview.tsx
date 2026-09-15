import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { PlannedRoute, RouteMap as RouteMapData, RouteEntry } from "../types";

interface Summary {
  totalPredicted: number;
  activePredicted: number;
  totalEffective: number;
  conflicts: number;
  warnings: number;
  interfaces: number;
  profiles: number;
}

function computeSummary(map: RouteMapData): Summary {
  const interfaces = new Set(
    [...map.predicted.map((r) => r.interfaceName), ...map.effective.map((r) => r.interfaceName)]
      .filter(Boolean) as string[],
  );
  const profiles = new Set(map.predicted.map((r) => r.ownerProfileId));
  return {
    totalPredicted: map.predicted.length,
    activePredicted: map.predicted.filter((r) => r.active).length,
    totalEffective: map.effective.length,
    conflicts: map.diffs.length,
    warnings: map.warnings.length,
    interfaces: interfaces.size,
    profiles: profiles.size,
  };
}

function groupByOwner(routes: PlannedRoute[]): Map<string, PlannedRoute[]> {
  const groups = new Map<string, PlannedRoute[]>();
  for (const r of routes) {
    const key = r.ownerName;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(r);
  }
  return groups;
}

function groupByInterface(routes: RouteEntry[]): Map<string, RouteEntry[]> {
  const groups = new Map<string, RouteEntry[]>();
  for (const r of routes) {
    if (!groups.has(r.interfaceName)) groups.set(r.interfaceName, []);
    groups.get(r.interfaceName)!.push(r);
  }
  return groups;
}

export default function RouteOverview() {
  const [map, setMap] = useState<RouteMapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drill, setDrill] = useState<"conflicts" | "owners" | "interfaces" | null>(null);

  const fetch = async () => {
    try {
      setError(null);
      const data = await invoke<RouteMapData>("get_route_map", { includeInactive: true });
      setMap(data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetch();
    const handler = () => fetch();
    window.addEventListener("route-changed", handler);
    return () => window.removeEventListener("route-changed", handler);
  }, []);

  if (loading) return <p>Loading route overview...</p>;
  if (error) return <p className="error">Error: {error}</p>;
  if (!map) return null;

  const s = computeSummary(map);

  return (
    <div className="route-overview">
      <div className="summary-cards">
        <div className="summary-card" onClick={() => setDrill(drill === "owners" ? null : "owners")}>
          <span className="summary-value">{s.activePredicted}</span>
          <span className="summary-label">Active routes</span>
          <span className="summary-sub">{s.totalPredicted} total predicted</span>
        </div>
        <div className="summary-card">
          <span className="summary-value">{s.totalEffective}</span>
          <span className="summary-label">OS routes</span>
          <span className="summary-sub">in effective table</span>
        </div>
        <div
          className={`summary-card ${s.conflicts > 0 ? "summary-warn" : ""}`}
          onClick={() => setDrill(drill === "conflicts" ? null : "conflicts")}
        >
          <span className="summary-value">{s.conflicts}</span>
          <span className="summary-label">Conflicts</span>
          <span className="summary-sub">{s.warnings} warnings</span>
        </div>
        <div className="summary-card" onClick={() => setDrill(drill === "interfaces" ? null : "interfaces")}>
          <span className="summary-value">{s.interfaces}</span>
          <span className="summary-label">Interfaces</span>
          <span className="summary-sub">{s.profiles} profiles</span>
        </div>
      </div>

      {drill === "conflicts" && (
        <div className="drill-panel">
          <h3>Conflicts & issues</h3>
          {map.diffs.length === 0 && map.warnings.length === 0 ? (
            <p className="empty-state">No conflicts detected.</p>
          ) : (
            <>
              {map.diffs.map((d, i) => (
                <div key={i} className={`drill-item drill-${d.kind}`}>
                  <span className="drill-tag">{d.kind}</span>
                  <span className="drill-dest">{d.destination}</span>
                  <span className="drill-msg">{d.message}</span>
                </div>
              ))}
              {map.warnings.map((w, i) => (
                <div key={`w${i}`} className="drill-item drill-warning">
                  <span className="drill-tag">warning</span>
                  <span className="drill-msg">{w}</span>
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {drill === "owners" && (
        <div className="drill-panel">
          <h3>Routes by profile</h3>
          {[...groupByOwner(map.predicted).entries()].map(([owner, routes]) => (
            <div key={owner} className="drill-group">
              <div className="drill-group-header">
                <span className="drill-group-name">{owner}</span>
                <span className="drill-group-count">
                  {routes.filter((r) => r.active).length}/{routes.length} active
                </span>
              </div>
              <div className="route-chips">
                {routes.map((r, i) => (
                  <span
                    key={i}
                    className={`route-chip ${r.active ? "active" : "inactive"}`}
                    title={`${r.source} · ${r.interfaceName ?? "auto"} · metric ${r.metric ?? "—"}${r.active ? "" : " (inactive)"}`}
                  >
                    {r.destination}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {drill === "interfaces" && (
        <div className="drill-panel">
          <h3>OS routes by interface</h3>
          {[...groupByInterface(map.effective).entries()].map(([iface, routes]) => (
            <div key={iface} className="drill-group">
              <div className="drill-group-header">
                <span className="drill-group-name">{iface}</span>
                <span className="drill-group-count">{routes.length} routes</span>
              </div>
              <div className="route-chips">
                {routes.map((r, i) => (
                  <span
                    key={i}
                    className="route-chip effective"
                    title={`metric ${r.metric}${r.gateway ? " via " + r.gateway : ""}`}
                  >
                    {r.destination}/{r.prefixLen}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {!drill && (
        <div className="overview-hint">
          <p>Click a summary card to drill down into details.</p>
        </div>
      )}
    </div>
  );
}
