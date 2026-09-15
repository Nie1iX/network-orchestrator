import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { PlannedRoute, RouteMap as RouteMapData } from "../types";

interface InterfaceGroup {
  name: string;
  routes: PlannedRoute[];
  activeCount: number;
}

function groupByInterface(routes: PlannedRoute[]): InterfaceGroup[] {
  const groups = new Map<string, PlannedRoute[]>();
  for (const r of routes) {
    const key = r.interfaceName ?? "auto";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(r);
  }
  return [...groups.entries()]
    .map(([name, rs]) => ({
      name,
      routes: rs,
      activeCount: rs.filter((r) => r.active).length,
    }))
    .sort((a, b) => b.activeCount - a.activeCount || a.name.localeCompare(b.name));
}

const OWNER_COLORS = [
  "#646cff",
  "#34d399",
  "#f59e0b",
  "#f87171",
  "#a78bfa",
  "#22d3ee",
  "#fb923c",
  "#e879f9",
];

function colorForOwner(owner: string, owners: string[]): string {
  const idx = owners.indexOf(owner);
  return OWNER_COLORS[idx % OWNER_COLORS.length] ?? "#9ca3af";
}

export default function RouteByInterface() {
  const [map, setMap] = useState<RouteMapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

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

  if (loading) return <p>Loading...</p>;
  if (error) return <p className="error">Error: {error}</p>;
  if (!map) return null;

  const owners = [...new Set(map.predicted.map((r) => r.ownerName))];
  const groups = groupByInterface(map.predicted);
  const filterText = filter.toLowerCase();

  return (
    <div className="route-by-interface">
      <input
        type="text"
        className="route-filter-input"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter by destination or owner..."
      />
      <div className="route-owner-legend">
        {owners.map((o) => (
          <span key={o} className="owner-legend-item">
            <span className="owner-legend-dot" style={{ background: colorForOwner(o, owners) }} />
            {o}
          </span>
        ))}
      </div>
      <div className="interface-route-grid">
        {groups.map((g) => {
          const visible = g.routes.filter(
            (r) =>
              !filterText ||
              r.destination.toLowerCase().includes(filterText) ||
              r.ownerName.toLowerCase().includes(filterText),
          );
          if (visible.length === 0) return null;
          return (
            <div key={g.name} className="interface-route-card">
              <div className="interface-route-header">
                <span className="interface-route-name">{g.name}</span>
                <span className="interface-route-count">
                  {g.activeCount}/{g.routes.length}
                </span>
              </div>
              <div className="route-chips">
                {visible.map((r, i) => (
                  <span
                    key={i}
                    className={`route-chip ${r.active ? "active" : "inactive"}`}
                    style={{ borderColor: colorForOwner(r.ownerName, owners) }}
                    title={`${r.ownerName} · ${r.source} · metric ${r.metric ?? "—"}${r.active ? "" : " (inactive)"}`}
                  >
                    {r.destination}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
