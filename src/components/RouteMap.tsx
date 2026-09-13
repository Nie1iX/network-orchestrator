import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { PlannedRoute, RouteMap as RouteMapData } from "../types";

function parseCidr(cidr: string): { bits: bigint; len: number; family: 4 | 6 } | null {
  const [addr, lenStr] = cidr.split("/");
  const len = Number(lenStr);
  if (!addr || !Number.isFinite(len)) return null;
  if (addr.includes(":")) {
    const expanded = expandV6(addr);
    if (!expanded) return null;
    return { bits: expanded, len, family: 6 };
  }
  const parts = addr.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return null;
  }
  const bits = parts.reduce((acc, p) => (acc << 8n) | BigInt(p), 0n);
  return { bits, len, family: 4 };
}

function expandV6(addr: string): bigint | null {
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = 8 - left.length - right.length;
  if (halves.length === 2 ? fill < 0 : left.length !== 8) return null;
  const groups = [...left, ...Array(Math.max(fill, 0)).fill("0"), ...right];
  if (groups.length !== 8) return null;
  let bits = 0n;
  for (const g of groups) {
    const v = parseInt(g || "0", 16);
    if (!Number.isInteger(v) || v < 0 || v > 0xffff) return null;
    bits = (bits << 16n) | BigInt(v);
  }
  return bits;
}

function cidrContains(parent: string, child: string): boolean {
  const p = parseCidr(parent);
  const c = parseCidr(child);
  if (!p || !c || p.family !== c.family || p.len >= c.len) return false;
  const width = p.family === 4 ? 32n : 128n;
  const shift = width - BigInt(p.len);
  const mask = ((1n << BigInt(p.len)) - 1n) << shift;
  return (p.bits & mask) === (c.bits & mask);
}

function parentPrefixIndex(index: number, routes: PlannedRoute[]): number | null {
  const target = routes[index];
  for (let i = index - 1; i >= 0; i--) {
    if (cidrContains(routes[i].destination, target.destination)) return i;
  }
  return null;
}

function treeDepth(index: number, routes: PlannedRoute[]): number {
  let depth = 0;
  let current = index;
  const seen = new Set<number>();
  while (true) {
    const parent = parentPrefixIndex(current, routes);
    if (parent === null || seen.has(parent)) return depth;
    seen.add(parent);
    depth += 1;
    current = parent;
  }
}

export default function RouteMap() {
  const [map, setMap] = useState<RouteMapData | null>(null);
  const [includeInactive, setIncludeInactive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (include: boolean) => {
    setLoading(true);
    setError(null);
    try {
      const data = await invoke<RouteMapData>("get_route_map", {
        includeInactive: include,
      });
      setMap(data);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load(includeInactive);
  }, [includeInactive, load]);

  useEffect(() => {
    const handler = () => load(includeInactive);
    window.addEventListener("route-changed", handler);
    return () => window.removeEventListener("route-changed", handler);
  }, [includeInactive, load]);

  return (
    <section className="route-map">
      <div className="route-map-header">
        <h2>Route map</h2>
        <label className="route-map-toggle">
          <input
            type="checkbox"
            checked={includeInactive}
            onChange={(e) => setIncludeInactive(e.target.checked)}
          />
          Include stopped profiles
        </label>
      </div>

      {loading && <p>Loading route map...</p>}
      {error && <p className="error">Error loading route map: {error}</p>}

      {map && (
        <>
          {map.warnings.length > 0 && (
            <ul className="route-map-warnings">
              {map.warnings.map((w, i) => (
                <li key={i} className="warning">
                  {w}
                </li>
              ))}
            </ul>
          )}

          <h3>Predicted routes</h3>
          {map.predicted.length === 0 ? (
            <p>No predicted routes.</p>
          ) : (
            <table className="route-map-table">
              <thead>
                <tr>
                  <th>Destination</th>
                  <th>Owner</th>
                  <th>Source</th>
                  <th>Interface</th>
                  <th>Metric</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {map.predicted.map((route, i) => {
                  const depth = treeDepth(i, map.predicted);
                  return (
                    <tr key={i} className={route.active ? "" : "inactive"}>
                      <td>
                        <span
                          className="route-map-indent"
                          style={{ paddingLeft: `${depth * 1.25}rem` }}
                        >
                          {depth > 0 ? "↳ " : ""}
                          {route.destination}
                        </span>
                      </td>
                      <td>
                        <span className="owner-badge">{route.ownerName}</span>
                      </td>
                      <td>{route.source}</td>
                      <td>{route.interfaceName ?? "auto"}</td>
                      <td>{route.metric ?? "auto"}</td>
                      <td>{route.active ? "active" : "stopped"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}

          <h3>Differences</h3>
          {map.diffs.length === 0 ? (
            <p className="route-map-ok">
              Predicted active routes match the effective table.
            </p>
          ) : (
            <ul className="route-map-diffs">
              {map.diffs.map((diff, i) => (
                <li key={i} className={`route-diff diff-${diff.kind}`}>
                  {diff.message}
                </li>
              ))}
            </ul>
          )}

          <h3>Effective routes</h3>
          {map.effective.length === 0 ? (
            <p>No effective routes reported.</p>
          ) : (
            <table className="route-map-table effective">
              <thead>
                <tr>
                  <th>Destination</th>
                  <th>Interface</th>
                  <th>Metric</th>
                </tr>
              </thead>
              <tbody>
                {map.effective.map((route, i) => (
                  <tr key={i}>
                    <td>
                      {route.destination}/{route.prefixLen}
                    </td>
                    <td>{route.interfaceName}</td>
                    <td>{route.metric}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </section>
  );
}
