import { useCallback, useEffect, useMemo, useState } from "react";
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

function hasChildren(index: number, routes: PlannedRoute[]): boolean {
  const target = routes[index];
  return routes.some(
    (r, i) => i > index && cidrContains(target.destination, r.destination),
  );
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

function ancestors(index: number, routes: PlannedRoute[]): number[] {
  const result: number[] = [];
  let current = index;
  const seen = new Set<number>();
  while (true) {
    const parent = parentPrefixIndex(current, routes);
    if (parent === null || seen.has(parent)) return result;
    seen.add(parent);
    result.push(parent);
    current = parent;
  }
}

function nodeKey(route: PlannedRoute): string {
  return `${route.destination}|${route.ownerProfileId}`;
}

function groupKey(route: PlannedRoute): string {
  return route.interfaceName ?? "auto";
}

export default function RouteMap() {
  const [map, setMap] = useState<RouteMapData | null>(null);
  const [includeInactive, setIncludeInactive] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [collapsedNodes, setCollapsedNodes] = useState<Set<string>>(new Set());

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

  const diffDestinations = useMemo(() => {
    const set = new Set<string>();
    if (map) {
      for (const d of map.diffs) set.add(d.destination);
    }
    return set;
  }, [map]);

  const predictedGroups = useMemo(() => {
    if (!map) return new Map<string, PlannedRoute[]>();
    const groups = new Map<string, PlannedRoute[]>();
    for (const route of map.predicted) {
      const key = groupKey(route);
      const list = groups.get(key);
      if (list) list.push(route);
      else groups.set(key, [route]);
    }
    return groups;
  }, [map]);

  const effectiveGroups = useMemo(() => {
    if (!map) return new Map<string, { destination: string; prefixLen: number; metric: number }[]>();
    const groups = new Map<string, { destination: string; prefixLen: number; metric: number }[]>();
    for (const route of map.effective) {
      const list = groups.get(route.interfaceName);
      if (list) list.push(route);
      else groups.set(route.interfaceName, [route]);
    }
    return groups;
  }, [map]);

  const toggleGroup = (key: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const toggleNode = (key: string) => {
    setCollapsedNodes((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const filterText = filter.trim().toLowerCase();

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

      <input
        className="route-map-filter"
        type="text"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter by destination or owner (e.g. 10.0.0.0/8, work-vpn)"
      />

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
            <div className="route-map-groups">
              {[...predictedGroups.entries()].map(([key, routes]) => {
                const collapsed = collapsedGroups.has(key);
                const visible = routes.filter((r) => {
                  if (!filterText) return true;
                  return (
                    r.destination.toLowerCase().includes(filterText) ||
                    r.ownerName.toLowerCase().includes(filterText)
                  );
                });
                return (
                  <div className="route-map-group" key={key}>
                    <button
                      type="button"
                      className="route-map-group-header"
                      onClick={() => toggleGroup(key)}
                    >
                      <span className="route-map-caret">{collapsed ? "▸" : "▾"}</span>
                      <span className="route-map-group-name">
                        {key === "auto" ? "auto interface" : key}
                      </span>
                      <span className="route-map-group-count">{routes.length}</span>
                    </button>
                    {!collapsed && visible.length > 0 && (
                      <table className="route-map-table">
                        <thead>
                          <tr>
                            <th>Destination</th>
                            <th>Owner</th>
                            <th>Source</th>
                            <th>Metric</th>
                            <th>State</th>
                          </tr>
                        </thead>
                        <tbody>
                          {visible.map((route) => {
                            const index = routes.indexOf(route);
                            const depth = treeDepth(index, routes);
                            const key = nodeKey(route);
                            const branchable = hasChildren(index, routes);
                            const isCollapsed = collapsedNodes.has(key);
                            const hiddenByAncestor = ancestors(index, routes).some(
                              (a) => collapsedNodes.has(nodeKey(routes[a])),
                            );
                            if (hiddenByAncestor) return null;
                            const flagged = diffDestinations.has(route.destination);
                            return (
                              <tr
                                key={key}
                                className={`${route.active ? "" : "inactive"}${flagged ? " flagged" : ""}`}
                              >
                                <td>
                                  <span
                                    className="route-map-indent"
                                    style={{ paddingLeft: `${depth * 1.25}rem` }}
                                  >
                                    {branchable ? (
                                      <button
                                        type="button"
                                        className="route-map-node-toggle"
                                        onClick={() => toggleNode(key)}
                                        aria-label={isCollapsed ? "Expand" : "Collapse"}
                                      >
                                        {isCollapsed ? "▸" : "▾"}
                                      </button>
                                    ) : depth > 0 ? (
                                      "↳ "
                                    ) : (
                                      ""
                                    )}
                                    {route.destination}
                                  </span>
                                </td>
                                <td>
                                  <span className="owner-badge">{route.ownerName}</span>
                                </td>
                                <td>{route.source}</td>
                                <td>{route.metric ?? "auto"}</td>
                                <td>{route.active ? "active" : "stopped"}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    )}
                    {!collapsed && visible.length === 0 && filterText && (
                      <p className="route-map-empty">No routes match the filter.</p>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {map.pushedRoutes.length > 0 && (
            <>
              <h3>Server-pushed routes (OpenVPN, runtime)</h3>
              <table className="route-map-table pushed">
                <thead>
                  <tr>
                    <th>Destination</th>
                    <th>Owner</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {map.pushedRoutes
                    .filter(
                      (r) =>
                        !filterText ||
                        r.destination.toLowerCase().includes(filterText) ||
                        r.ownerName.toLowerCase().includes(filterText),
                    )
                    .map((route, i) => (
                      <tr key={i}>
                        <td>{route.destination}</td>
                        <td>
                          <span className="owner-badge">{route.ownerName}</span>
                        </td>
                        <td>active</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </>
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
            <div className="route-map-groups">
              {[...effectiveGroups.entries()].map(([key, routes]) => {
                const collapsed = collapsedGroups.has(`eff::${key}`);
                const visible = routes.filter((r) =>
                  filterText ? r.destination.toLowerCase().includes(filterText) : true,
                );
                return (
                  <div className="route-map-group" key={`eff::${key}`}>
                    <button
                      type="button"
                      className="route-map-group-header"
                      onClick={() => toggleGroup(`eff::${key}`)}
                    >
                      <span className="route-map-caret">{collapsed ? "▸" : "▾"}</span>
                      <span className="route-map-group-name">{key}</span>
                      <span className="route-map-group-count">{routes.length}</span>
                    </button>
                    {!collapsed && visible.length > 0 && (
                      <table className="route-map-table effective">
                        <thead>
                          <tr>
                            <th>Destination</th>
                            <th>Metric</th>
                          </tr>
                        </thead>
                        <tbody>
                          {visible.map((route, i) => (
                            <tr key={i}>
                              <td>
                                {route.destination}/{route.prefixLen}
                              </td>
                              <td>{route.metric}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}
    </section>
  );
}
