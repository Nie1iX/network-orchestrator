import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import Page from "./Page";
import RouteFlow from "./RouteFlow";
import RouteMap from "./RouteMap";
import RouteTable from "./RouteTable";
import { RouteLookupResult, RouteMap as RouteMapData } from "../types";

type RouteTab = "flow" | "tree" | "table";

const TABS: { id: RouteTab; label: string }[] = [
  { id: "flow", label: "Traffic flow" },
  { id: "tree", label: "Tree" },
  { id: "table", label: "Table" },
];

export default function RouteView() {
  const [tab, setTab] = useState<RouteTab>("flow");
  const [map, setMap] = useState<RouteMapData | null>(null);
  const [lookupDest, setLookupDest] = useState("");
  const [lookupResult, setLookupResult] = useState<RouteLookupResult | null>(
    null,
  );
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);

  const loadSummary = useCallback(async () => {
    try {
      const data = await invoke<RouteMapData>("get_route_map", {
        includeInactive: true,
      });
      setMap(data);
    } catch {
      // summary chips are best-effort
    }
  }, []);

  useEffect(() => {
    void loadSummary();
    const handler = () => void loadSummary();
    window.addEventListener("route-changed", handler);
    return () => window.removeEventListener("route-changed", handler);
  }, [loadSummary]);

  const lookup = async () => {
    const target = lookupDest.trim();
    if (!target) return;
    setLookupLoading(true);
    setLookupError(null);
    try {
      const data = await invoke<RouteLookupResult>("lookup_destination", {
        dest: target,
      });
      setLookupResult(data);
    } catch (err) {
      setLookupResult(null);
      setLookupError(String(err));
    } finally {
      setLookupLoading(false);
    }
  };

  const activeCount = map ? map.predicted.filter((r) => r.active).length : null;
  const conflicts = map?.diffs.length ?? null;
  const warnings = map?.warnings.length ?? null;

  return (
    <Page width="full">
      <div className="routes-toolbar">
        <h2>Routes</h2>
        <nav className="route-tabs" aria-label="Route views">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              className={`route-tab ${tab === t.id ? "active" : ""}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>
        {map && (
          <div className="routes-summary">
            <span className="route-stat">{activeCount} active</span>
            <button
              type="button"
              className={`route-stat route-stat-btn ${conflicts ? "bad" : ""}`}
              onClick={() => setTab("tree")}
              title="Show conflicts in Tree"
            >
              {conflicts} {conflicts === 1 ? "conflict" : "conflicts"}
            </button>
            <button
              type="button"
              className={`route-stat route-stat-btn ${warnings ? "warn" : ""}`}
              onClick={() => setTab("tree")}
              title="Show warnings in Tree"
            >
              {warnings} {warnings === 1 ? "warning" : "warnings"}
            </button>
          </div>
        )}
        <form
          className="lookup-input"
          onSubmit={(e) => {
            e.preventDefault();
            void lookup();
          }}
        >
          <input
            type="text"
            value={lookupDest}
            onChange={(e) => setLookupDest(e.currentTarget.value)}
            placeholder="Lookup destination…"
          />
          <button
            type="submit"
            className="btn-sm"
            disabled={lookupLoading || !lookupDest.trim()}
          >
            {lookupLoading ? "…" : "Lookup"}
          </button>
        </form>
      </div>

      {lookupError && <p className="error">{lookupError}</p>}
      {lookupResult && (
        <div className="lookup-result routes-lookup-result">
          <div className="lookup-result-head">
            <span>
              {lookupResult.destination} →{" "}
              <span className="mono">
                {lookupResult.matchedRoute.destination}/
                {lookupResult.matchedRoute.prefixLen}
              </span>{" "}
              via {lookupResult.interfaceName}
              {lookupResult.table ? ` · table ${lookupResult.table}` : ""}
            </span>
            <button
              type="button"
              className="btn-ghost btn-sm"
              onClick={() => {
                setLookupResult(null);
                setLookupError(null);
              }}
            >
              Clear
            </button>
          </div>
          <div className="lookup-result-meta">
            {lookupResult.matchedRoute.gateway && (
              <span className="mono">
                gw {lookupResult.matchedRoute.gateway}
              </span>
            )}
            <span>metric {lookupResult.matchedRoute.metric}</span>
          </div>
        </div>
      )}

      <div className="route-tab-content">
        {tab === "flow" && <RouteFlow />}
        {tab === "tree" && <RouteMap />}
        {tab === "table" && <RouteTable />}
      </div>
    </Page>
  );
}
